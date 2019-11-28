/*
 * Filesystem synchronization client
 *
 * Copyright (c) 2017 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/time.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <termios.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <getopt.h>

#include "cutils.h"
#include "list.h"
#include "fs.h"
#include "fs_utils.h"
#include "fs_wget.h"

#include <openssl/rand.h>

#define SYNCDIR_NAME ".vfsync"
#define FILELIST_FILENAME "filelist.txt"
#define ROOT_DIR_COUNT 3 /* in the URL, the root begins after 3 directories */

typedef enum {
    FT_FIFO = 1,
    FT_CHR = 2,
    FT_DIR = 4,
    FT_BLK = 6,
    FT_REG = 8,
    FT_LNK = 10,
    FT_SOCK = 12,
} FLINodeTypeEnum;

typedef struct FLINode {
    struct list_head link;
    FLINodeTypeEnum type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t mtime_sec;
    uint32_t mtime_nsec;
    union {
        struct {
            size_t size; /* real file size */
            FSFileID file_id; /* network file ID */
        } reg;
        struct {
            struct list_head de_list; /* list of FLDirEntry */
        } dir;
        struct {
            uint32_t major;
            uint32_t minor;
        } dev;
        struct {
            char *name;
        } symlink;
    } u;
} FLINode;

typedef struct {
    struct list_head link;
    FLINode *inode;
    uint8_t mark; /* temporary use only */
    char name[0];
} FLDirEntry;

static FLINode *inode_new(FLINodeTypeEnum type,
                          uint32_t mode, uint32_t uid, uint32_t gid)
{
    FLINode *n;

    n = mallocz(sizeof(*n));
    n->type = type;
    n->mode = mode & 0xfff;
    n->uid = uid;
    n->gid = gid;

    switch(type) {
    case FT_DIR:
        init_list_head(&n->u.dir.de_list);
        break;
    default:
        break;
    }
    return n;
}

static void inode_free(FLINode *n)
{
    switch(n->type) {
    case FT_LNK:
        free(n->u.symlink.name);
        break;
    case FT_DIR:
        {
            struct list_head *el, *el1;
            FLDirEntry *de;

            list_for_each_safe(el, el1, &n->u.dir.de_list) {
                de = list_entry(el, FLDirEntry, link);
                inode_free(de->inode);
                free(de);
            }
        }
        break;
    default:
        break;
    }
    free(n);
}

static FLDirEntry *inode_dirent_add(FLINode *n, const char *name,
                                    FLINode *n1)
{
    FLDirEntry *de;
    int name_len;
    assert(n->type == FT_DIR);

    name_len = strlen(name);
    de = mallocz(sizeof(*de) + name_len + 1);
    de->inode = n1;
    memcpy(de->name, name, name_len + 1);
    list_add_tail(&de->link, &n->u.dir.de_list);
    return de;
}

/* Note: the inode is not remove */
static void inode_dirent_delete(FLINode *n, FLDirEntry *de)
{
    assert(n->type == FT_DIR);
    list_del(&de->link);
    free(de);
}

static FLDirEntry *inode_search(FLINode *n, const char *name)
{
    struct list_head *el;
    FLDirEntry *de;

    if (n->type != FT_DIR)
        return NULL;

    list_for_each(el, &n->u.dir.de_list) {
        de = list_entry(el, FLDirEntry, link);
        if (!strcmp(de->name, name))
            return de;
    }
    return NULL;
}

static FLINode *inode_search_path(FLINode *n, const char *path)
{
    char name[1024];
    const char *p, *p1;
    int len;
    FLDirEntry *de;

    p = path;
    if (*p == '/')
        p++;
    if (*p == '\0')
        return n;
    for(;;) {
        p1 = strchr(p, '/');
        if (!p1) {
            len = strlen(p);
        } else {
            len = p1 - p;
            p1++;
        }
        if (len > sizeof(name) - 1)
            return NULL;
        memcpy(name, p, len);
        name[len] = '\0';
        if (n->type != FT_DIR)
            return NULL;
        de = inode_search(n, name);
        if (!de)
            return NULL;
        n = de->inode;
        p = p1;
        if (!p)
            break;
    }
    return n;
}

static int filelist_load_rec(const char **pp, FLINode *dir,
                             const char *path)
{
    char fname[1024], lname[1024];
    int ret;
    const char *p;
    FLINodeTypeEnum type;
    uint32_t mode, uid, gid;
    uint64_t size;
    FLINode *n;

    p = *pp;
    for(;;) {
        /* skip comments or empty lines */
        if (*p == '\0')
            break;
        if (*p == '#') {
            skip_line(&p);
            continue;
        }
        /* end of directory */
        if (*p == '.') {
            p++;
            skip_line(&p);
            break;
        }
        if (parse_uint32_base(&mode, &p, 8) < 0) {
            fprintf(stderr, "invalid mode\n");
            return -1;
        }
        type = mode >> 12;
        mode &= 0xfff;

        if (parse_uint32(&uid, &p) < 0) {
            fprintf(stderr, "invalid uid\n");
            return -1;
        }

        if (parse_uint32(&gid, &p) < 0) {
            fprintf(stderr, "invalid gid\n");
            return -1;
        }

        n = inode_new(type, mode, uid, gid);

        size = 0;
        switch(type) {
        case FT_CHR:
        case FT_BLK:
            if (parse_uint32(&n->u.dev.major, &p) < 0) {
                fprintf(stderr, "invalid major\n");
                return -1;
            }
            if (parse_uint32(&n->u.dev.minor, &p) < 0) {
                fprintf(stderr, "invalid minor\n");
                return -1;
            }
            break;
        case FT_REG:
            if (parse_uint64(&size, &p) < 0) {
                fprintf(stderr, "invalid size\n");
                return -1;
            }
            break;
        case FT_DIR:
            break;
        default:
            break;
        }

        /* modification time */
        if (parse_time(&n->mtime_sec, &n->mtime_nsec, &p) < 0) {
            fprintf(stderr, "invalid mtime\n");
            return -1;
        }

        if (parse_fname(fname, sizeof(fname), &p) < 0) {
            fprintf(stderr, "invalid filename\n");
            return -1;
        }
        inode_dirent_add(dir, fname, n);

        if (type == FT_LNK) {
            if (parse_fname(lname, sizeof(lname), &p) < 0) {
                fprintf(stderr, "invalid symlink name\n");
                return -1;
            }
            n->u.symlink.name = strdup(lname);
        } else if (type == FT_REG && size > 0) {
            FSFileID file_id;
            if (parse_file_id(&file_id, &p) < 0) {
                fprintf(stderr, "invalid file id\n");
                return -1;
            }
            n->u.reg.size = size;
            n->u.reg.file_id = file_id;
        }

        skip_line(&p);

        if (type == FT_DIR) {
            char *path1;
            path1 = compose_path(path, fname);
            ret = filelist_load_rec(&p, n, path1);
            free(path1);
            if (ret)
                return ret;
        }
    }
    *pp = p;
    return 0;
}

int filelist_load(FLINode *root_inode, const char *str)
{
    int ret;
    const char *p;

    if (parse_tag_version(str) != 1)
        return -1;
    p = skip_header(str);
    if (!p)
        return -1;
    ret = filelist_load_rec(&p, root_inode, "");
    return ret;
}

ssize_t get_pass(char **pbuf);

static void __attribute__((format(printf, 1, 2))) fatal_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

void dbuf_put_quoted_str(DynBuf *s, const char *str)
{
    char *str1;
    if (!str)
        str = "";
    str1 = quoted_str(str);
    dbuf_putstr(s, str1);
    free(str1);
}


#ifdef CONFIG_FS_CMD
static void fs_write_cmd(const char *cmd)
{
    int fd, err;

    fd = open("/" FSCMD_NAME, O_WRONLY);
    if (fd < 0)
        goto fail;
    err = write(fd, cmd, strlen(cmd));
    if (err < 0) {
    fail:
        perror("/" FSCMD_NAME);
        exit(1);
    }
    close(fd);
}
#endif

/* return < 0 if error, otherwise the file size. Add a trailing '\0'
   in the loaded file */
static int fs_sync_load_file(FSDevice *fs, uint8_t **pbuf,
                             FSFile *dir_fd, const char *name,
                             int max_size)
{
    FSFile *fd;
    uint8_t *buf;
    int err, size;
    FSStat st;
    FSQID qid;

    fd = fs_walk_path(fs, dir_fd, name);
    if (!fd)
        return -P9_ENOENT;
    err = fs->fs_open(fs, &qid, fd, P9_O_RDONLY, NULL, NULL);
    if (err < 0) {
    fail:
        fs->fs_delete(fs, fd);
        return -1;
    }
    err = fs->fs_stat(fs, fd, &st);
    if (err < 0)
        goto fail;
    size = max_size;
    if (st.st_size < size)
        size = st.st_size;
    buf = malloc(size + 1);
    err = fs->fs_read(fs, fd, 0, buf, size);
    if (err < 0 || err != size)
        goto fail;
    fs->fs_delete(fs, fd);
    buf[size] = 0; /* add extra '\0' to ease parsing */
    *pbuf = buf;
    return size;
}

typedef struct {
    FSDevice *fs;
    FSFile *fd;
    uint64_t pos;
} FSStream;

static int fs_stream_write(FSStream *f, const uint8_t *buf, int len)
{
    FSDevice *fs = f->fs;
    int err;
    err = fs->fs_write(fs, f->fd, f->pos, (uint8_t *)buf, len);
    if (err < 0)
        return err;
    f->pos += len;
    return len;
}

static int __attribute__((format(printf, 2, 3))) fs_printf(FSStream *f,
                                                           const char *fmt, ...)
{
    va_list ap;
    char buf[4096];
    int len;

    va_start(ap, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len > sizeof(buf) - 1)
        fatal_error("print string too long");
    return fs_stream_write(f, (uint8_t *)buf, len);
}

/* return the root path and the corresponding URL from a user URL,
   assuming the root path starts after 'dir_count' directory in
   'url' */
static char *find_root_path_from_url(char **purl, const char *url,
                                     int dir_count)
{
    const char *p;
    int i;

    p = strchr(url, ':');
    if (!p)
        goto fail;
    p++;
    while (*p == '/')
        p++;
    for(i = 0; i < dir_count + 1; i++) {
        p = strchr(p, '/');
        if (!p) {
        fail:
            *purl = strdup(url);
            return strdup("/");
        }
        p++;
    }
    p--;
    *purl = strndup(url, p - url);
    return strdup(p);
}

static char *hash_password(const char *user, const char *password)
{
    char buf[128];
    uint8_t key[32];

    if (!password)
        return NULL;

    snprintf(buf, sizeof(buf), "user=%s", user);
    pbkdf2_hmac_sha256((uint8_t *)password, strlen(password),
                       (uint8_t *)buf, strlen(buf), 4096, 32,
                       key);
    encode_hex(buf, key, 32);
    return strdup(buf);
}

#define PWD_KEY_LEN 32
#define SALT_LEN 32

/* create a new encryption key */
static char *create_fs_key(const char *password)
{
    uint8_t secret_key[FS_KEY_LEN], encrypted_key[FS_KEY_LEN];
    uint8_t salt[SALT_LEN];
    uint8_t pwd_key[PWD_KEY_LEN];
    AES_KEY pwd_aes_state;
    char buf[SALT_LEN * 2 + FS_KEY_LEN * 2 + 1];

    RAND_bytes(secret_key, FS_KEY_LEN);
    RAND_bytes(salt, SALT_LEN);

    pbkdf2_hmac_sha256((uint8_t *)password, strlen(password), salt, SALT_LEN,
                       4096, PWD_KEY_LEN, pwd_key);
    AES_set_encrypt_key(pwd_key, PWD_KEY_LEN * 8, &pwd_aes_state);
    AES_encrypt(secret_key, encrypted_key, &pwd_aes_state);
    memset(secret_key, 0, FS_KEY_LEN);
    memset(pwd_key, 0, PWD_KEY_LEN);
    memset(&pwd_aes_state, 0, sizeof(pwd_aes_state));

    encode_hex(buf, salt, SALT_LEN);
    encode_hex(buf + SALT_LEN * 2, encrypted_key, FS_KEY_LEN);
    return strdup(buf);
}

static int decrypt_fs_key(uint8_t *secret_key, const char *key,
                          const char *password)
{
    uint8_t encrypted_key[FS_KEY_LEN];
    uint8_t salt[SALT_LEN];
    uint8_t pwd_key[PWD_KEY_LEN];
    AES_KEY pwd_aes_state;

    if (strlen(key) != (SALT_LEN * 2 + FS_KEY_LEN * 2))
        return -1;
    if (decode_hex(salt, key, SALT_LEN) < 0 ||
        decode_hex(encrypted_key, key + SALT_LEN * 2, FS_KEY_LEN) < 0)
        return -1;

    pbkdf2_hmac_sha256((uint8_t *)password, strlen(password), salt, SALT_LEN,
                       4096, PWD_KEY_LEN, pwd_key);
    AES_set_decrypt_key(pwd_key, PWD_KEY_LEN * 8, &pwd_aes_state);
    AES_decrypt(encrypted_key, secret_key, &pwd_aes_state);
    memset(pwd_key, 0, PWD_KEY_LEN);
    memset(&pwd_aes_state, 0, sizeof(pwd_aes_state));
    return 0;
}

static void set_fs_key(AES_KEY *aes_state_enc, AES_KEY *aes_state_dec,
                       const uint8_t *secret_key)
{
    AES_set_encrypt_key(secret_key, FS_KEY_LEN * 8, aes_state_enc);
    AES_set_decrypt_key(secret_key, FS_KEY_LEN * 8, aes_state_dec);
}

/* init syncdir */
static void fs_sync_init(FSDevice *fs, const char *url1,
                         const char *user, const char *pwd,
                         BOOL allow_existing_dir)
{
    FSFile *root_fd, *syncdir_fd, *fd;
    FSQID qid;
    int err;
    char *root_path, *url;
    FSStream fp_s, *fp = &fp_s;

    assert(!fs->fs_attach(fs, &root_fd, &qid, 0, "", ""));

    /* create the directory */
    err = fs->fs_mkdir(fs, &qid, root_fd, SYNCDIR_NAME, 0700, 0);
    if (err != 0) {
        if (!allow_existing_dir || err != -P9_EEXIST) {
            if (err == -P9_EEXIST)
                fatal_error("directory '%s' already exists\n", SYNCDIR_NAME);
            else
                fatal_error("could not create '%s' directory\n", SYNCDIR_NAME);
        }
    }
    syncdir_fd = fs_walk_path(fs, root_fd, SYNCDIR_NAME);
    if (!syncdir_fd)
        fatal_error("could not access to '%s' directory", SYNCDIR_NAME);

    fd = fs_dup(fs, syncdir_fd);
    err = fs->fs_create(fs, &qid, fd, "info.txt", P9_O_RDWR | P9_O_TRUNC,
                        0644, 0);
    if (err < 0)
        fatal_error("could not create '%s'", "info.txt");

    root_path = find_root_path_from_url(&url, url1, ROOT_DIR_COUNT);

    fp->fs = fs;
    fp->fd = fd;
    fp->pos = 0;
    fs_printf(fp, "Version: %d\n", 1);
    fs_printf(fp, "URL: %s\n", url);
    if (user) {
        fs_printf(fp, "User: %s\n", user);
        if (pwd) {
            fs_printf(fp, "Password: %s\n", pwd);
        }
    }
    fs_printf(fp, "RootPath: %s\n", root_path);
    fs->fs_delete(fs, fd);
    fs->fs_delete(fs, syncdir_fd);
    fs->fs_delete(fs, root_fd);

    free(url);
    free(root_path);
}

typedef struct {
    char *local_dir; /* absolute path of the repository in the local filesystem */
    FSDevice *fs;
    BOOL preserve_uid_gid;
    BOOL verbose;
    FSFile *root_fd;
    FSFile *syncdir_fd;
    char *url;
    char *user;
    char *user_password;
    char *http_password;
    char *root_path; /* path of the root on the server */
    BOOL need_agent_set;
    uint64_t revision; /* 0 means invalid */
    FSFileID next_file_id; /* only valid if revision is valid */
    BOOL has_root_id;
    FSFileID root_id;

    int wget_status;
    BOOL wget_completed;
    /* used in fs_sync_update() only */
    uint64_t new_revision;

    /* used in fs_sync_commit() only */
    BOOL fl_updated;
    char *new_fs_key;

    /* file encryption key */
    BOOL key_available;
    BOOL is_encrypted;
    uint8_t aes_key[FS_KEY_LEN];
    AES_KEY aes_state_enc;
    AES_KEY aes_state_dec;
} FSSyncState;

#define ERR(x) do { int _err = (x); if (_err < 0) fatal_error("%s:%d: error=%d", __FILE__, __LINE__, _err); } while (0)

static void revision_loaded(FSSyncState *s);
static void filelist_loaded(FSSyncState *s, BOOL has_filelist);
static void filelist_modfile_rec(FSSyncState *s, FSFile *dir_fd,
                                 FLINode *dir_cur,
                                 FLINode *dir_new,
                                 const char *path);

static void http_error(FSSyncState *s, int err, const char *url)
{
    err = -err;
    fprintf(stderr, "%s: HTTP error %u",
            url, err);
    switch(err) {
    case 401:
        fprintf(stderr, " (Unauthorized user)");
        break;
    case 404:
        fprintf(stderr, " (Not found)");
        break;
    default:
        break;
    }
    fprintf(stderr, "\n");
    exit(1);
}

#ifdef CONFIG_FS_CMD

void fs_wget_init(void)
{
}

void fs_wget_end(void)
{
}

void fs_net_event_loop(FSNetEventLoopCompletionFunc *cb, void *opaque)
{
}

int fs_wget_file3(FSSyncState *s,
                  const char *filename, const char *url,
                  const char *user, const char *password,
                  const char *post_filename, BOOL decrypt_flag)
{
    DynBuf cmd;
    int fd, err, err_code;
    char buf[256], *fname;

    //    printf("file=%s url=%s\n", filename, url);
    dbuf_init(&cmd);
    dbuf_putstr(&cmd, "xhr ");

    dbuf_put_quoted_str(&cmd, url);

    dbuf_putstr(&cmd, " ");
    dbuf_put_quoted_str(&cmd, user);

    dbuf_putstr(&cmd, " ");
    dbuf_put_quoted_str(&cmd, password);

    dbuf_putstr(&cmd, " ");
    if (post_filename) {
        fname = compose_path(s->local_dir, post_filename);
    } else {
        fname = NULL;
    }
    dbuf_put_quoted_str(&cmd, fname);
    free(fname);

    dbuf_putstr(&cmd, " ");
    fname = compose_path(s->local_dir, filename);
    dbuf_put_quoted_str(&cmd, fname);
    free(fname);

    dbuf_putstr(&cmd, " ");
    if (decrypt_flag) {
        encode_hex(buf, s->aes_key, FS_KEY_LEN);
        dbuf_put_quoted_str(&cmd, buf);
    } else {
        dbuf_put_quoted_str(&cmd, NULL);
    }

    snprintf(buf, sizeof(buf), " %d", 0); /* flags, not used yet */
    dbuf_putstr(&cmd, buf);

    fd = open("/" FSCMD_NAME, O_RDWR);
    if (fd < 0) {
        dbuf_free(&cmd);
        goto fail;
    }
    err = write(fd, cmd.buf, cmd.size);
    dbuf_free(&cmd);
    if (err < 0)
        goto fail;

    /* wait until the completion */
    for(;;) {
        err = read(fd, &err_code, sizeof(err_code));
        if (err < 0)
            goto fail;
        if (err > 0) {
            if (err != sizeof(err_code))
                goto fail;
            else
                break;
        }
        usleep(10 * 1000);
    }
    close(fd);
    return err_code;
 fail:
    perror("/" FSCMD_NAME);
    exit(1);
}

void pbkdf2_hmac_sha256(const uint8_t *pwd, int pwd_len,
                        const uint8_t *salt, int salt_len,
                        int iter, int key_len, uint8_t *out)
{
    DynBuf cmd;
    char buf[4096];
    int err, fd;

    dbuf_init(&cmd);
    dbuf_putstr(&cmd, "pbkdf2 ");

    encode_hex(buf, pwd, pwd_len);
    dbuf_putstr(&cmd, buf);

    dbuf_putstr(&cmd, " ");

    encode_hex(buf, salt, salt_len);
    dbuf_putstr(&cmd, buf);

    snprintf(buf, sizeof(buf), " %d %d", iter, key_len);
    dbuf_putstr(&cmd, buf);

    fd = open("/" FSCMD_NAME, O_RDWR);
    if (fd < 0)
        fatal_error("could not open %s", "/" FSCMD_NAME);
    err = write(fd, cmd.buf, cmd.size);
    dbuf_free(&cmd);
    if (err < 0)
        fatal_error("pbkdf2 write");

    /* wait until the completion */
    for(;;) {
        err = read(fd, out, key_len);
        if (err < 0)
            fatal_error("pbkdf2 read");
        if (err > 0) {
            if (err != key_len)
                fatal_error("pbkdf2 read");
            else
                break;
        }
        usleep(10 * 1000);
    }
    close(fd);
}

#else

static void download_file_cb(FSDevice *fs, FSFile *f, int64_t size, void *opaque)
{
    FSSyncState *s = opaque;
    s->wget_status = size;
    s->wget_completed = TRUE;
}

static BOOL download_file_completion(void *opaque)
{
    FSSyncState *s = opaque;

    return s->wget_completed;
}

int fs_wget_file3(FSSyncState *s,
                  const char *filename, const char *url,
                  const char *user, const char *password,
                  const char *post_filename,
                  BOOL decrypt_flag)
{
    FSDevice *fs = s->fs;
    FSFile *fd, *post_fd;
    FSQID qid;
    char *name;
    uint64_t post_data_len;
    FSStat st;
    int err;
    AES_KEY *aes_state;

    //    printf("file=%s url=%s\n", filename, url);
    fd = fs_walk_path1(fs, s->root_fd, filename, &name);
    if (!fd)
        fatal_error("%s: invalid path", filename);
    err = fs->fs_create(fs, &qid, fd, name,
                        P9_O_RDWR | P9_O_TRUNC, 0600, 0);
    if (err < 0) {
        fatal_error("%s: could not create file", filename);
    }

    if (post_filename) {
        post_fd = fs_walk_path(fs, s->root_fd, post_filename);
        if (!post_fd)
            fatal_error("%s: file not found", post_filename);
        err = fs->fs_open(fs, &qid, post_fd, P9_O_RDONLY, NULL, NULL);
        if (err < 0)
            fatal_error("%s: could not open file", post_filename);
        err = fs->fs_stat(fs, post_fd, &st);
        if (err < 0)
            fatal_error("%s: could not stat file", post_filename);
        post_data_len = st.st_size;
    } else {
        post_fd = NULL;
        post_data_len = 0;
    }

    if (decrypt_flag && s->is_encrypted)
        aes_state = &s->aes_state_dec;
    else
        aes_state = NULL;
    s->wget_completed = FALSE;

    fs_wget_file2(fs, fd, url, user, password, post_fd, post_data_len,
                  download_file_cb, s, aes_state);

    fs_net_event_loop(download_file_completion, s);

    fs->fs_delete(fs, fd);
    if (post_fd) {
        fs->fs_delete(fs, post_fd);
    }

    return s->wget_status;
}

#endif

static void fs_sync_set_fs_key(FSSyncState *s, const char *key)
{
    if (key[0] == '\0') {
        s->is_encrypted = FALSE;
    } else {
        if (decrypt_fs_key(s->aes_key, (char *)key, s->user_password) < 0)
            fatal_error("invalid FS key");
        set_fs_key(&s->aes_state_enc, &s->aes_state_dec, s->aes_key);
        s->is_encrypted = TRUE;
    }
}

static int fs_sync_agent_set_get_password(FSSyncState *s,
                                          BOOL set)
{
    const char *sock_path;
    int fd;
    struct sockaddr_un addr;
    DynBuf cmd;
    char buf[4096];
    int len, err;
    const char *p;
    char buf1[32], password1[256], password2[256], password3[256];

    sock_path = getenv("VFSYNC_SOCK");
    if (!sock_path)
        return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    addr.sun_family = AF_UNIX;
    pstrcpy(addr.sun_path, sizeof(addr.sun_path), sock_path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    dbuf_init(&cmd);

    if (set) {
        dbuf_putstr(&cmd, "set ");
        dbuf_put_quoted_str(&cmd, s->url);
        dbuf_putstr(&cmd, " ");
        dbuf_put_quoted_str(&cmd, s->user);
        dbuf_putstr(&cmd, " ");
        dbuf_put_quoted_str(&cmd, s->user_password);
        dbuf_putstr(&cmd, " ");
        dbuf_put_quoted_str(&cmd, s->http_password);
        dbuf_putstr(&cmd, " ");
        if (s->key_available && s->is_encrypted) {
            encode_hex(buf, s->aes_key, FS_KEY_LEN);
            dbuf_put_quoted_str(&cmd, buf);
        } else {
            dbuf_put_quoted_str(&cmd, NULL);
        }
    } else {
        dbuf_putstr(&cmd, "get ");
        dbuf_put_quoted_str(&cmd, s->url);
        dbuf_putstr(&cmd, " ");
        dbuf_put_quoted_str(&cmd, s->user);
    }

#if 0
    {
        dbuf_putc(&cmd, 0);
        printf("cmd=%s\n", (char *)cmd.buf);
    }
#endif

    err = write(fd, cmd.buf, cmd.size);
    if (err < 0) {
        perror("write");
        exit(1);
    }

    dbuf_free(&cmd);

    len = read(fd, buf, sizeof(buf) - 1);
    if (len < 0) {
        perror("read");
        exit(1);
    }
    buf[len] = '\0';

    //    printf("reply=%s\n", buf);

    p = buf;
    if (parse_fname(buf1, sizeof(buf1), &p) < 0)
        goto fail;

    if (strcmp(buf1, "ok") != 0)
        goto fail;

    if (!set) {
        if (parse_fname(password1, sizeof(password1), &p) < 0)
            goto fail;
        if (parse_fname(password2, sizeof(password2), &p) < 0)
            goto fail;
        if (parse_fname(password3, sizeof(password3), &p) < 0)
            goto fail;
        s->user_password = strdup(password1);
        s->http_password = strdup(password2);
        if (password3[0] != '\0') {
            if (decode_hex(s->aes_key, password3, FS_KEY_LEN) < 0)
                fatal_error("invalid agent key");
            set_fs_key(&s->aes_state_enc, &s->aes_state_dec,
                       s->aes_key);
            s->key_available = TRUE;
            s->is_encrypted = TRUE;
        }
    }
    close(fd);
    return err;
 fail:
    close(fd);
    return -1;
}

/* password given on the command line */
static char *cmdline_pwd;

static void fs_sync_read_password(FSSyncState *s)
{
    char *password;

    if (!s->user)
        return;

    if (fs_sync_agent_set_get_password(s, FALSE) < 0) {
        if (cmdline_pwd) {
            password = strdup(cmdline_pwd);
        } else {
            printf("Password: ");
            password = NULL;
            if (get_pass(&password) < 0) {
                fprintf(stderr, "Could not read password\n");
                exit(1);
            }
        }
        s->user_password = password;
        s->http_password = hash_password(s->user, password);
        s->need_agent_set = TRUE;
    }
}

/* XXX: use flock, but need to support it in fs_net() */
static void fs_lock(FSSyncState *s)
{
    char *lock_fname;
    char buf[64];
    BOOL has_lock;
    int pid, fd, len, err;

    has_lock = FALSE;
    lock_fname = compose_path(s->local_dir, SYNCDIR_NAME "/lock");
    for(;;) {
        fd = open(lock_fname, O_RDWR | O_CREAT | O_TRUNC | O_EXCL, 0600);
        if (fd >= 0) {
            /* the lock file does not exists : create it */
            snprintf(buf, sizeof(buf), "%d", getpid());
            err = write(fd, buf, strlen(buf));
            close(fd);
            if (err < 0) {
                perror("write");
                exit(1);
            }
            break;
        } else {
            /* the lock exists : see if there is still a process holding it */
            fd = open(lock_fname, O_RDONLY);
            if (fd < 0) {
                if (errno == ENOENT) {
                    continue;
                } else {
                    perror(lock_fname);
                    exit(1);
                }
            }
            len = read(fd, buf, sizeof(buf) - 1);
            if (len < 0) {
                perror(lock_fname);
                exit(1);
            }
            close(fd);
            pid = strtol(buf, NULL, 0);
            if (kill(pid, 0) < 0) {
                /* the process no longer exists */
                unlink(lock_fname);
            } else {
                /* the lock exists: wait */
                if (!has_lock) {
                    has_lock = TRUE;
                    printf("Waiting for lock\n");
                }
                usleep(100 * 1000);
            }
        }
    }
    free(lock_fname);
}

static void fs_unlock(FSSyncState *s)
{
    char *lock_fname;
    lock_fname = compose_path(s->local_dir, SYNCDIR_NAME "/lock");
    unlink(lock_fname);
    free(lock_fname);
}

#define SYNC_FLAG_DRY_RUN          (1 << 0)
#define SYNC_FLAG_QUIET            (1 << 1)
#define SYNC_FLAG_PRESERVE_UID_GID (1 << 2)
#define SYNC_FLAG_CHECKOUT         (1 << 3)

static FSSyncState *fs_sync_start(const char *local_dir, int flags)
{
    FSSyncState *s;
    FSDevice *fs;
    uint8_t *buf;
    int size, err, version;
    char fname[1024];
    FSStat st;
    FSQID qid;

    fs = fs_disk_init(local_dir);
    if (!fs) {
        fprintf(stderr, "%s: not a directory\n", local_dir);
        exit(1);
    }

    s = mallocz(sizeof(*s));
    s->local_dir = strdup(local_dir);
    s->fs = fs;
    s->preserve_uid_gid = ((flags & SYNC_FLAG_PRESERVE_UID_GID) != 0);
    s->verbose = !(flags & SYNC_FLAG_QUIET);
    assert(!fs->fs_attach(fs, &s->root_fd, &qid, 0, "", ""));

    s->syncdir_fd = fs_walk_path(fs, s->root_fd, SYNCDIR_NAME);
    if (!s->syncdir_fd)
        fatal_error("could not find '%s' directory\n", SYNCDIR_NAME);

    err = fs->fs_stat(fs, s->syncdir_fd, &st);
    if (err < 0 || (st.st_mode & P9_S_IFMT) != P9_S_IFDIR)
        fatal_error("'%s' must be a directory\n", SYNCDIR_NAME);

    fs_lock(s);

    size = fs_sync_load_file(fs, &buf, s->syncdir_fd, "info.txt", INT_MAX);
    if (size < 0)
        fatal_error("could not load info.txt");

    version = parse_tag_version((char *)buf);
    if (version != 1)
        fatal_error("Unusupported version: %d\n", version);

    if (parse_tag(fname, sizeof(fname), (char *)buf, "URL") < 0)
        fatal_error("cannot parse URL");
    s->url = strdup(fname);

    if (parse_tag(fname, sizeof(fname), (char *)buf, "User") >= 0) {
        s->user = strdup(fname);
    }

    if (s->user &&
        parse_tag(fname, sizeof(fname), (char *)buf, "Password") >= 0) {
        s->user_password = strdup(fname);
        s->http_password = hash_password(s->user, s->user_password);
    } else {
        fs_sync_read_password(s);
    }

    if (parse_tag(fname, sizeof(fname), (char *)buf, "RootPath") < 0)
        fatal_error("cannot parse RootPath");
    s->root_path = strdup(fname);

    free(buf);

    s->has_root_id = FALSE;
    size = fs_sync_load_file(fs, &buf, s->syncdir_fd, "current.txt", INT_MAX);
    if (size < 0) {
        s->revision = 0; /* no current revision */
    } else {
        version = parse_tag_version((char *)buf);
        if (version != 1)
            fatal_error("Unusupported version: %d\n", version);
        if (parse_tag_uint64(&s->revision, (char *)buf, "Revision") < 0 ||
            s->revision == 0)
            fatal_error("invalid Revision tag");
        if (parse_tag_file_id(&s->next_file_id, (char *)buf, "NextFileID") < 0)
            fatal_error("invalid NextFileID tag");
        if (parse_tag_file_id(&s->root_id, (char *)buf, "RootID") >= 0)
            s->has_root_id = TRUE;
        free(buf);
    }

    if (!s->key_available) {
        size = fs_sync_load_file(fs, &buf, s->syncdir_fd, "key.txt", INT_MAX);
        if (size >= 0) {
            fs_sync_set_fs_key(s, (char *)buf);
            s->key_available = TRUE;
            free(buf);
        }
    }

    return s;
}

/* also call the end callback */
static void fs_sync_end(FSSyncState *s, int err)
{
    FSDevice *fs = s->fs;
    fs_unlock(s);
    if (s->root_fd)
        fs->fs_delete(fs, s->root_fd);
    if (s->syncdir_fd)
        fs->fs_delete(fs, s->syncdir_fd);
    free(s->new_fs_key);
    free(s->url);
    free(s->user);
    free(s->user_password);
    free(s->http_password);
    free(s->root_path);
    free(s->local_dir);
    fs_end(fs);
    free(s);
}

static void remove_checkout_sync_dir(FSSyncState *s)
{
    FSDevice *fs = s->fs;
    fs_unlock(s);
    fs->fs_unlinkat(fs, s->syncdir_fd, HEAD_FILENAME);
    fs->fs_unlinkat(fs, s->syncdir_fd, "info.txt");
    fs->fs_unlinkat(fs, s->root_fd, SYNCDIR_NAME);
}

static void fs_sync_update(const char *local_dir, int flags)
{
    FSSyncState *s;
    char buf[128], *url;
    struct timeval tv;
    int ret;

    s = fs_sync_start(local_dir, flags);
    if (s->verbose)
        printf("Updating:\n");

    /* check if new revision on server */
    /* avoid using cached version */
    gettimeofday(&tv, NULL);
    snprintf(buf, sizeof(buf), HEAD_FILENAME "?nocache=%" PRId64,
             (int64_t)tv.tv_sec * 1000000 + tv.tv_usec);
    url = compose_url(s->url, buf);
    ret = fs_wget_file3(s, SYNCDIR_NAME "/" HEAD_FILENAME,
                        url, s->user, s->http_password,
                        NULL, FALSE);
    if (ret < 0) {
        if (flags & SYNC_FLAG_CHECKOUT) {
            /* in case of error, remove the created dir.  XXX: should
               create the directory later, but need to reorganize the
               code */
            remove_checkout_sync_dir(s);
        }
        http_error(s, ret, url);
    }
    free(url);
    revision_loaded(s);
}

/* set the encryption key in the local repository */
static void write_fs_key(FSSyncState *s, const char *key)
{
    FSDevice *fs = s->fs;
    FSFile *fd;
    FSQID qid;
    int err, key_len;

    fd = fs_dup(fs, s->syncdir_fd);
    err = fs->fs_create(fs, &qid, fd, "key.txt", P9_O_RDWR | P9_O_TRUNC,
                        0600, 0);
    if (err < 0)
        fatal_error("could not create key.txt");
    key_len = strlen(key);
    fs->fs_write(fs, fd, 0, (uint8_t *)key, key_len);
    fs->fs_delete(fs, fd);
}

static void revision_loaded(FSSyncState *s)
{
    FSDevice *fs = s->fs;
    char *buf;
    char buf1[256];
    uint64_t fs_max_size;

    if (fs_sync_load_file(fs, (uint8_t **)&buf, s->syncdir_fd, HEAD_FILENAME, INT_MAX) < 0)
        fatal_error("could not open %s", HEAD_FILENAME);
    fs->fs_unlinkat(fs, s->syncdir_fd, HEAD_FILENAME);

    if (parse_tag_version(buf) != 1)
        fatal_error("invalid version");
    if (parse_tag_uint64(&s->new_revision, buf, "Revision") < 0 || s->new_revision == 0)
        fatal_error("invalid revision");
    if (parse_tag_file_id(&s->next_file_id, buf, "NextFileID") < 0)
        fatal_error("invalid NextFileID");
    if (parse_tag_uint64(&fs_max_size, buf, "FSMaxSize") < 0)
        fatal_error("invalid FSMaxSize");

    s->has_root_id = FALSE;
    if (parse_tag_file_id(&s->root_id, buf, "RootID") >= 0)
        s->has_root_id = TRUE;

    /* set the key if not known yet (only happens in checkout or after
       first commit) */
    if (!s->key_available &&
        parse_tag(buf1, sizeof(buf1), buf, "Key") >= 0) {
        write_fs_key(s, buf1);
        fs_sync_set_fs_key(s, buf1);
        s->key_available = TRUE;
        /* update the encryption key in agent */
        s->need_agent_set = TRUE;
    }

    /* set the agent password only if we got at least one URL correctly */
    if (s->need_agent_set) {
        fs_sync_agent_set_get_password(s, TRUE);
    }

    /* set the Root URL in the filesystem */
#ifdef CONFIG_FS_CMD
    {
        DynBuf cmd;
        char *root_url;

        root_url = compose_url(s->url, ROOT_FILENAME);

        dbuf_init(&cmd);
        dbuf_putstr(&cmd, "set_base_url ");
        dbuf_put_quoted_str(&cmd, s->local_dir);
        dbuf_putstr(&cmd, " ");
        dbuf_put_quoted_str(&cmd, root_url);
        dbuf_putstr(&cmd, " ");
        dbuf_put_quoted_str(&cmd, s->user);
        dbuf_putstr(&cmd, " ");
        dbuf_put_quoted_str(&cmd, s->http_password);

        dbuf_putstr(&cmd, " ");
        if (s->is_encrypted) {
            char buf[FS_KEY_LEN * 2 + 1];
            encode_hex(buf, s->aes_key, FS_KEY_LEN);
            dbuf_put_quoted_str(&cmd, buf);
        } else {
            dbuf_put_quoted_str(&cmd, NULL);
        }

        dbuf_putc(&cmd, '\0');

        fs_write_cmd((char *)cmd.buf);
        dbuf_free(&cmd);
        free(root_url);
    }
#endif

    if (s->new_revision < s->revision) {
        fatal_error("Server revision less than current revision (%" PRIu64
                    " < %" PRIu64 ")", s->new_revision, s->revision);
    }
    if (s->new_revision == s->revision) {
        if (s->verbose)
            printf("Already up to date\n");
        /* we are up to date */
        fs_sync_end(s, FS_ERR_OK);
    } else if (!s->has_root_id) {
        /* no file list yet */
        filelist_loaded(s, FALSE);
    } else {
        char *root_url, *url;
        char root_id[64];
        int ret;

        url = compose_url(s->url, ROOT_FILENAME);
        snprintf(root_id, sizeof(root_id), "%016" PRIx64, s->root_id);
        root_url = compose_url(url, root_id);
        ret = fs_wget_file3(s, SYNCDIR_NAME "/" FILELIST_FILENAME ".new",
                            root_url, s->user, s->http_password,
                            NULL, s->is_encrypted);
        if (ret < 0) {
            http_error(s, ret, root_url);
        }
        free(root_url);
        free(url);
        filelist_loaded(s, TRUE);
    }
}

static void update_current_revision(FSSyncState *s)
{
    FSDevice *fs = s->fs;
    FSFile *fd;
    FSStream fp_s, *fp = &fp_s;
    FSQID qid;

    fs->fs_unlinkat(fs, s->syncdir_fd, "current.txt");
    fd = fs_dup(fs, s->syncdir_fd);
    ERR(fs->fs_create(fs, &qid, fd, "current.txt", P9_O_RDWR | P9_O_TRUNC,
                      0644, 0));
    fp->fs = fs;
    fp->fd = fd;
    fp->pos = 0;
    fs_printf(fp, "Version: %d\n", 1);
    fs_printf(fp, "Revision: %" PRIu64 "\n", s->new_revision);
    fs_printf(fp, "NextFileID: %" PRIx64 "\n", s->next_file_id);
    if (s->has_root_id) {
        fs_printf(fp, "RootID: %" PRIx64 "\n", s->root_id);
    }
    fs->fs_delete(fs, fd);
}

static void filelist_loaded(FSSyncState *s, BOOL has_filelist)
{
    FSDevice *fs = s->fs;
    uint8_t *buf;
    FLINode *fl_new, *fl_cur;
    int err, size;

    fl_new = inode_new(FT_DIR, 0777, 0, 0);
    if (has_filelist) {
        if (fs_sync_load_file(fs, &buf, s->syncdir_fd,
                              FILELIST_FILENAME ".new", INT_MAX) < 0)
            fatal_error("could not open %s", FILELIST_FILENAME ".new");

        err = filelist_load(fl_new, (char *)buf);
        if (err < 0)
            fatal_error("error while loading new file list");
        free(buf);
    }
    if (s->verbose)
        printf("Updating to revision %" PRIu64 "\n", s->new_revision);

    /* load the current file list, if any */
    size = fs_sync_load_file(fs, &buf, s->syncdir_fd, FILELIST_FILENAME, INT_MAX);
    if (size >= 0) {
        fl_cur = inode_new(FT_DIR, 0777, 0, 0);
        err = filelist_load(fl_cur, (char *)buf);
        if (err < 0)
            fatal_error("error while loading new file list");
        free(buf);
    } else {
        fl_cur = NULL;
    }

    if (s->new_revision < s->revision) {
        fatal_error("Server revision less than current revision (%" PRIu64 " < %" PRIu64 ")",
                    s->new_revision, s->revision);
    }

    filelist_modfile_rec(s, s->root_fd,
                         inode_search_path(fl_cur, s->root_path),
                         inode_search_path(fl_new, s->root_path),
                         "");
    if (fl_cur)
        inode_free(fl_cur);

    if (has_filelist) {
        /* use the new file list */
        err = fs->fs_renameat(fs, s->syncdir_fd, FILELIST_FILENAME ".new",
                              s->syncdir_fd, FILELIST_FILENAME);
        if (err < 0)
            fatal_error("cannot rename %s (err=%d)", FILELIST_FILENAME, err);
    }
    inode_free(fl_new);

    /* update/create the stored revision */
    update_current_revision(s);

    /* we are up to date */
    fs_sync_end(s, FS_ERR_OK);
}

static void conflict_rename(FSSyncState *s,
                            FSDevice *fs, FSFile *dir_fd, const char *name,
                            const char *path)
{
    char new_name[1024];
    uint32_t n;
    FSFile *fd;
    int err;

    /* XXX: inefficient and potentially incorrect if the name is too long */
    n = 1;
    for(;;) {
        snprintf(new_name, sizeof(new_name), "%s.%u", name, n);
        fd = fs_walk_path(fs, dir_fd, new_name);
        if (!fd)
            break;
        fs->fs_delete(fs, fd);
        n++;
    }

    if (s->verbose) {
        char *fname, *fname_new;
        fname = compose_path(path, name);
        fname_new = compose_path(path, new_name);
        printf("Conflict: renaming '%s' to '%s'\n", fname, fname_new);
        free(fname);
        free(fname_new);
    }

    err = fs->fs_renameat(fs, dir_fd, name, dir_fd, new_name);
    if (err < 0)
        fatal_error("could not rename '%s' to '%s'", name, new_name);
}

#ifdef CONFIG_FS_CMD
static void download_file(FSSyncState *s, FSFileID file_id, const char *path,
                          uint64_t size)
{
    DynBuf cmd;
    char fname[FILEID_SIZE_MAX];
    char buf[32];
    char *filename;

    dbuf_init(&cmd);
    dbuf_putstr(&cmd, "set_url ");

    filename = compose_path(s->local_dir, path);
    dbuf_put_quoted_str(&cmd, filename);
    free(filename);

    dbuf_putstr(&cmd, " ");
    dbuf_put_quoted_str(&cmd, s->local_dir);

    file_id_to_filename(fname, file_id);
    dbuf_putstr(&cmd, " ");
    dbuf_putstr(&cmd, fname);

    snprintf(buf, sizeof(buf), " %" PRIu64, size);
    dbuf_putstr(&cmd, buf);

    dbuf_putc(&cmd, '\0');

    fs_write_cmd((char *)cmd.buf);
    dbuf_free(&cmd);
}
#else
static void download_file(FSSyncState *s, FSFileID file_id, const char *path,
                          uint64_t size)
{
    char *root_url, *url, fname[FILEID_SIZE_MAX];
    int ret;

    file_id_to_filename(fname, file_id);
    root_url = compose_url(s->url, ROOT_FILENAME);
    url = compose_url(root_url, fname);

    ret = fs_wget_file3(s, path, url, s->user, s->http_password,
                  NULL, s->is_encrypted);
    if (ret < 0) {
        http_error(s, ret, url);
    }
    free(url);
    free(root_url);
}
#endif

static FSFile *sync_newfile(FSSyncState *s, FSFile *dir_fd,
                            FLINode *n, const char *path, const char *name)
{
    FSDevice *fs = s->fs;
    FSFile *fd;
    int err;
    FSQID qid;

    if (s->verbose) {
        char *fname;
        fname = compose_path(path, name);
        printf("Adding '%s'\n", fname);
        free(fname);
    }
    /* file does not exist: add it */
    fd = NULL;
    switch(n->type) {
    case FT_REG:
        fd = fs_dup(fs, dir_fd);
        err = fs->fs_create(fs, &qid, fd, name, P9_O_RDWR | P9_O_TRUNC,
                            0600, n->gid);
        if (err < 0)
            fatal_error("could not create '%s'", name);
        if (n->u.reg.size > 0) {
            char *fname;
            fname = compose_path(path, name);
            download_file(s, n->u.reg.file_id, fname, n->u.reg.size);
            free(fname);
        }
        break;
    case FT_CHR:
    case FT_BLK:
        {
            err = fs->fs_mknod(fs, &qid, dir_fd, name,
                               0600 | (n->type << 12),
                               n->u.dev.major, n->u.dev.minor, n->gid);
            if (err < 0)
                fatal_error("could not create '%s'", name);
        }
        break;
    case FT_FIFO:
    case FT_SOCK:
        {
            err = fs->fs_mknod(fs, &qid, dir_fd, name,
                               0600 | (n->type << 12),
                               0, 0, n->gid);
            if (err < 0)
                fatal_error("could not create '%s'", name);
        }
        break;
    case FT_LNK:
        {
            err = fs->fs_symlink(fs, &qid, dir_fd, name,
                                 n->u.symlink.name, n->gid);
            if (err < 0)
                fatal_error("could not create '%s'", name);
        }
        break;
    case FT_DIR:
        {
            err = fs->fs_mkdir(fs, &qid, dir_fd, name, 0700,
                               n->gid);
            if (err < 0)
                fatal_error("could not create '%s'", name);
        }
        break;
    default:
        abort();
    }

    if (!fd) {
        fd = fs_walk_path(fs, dir_fd, name);
        if (!fd)
            fatal_error("could not open '%s'", name);
    }
    return fd;
}

/* recursive comparison */
static BOOL same_inode(FLINode *n1, FLINode *n2)
{
    if (n1->type != n2->type)
        return FALSE;
    if (n1->mtime_sec != n2->mtime_sec ||
        n1->mtime_nsec != n2->mtime_nsec ||
        n1->uid != n2->uid ||
        n1->gid != n2->gid ||
        n1->mode != n2->mode)
        return FALSE;

    switch(n1->type) {
    case FT_REG:
        if (n1->u.reg.size != n2->u.reg.size)
            return FALSE;
        break;
    case FT_DIR:
        {
            struct list_head *el;
            FLDirEntry *de1, *de2;

            list_for_each(el, &n1->u.dir.de_list) {
                de2 = list_entry(el, FLDirEntry, link);
                de2->mark = 0;
            }

            list_for_each(el, &n1->u.dir.de_list) {
                de1 = list_entry(el, FLDirEntry, link);

                de2 = inode_search(n2, de1->name);
                if (!de2)
                    return FALSE;
                if (!same_inode(de1->inode, de2->inode))
                    return FALSE;
                de2->mark = 1;
            }

            list_for_each(el, &n1->u.dir.de_list) {
                de2 = list_entry(el, FLDirEntry, link);
                if (!strcmp(de2->name, ".") || !strcmp(de2->name, ".."))
                    continue;
                if (!de2->mark)
                    return FALSE;
            }
        }
        break;
    case FT_FIFO:
    case FT_SOCK:
        break;
    case FT_CHR:
    case FT_BLK:
        if (n1->u.dev.major != n2->u.dev.major ||
            n1->u.dev.minor != n2->u.dev.minor)
            return FALSE;
        break;
    case FT_LNK:
        if (strcmp(n1->u.symlink.name, n2->u.symlink.name) != 0)
            return FALSE;
        break;
    default:
        abort();
    }
    return TRUE;
}

/* note: only the content of regular files, symlink and devices is
   checked. Regular files are considered identical if they have the
   same size and mtime. */
static BOOL same_content(FSSyncState *s, FSFile *f, FSStat *st, FLINode *n)
{
    int err;
    char buf[1024];

    if ((st->st_mode >> 12) != n->type)
        return FALSE;
    switch(n->type) {
    case FT_REG:
        if (st->st_size != n->u.reg.size ||
            st->st_mtime_sec != n->mtime_sec ||
            st->st_mtime_nsec != n->mtime_nsec)
            return FALSE;
        break;
    case FT_LNK:
        err = s->fs->fs_readlink(s->fs, buf, sizeof(buf), f);
        if (err < 0)
            fatal_error("cannot read symlink");
        if (strcmp(buf, n->u.symlink.name) != 0)
            return FALSE;
        break;
    case FT_CHR:
    case FT_BLK:
        if (st->st_rdev != ((n->u.dev.major << 8) | n->u.dev.minor))
            return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

static int fs_iterate_dir(FSDevice *fs, FSFile *dir_fd,
                          int (*cb)(FSDevice *fs, FSFile *dir_fd,
                                    const char *name, void *opaque),
                          void *opaque)
{
    FSQID qid;
    uint64_t offset;
    uint8_t buf[1024];
    int err, pos, name_len, len;
    char *name;

    err = fs->fs_open(fs, &qid, dir_fd, P9_O_RDONLY | P9_O_DIRECTORY,
                      NULL, NULL);
    if (err < 0)
        return err;
    offset = 0;
    for(;;) {
        len = fs->fs_readdir(fs, dir_fd, offset, buf, sizeof(buf));
        if (len < 0)
            fatal_error("readdir error");
        if (len == 0)
            break;
        pos = 0;
        while (pos < len) {
            pos += 13;
            offset = get_le64(buf + pos);
            pos += 8 + 1;
            name_len = get_le16(buf + pos);
            pos += 2;
            name = malloc(name_len + 1);
            memcpy(name, buf + pos, name_len);
            pos += name_len;
            name[name_len] = 0;

            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                err = cb(fs, dir_fd, name, opaque);
            } else {
                err = 0;
            }
            free(name);
            if (err)
                return err;
        }
    }
    return 0;
}

typedef struct {
    FSSyncState *s;
    FLINode *n;
} SameFileCBState;

static BOOL same_file(FSSyncState *s, FSFile *f, FSStat *st, FLINode *n);

static int same_file_cb(FSDevice *fs, FSFile *dir_fd,
                        const char *name, void *opaque)
{
    SameFileCBState *state = opaque;
    FLINode *n1;
    FSFile *f1;
    FSStat st1;
    FLDirEntry *de;

    de = inode_search(state->n, name);
    if (!de)
        return FALSE;
    n1 = de->inode;
    f1 = fs_walk_path(fs, dir_fd, name);
    if (!f1)
        return 1;
    if (fs->fs_stat(fs, f1, &st1) != 0)
        return 1;
    if (!same_file(state->s, f1, &st1, n1))
        return 1;
    fs->fs_delete(fs, f1);
    de->mark = 1;
    return 0;
}

/* recursive comparison */
static BOOL same_file1(FSSyncState *s, FSFile *f, FSStat *st, FLINode *n,
                       BOOL recurse)
{
#if 0
    printf("same file: %u %u %u %u\n",
           (int)st->st_mtime_sec, n->mtime_sec,
           st->st_mtime_nsec, n->mtime_nsec);
#endif
    if (st->st_mtime_sec != n->mtime_sec ||
        st->st_mtime_nsec != n->mtime_nsec)
        return FALSE;
    if (!same_content(s, f, st, n))
        return FALSE;
    if (s->preserve_uid_gid &&
        (st->st_uid != n->uid ||
         st->st_gid != n->gid))
        return FALSE;
    /* check permissions */
    if (n->type != FT_LNK &&
        (st->st_mode & 0xfff) != n->mode) {
        return FALSE;
    }
    /* check directory content recursively */
    if (n->type == FT_DIR && recurse) {
        FSDevice *fs;
        FSFile *dir_fd;
        FLDirEntry *de;
        struct list_head *el;
        SameFileCBState state;
        int err;

        fs = s->fs;

        list_for_each(el, &n->u.dir.de_list) {
            de = list_entry(el, FLDirEntry, link);
            de->mark = 0;
        }

        dir_fd = fs_dup(fs, f);

        state.s = s;
        state.n = n;
        err = fs_iterate_dir(fs, dir_fd, same_file_cb, &state);

        fs->fs_delete(fs, dir_fd);

        if (err)
            return FALSE;

        /* see if there are more files in 'n' */
        err = 0;
        list_for_each(el, &n->u.dir.de_list) {
            de = list_entry(el, FLDirEntry, link);
            if (!strcmp(de->name, ".") || !strcmp(de->name, ".."))
                continue;
            if (!de->mark)
                return FALSE;
        }
    }
    return TRUE;
}

static BOOL same_file(FSSyncState *s, FSFile *f, FSStat *st, FLINode *n)
{
    return same_file1(s, f, st, n, TRUE);
}

/* recursive remove */
static int remove_file_or_dir(FSDevice *fs, FSFile *f, const char *name,
                              const char *path, BOOL verbose);

typedef struct {
    char *path;
    BOOL verbose;
} RemoveFileState;

static int remove_file_or_dir_cb(FSDevice *fs, FSFile *f, const char *name,
                                 void *opaque)
{
    RemoveFileState *rs = opaque;
    return remove_file_or_dir(fs, f, name, rs->path, rs->verbose);
}

static int remove_file_or_dir(FSDevice *fs, FSFile *f, const char *name,
                              const char *path, BOOL verbose)
{
    int err;
    RemoveFileState rs;
    FSFile *f1;

    if (verbose) {
        char *fname;
        fname = compose_path(path, name);
        printf("Removing '%s'\n", fname);
        free(fname);
    }

    err = fs->fs_unlinkat(fs, f, name);
    if (err < 0) {
        if (err == -P9_ENOTEMPTY) {
            /* remove all files in the directory */
            f1 = fs_walk_path(fs, f, name);
            if (!f1)
                return -P9_ENOENT;
            rs.path = compose_path(path, name);
            rs.verbose = verbose;
            err = fs_iterate_dir(fs, f1, remove_file_or_dir_cb, &rs);
            free(rs.path);
            fs->fs_delete(fs, f1);
            if (err)
                return err;
            return fs->fs_unlinkat(fs, f, name);
        } else {
            return err;
        }
    }
    return 0;
}

/* 'dir' is a directory in fl_new. 'path' is the local path (relative
   to the local repository root) */
/* XXX: handle removed files correctly */
static void filelist_modfile_rec(FSSyncState *s, FSFile *dir_fd,
                                 FLINode *dir_cur,
                                 FLINode *dir_new,
                                 const char *path)
{
    FSDevice *fs = s->fs;
    FLDirEntry *de, *de1;
    FSFile *fd;
    FLINode *n, *n1;
    uint32_t setattr_mask;
    int err, f_type;
    struct list_head *el;
    FSStat st;

    //    printf("modfile_rec: path=%s\n", path);
    list_for_each(el, &dir_new->u.dir.de_list) {
        de = list_entry(el, FLDirEntry, link);
        if (!strcmp(de->name, ".") || !strcmp(de->name, ".."))
            continue;

        n = de->inode;

        fd = fs_walk_path(fs, dir_fd, de->name);
        n1 = NULL;
        if (dir_cur) {
            de1 = inode_search(dir_cur, de->name);
            if (de1)
                n1 = de1->inode;
        }
        if (n1) {
            if (same_inode(n, n1)) {
                /* no change (the local content does not matter) */
            } else {
                /* file or dir was modified */
                if (!fd) {
                    /* no existing file: just add new file */
                    goto add_file;
                } else {
                    /* modified file with local content */
                    err = fs->fs_stat(fs, fd, &st);
                    if (err < 0)
                        fatal_error("cannot stat '%s'", de->name);
                    f_type = (st.st_mode >> 12);
                    if (n->type == FT_DIR) {
                        if (f_type != FT_DIR) {
                            goto conflict;
                        } else {
                            /* recurse thru directory */
                            goto handle_dir;
                        }
                    } else if (same_file(s, fd, &st, n)) {
                        /* local file already contains the modifications */
                    } else if (same_file(s, fd, &st, n1)) {
                        /* not modified locally: can update */
                        if (same_content(s, fd, &st, n)) {
                            /* same content: only need to change the
                               attributes */
                            setattr_mask = 0;
                            if (st.st_mtime_sec != n->mtime_sec ||
                                st.st_mtime_nsec != n->mtime_nsec)
                                setattr_mask |= P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET;
                            if (n->type != FT_LNK &&
                                (st.st_mode & 0xfff) != n->mode)
                                setattr_mask |= P9_SETATTR_MODE;
                            if (s->preserve_uid_gid &&
                                (st.st_uid != n->uid || st.st_gid != n->gid))
                                setattr_mask |= P9_SETATTR_UID | P9_SETATTR_GID;
                            if (setattr_mask != 0) {
                                if (s->verbose) {
                                    char *fname;
                                    fname = compose_path(path, de->name);
                                    printf("Changing attributes of '%s'\n", fname);
                                    free(fname);
                                }
                                err = fs->fs_setattr(fs, fd, setattr_mask, n->mode,
                                                     n->uid, n->gid,
                                                     0, 0, 0, n->mtime_sec, n->mtime_nsec);
                                if (err < 0)
                                    fatal_error("error setattr '%s'", de->name);
                            }
                        } else {
                            fs->fs_delete(fs, fd);
                            err = fs->fs_unlinkat(fs, dir_fd, de->name);
                            if (err < 0)
                                fatal_error("cannot remove '%s'", de->name);
                            goto add_file;
                        }
                    } else {
                        /* modified locally: conflict */
                        goto conflict;
                    }
                }
            }
        } else if (fd) {
            /* new file with local content */
            err = fs->fs_stat(fs, fd, &st);
            if (err < 0)
                fatal_error("cannot stat '%s'", de->name);
            f_type = (st.st_mode >> 12);
            if (n->type == FT_DIR) {
                if (f_type != FT_DIR) {
                    goto conflict;
                } else {
                    /* recurse thru directory */
                    goto handle_dir;
                }
            } else if (same_file(s, fd, &st, n)) {
                /* nothing to do */
            } else {
            conflict:
                /* conflict */
                conflict_rename(s, fs, dir_fd, de->name, path);
                fs->fs_delete(fs, fd);
                goto add_file;
            }
        } else {
        add_file:
            fd = sync_newfile(s, dir_fd, n, path, de->name);
        handle_dir:
            if (n->type == FT_DIR) {
                char *fname;
                fname = compose_path(path, de->name);
                if (n1 && n1->type != FT_DIR)
                    n1 = NULL;
                filelist_modfile_rec(s, fd, n1, de->inode,
                                     fname);
                free(fname);
            }
            /* set the attributes */
            setattr_mask = P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET;
            if (s->preserve_uid_gid)
                setattr_mask |= P9_SETATTR_UID | P9_SETATTR_GID;
            /* we ignore the mode for symlinks because chmod is not
               able to change it */
            if (n->type != FT_LNK)
                setattr_mask |= P9_SETATTR_MODE;
            err = fs->fs_setattr(fs, fd, setattr_mask, n->mode, n->uid, n->gid,
                                 0, 0, 0, n->mtime_sec, n->mtime_nsec);
            if (err < 0)
                fatal_error("error setattr '%s'", de->name);
        }
        if (fd)
            fs->fs_delete(fs, fd);
    }

    /* handle the removed files in fl_new */
    if (dir_cur) {
        list_for_each(el, &dir_cur->u.dir.de_list) {
            de = list_entry(el, FLDirEntry, link);
            n = de->inode;
            if (!inode_search(dir_new, de->name)) {
                /* file was deleted in new revision : delete locally */
                fd = fs_walk_path(fs, dir_fd, de->name);
                if (fd) {
                    err = fs->fs_stat(fs, fd, &st);
                    if (err < 0)
                        fatal_error("cannot stat '%s'", de->name);
                    if (same_file(s, fd, &st, n)) {
                        err = remove_file_or_dir(fs, dir_fd, de->name,
                                                 path, s->verbose);
                        if (err < 0)
                            fatal_error("cannot remove '%s'\n", de->name);
                    } else {
                        /* conflict */
                        conflict_rename(s, fs, dir_fd, de->name, path);
                    }
                    fs->fs_delete(fs, fd);
                }
            }
        }
    }
}

typedef struct {
    FSSyncState *s;
    FLINode *dir;
    const char *fl_path;
    const char *local_path;
    FSStream *fo;
} FSSyncCommitState;

/*
 rm file_id
 file file_id size (data follows)
*/
static void fs_sync_commit_rec(FSSyncState *s, FSFile *dir_fd,
                               FLINode *dir, const char *fl_path,
                               const char *local_path, FSStream *fo);

static void copy_file(FSDevice *fs, FSStream *fo,
                      FSFile *fd, uint64_t size)
{
    uint64_t pos;
    uint8_t buf[4096];
    int len, ret;

    pos = 0;
    while (size != 0) {
        len = sizeof(buf);
        if (len > size)
            len = size;
        ret = fs->fs_read(fs, fd, pos, buf, len);
        if (ret != len)
            fatal_error("read error");
        ERR(fs_stream_write(fo, buf, len));
        size -= len;
        pos += len;
    }
}

#define ENC_BUF_LEN (256 * AES_BLOCK_SIZE)

/* algorithm: AES-CBC with padding */
static void encrypt_file(FSDevice *fs, FSStream *fo,
                         FSFile *fd, uint64_t size, AES_KEY *aes_state)
{
    uint64_t pos;
    uint8_t buf[ENC_BUF_LEN + AES_BLOCK_SIZE];
    uint8_t buf2[ENC_BUF_LEN + AES_BLOCK_SIZE];
    int len, ret, out_len;
    uint8_t iv[AES_BLOCK_SIZE];

    RAND_bytes(iv, AES_BLOCK_SIZE);
    // RAND_pseudo_bytes(iv, AES_BLOCK_SIZE);

    ERR(fs_stream_write(fo, encrypted_file_magic, 4));
    ERR(fs_stream_write(fo, iv, AES_BLOCK_SIZE));

    pos = 0;
    while (size != 0) {
        len = ENC_BUF_LEN;
        if (len > size)
            len = size;
        ret = fs->fs_read(fs, fd, pos, buf, len);
        if (ret != len)
            fatal_error("read error");
        size -= len;
        pos += len;

        if (size == 0) {
            /* handle the padding */
            out_len = (len + AES_BLOCK_SIZE) & ~(AES_BLOCK_SIZE - 1);
            memset(buf + len, out_len - len, out_len - len);
        } else {
            out_len = len;
        }
        AES_cbc_encrypt(buf, buf2, out_len, aes_state, iv, TRUE);
        ERR(fs_stream_write(fo, buf2, out_len));
    }
}

static void rm_file(FSSyncState *s, FSStream *fo,
                    FLINode *fl_dir, FLDirEntry *de,
                    const char *path, BOOL verbose)
{
    FLINode *n1;
    char *local_fname;

    if (verbose) {
        local_fname = compose_path(path, de->name);
        printf("Removing '%s'\n", local_fname);
        free(local_fname);
    }

    /* remove the existing inode */
    n1 = de->inode;
    inode_dirent_delete(fl_dir, de);
    if (n1->type == FT_REG && n1->u.reg.size > 0) {
        /* remove the inode on server */
        fs_printf(fo, "rm %" PRIx64 "\n", n1->u.reg.file_id);
    }

    if (n1->type == FT_DIR) {
        struct list_head *el, *el1;
        FLDirEntry *de1;
        /* recursive remove in directory */
        local_fname = compose_path(path, de->name);
        list_for_each_safe(el, el1, &n1->u.dir.de_list) {
            de1 = list_entry(el, FLDirEntry, link);
            rm_file(s, fo, n1, de1, local_fname, verbose);
        }
        free(local_fname);
    }
    inode_free(n1);
    s->fl_updated = TRUE;
}

static void add_inode(FSSyncState *s, FSStream *fo, FSFile *fd, uint64_t size,
                      FSFileID *pfile_id)
{
    FSDevice *fs = s->fs;
    FSQID qid;
    uint64_t content_size;
    FSFileID file_id;

    assert(size > 0);

    content_size = size;
    if (content_size != 0 && s->is_encrypted) {
        content_size = 4 + AES_BLOCK_SIZE +
            ((content_size + AES_BLOCK_SIZE) & ~(AES_BLOCK_SIZE - 1));
    }
    file_id = s->next_file_id++;
    fs_printf(fo, "file %" PRIx64 " %" PRIu64 "\n",
              file_id, content_size);
    ERR(fs->fs_open(fs, &qid, fd, P9_O_RDONLY, NULL, NULL));
    if (s->is_encrypted) {
        encrypt_file(fs, fo, fd, size, &s->aes_state_enc);
    } else {
        copy_file(fs, fo, fd, size);
    }
    *pfile_id = file_id;
}

static FLDirEntry *add_file(FSSyncState *s, FSStream *fo,
                            FSFile *fd, FSStat *st, const char *name,
                            FLINode *fl_dir)
{
    FSDevice *fs = s->fs;
    int f_type;
    uint8_t buf[4096];
    FLINode *n1;

    s->fl_updated = TRUE;

    f_type = st->st_mode >> 12;
    n1 = inode_new(f_type, st->st_mode, st->st_uid, st->st_gid);
    n1->mtime_sec = st->st_mtime_sec;
    n1->mtime_nsec = st->st_mtime_nsec;
    switch(f_type) {
    case FT_DIR:
        break;
    case FT_REG:
        if (st->st_size != 0) {
            FSFileID file_id;
            add_inode(s, fo, fd, st->st_size, &file_id);
            n1->u.reg.size = st->st_size;
            n1->u.reg.file_id = file_id;
        }
        break;
    case FT_LNK:
        ERR(fs->fs_readlink(fs, (char *)buf, sizeof(buf), fd));
        n1->u.symlink.name = strdup((char *)buf);
        break;
    case FT_FIFO:
    case FT_SOCK:
        break;
    case FT_BLK:
    case FT_CHR:
        n1->u.dev.major = (st->st_rdev >> 8) & 0xff;
        n1->u.dev.minor = st->st_rdev & 0xff;
        break;
    default:
        fatal_error("unsupported file type=%d\n", f_type);
    }
    return inode_dirent_add(fl_dir, name, n1);
}

static void setattr_file(FSSyncState *s, FLINode *n, FSStat *st)
{
    n->mode = st->st_mode & 0xfff;
    n->uid = st->st_uid;
    n->gid = st->st_gid;
    n->mtime_sec = st->st_mtime_sec;
    n->mtime_nsec = st->st_mtime_nsec;
    s->fl_updated = TRUE;
}

static int fs_sync_commit_rec_file(FSDevice *fs, FSFile *dir_fd,
                                   const char *name, void *opaque)
{
    FSSyncCommitState *state = opaque;
    FSStream *fo = state->fo;
    FSSyncState *s = state->s;
    FLINode *n, *dir = state->dir;
    FSStat st;
    FSFile *fd;
    FLDirEntry *de;
    char *fname, *local_fname;

    if (state->local_path[0] == '\0' && !strcmp(name, SYNCDIR_NAME))
        return 0;

    fd = fs_walk_path(fs, dir_fd, name);
    if (!fd)
        fatal_error("fs_walk_path");
    if (fs->fs_stat(fs, fd, &st) < 0)
        fatal_error("fs_stat");
    de = inode_search(dir, name);
    local_fname = compose_path(state->local_path, name);
    if ((st.st_mode >> 12) == FT_DIR) {
        /* directory */
        if (de) {
            n = de->inode;
            if (n->type != FT_DIR) {
                if (s->verbose) {
                    printf("Modifying '%s'\n", local_fname);
                }
                rm_file(s, fo, dir, de, state->local_path, FALSE);
                de = add_file(s, fo, fd, &st, name, dir);
            } else if (same_file1(s, fd, &st, n, FALSE)) {
                /* nothing to do */
            } else {
                if (s->verbose) {
                    printf("Changing attributes of '%s'\n", local_fname);
                }
                setattr_file(s, n, &st);
            }
        } else {
            if (s->verbose) {
                printf("Adding '%s'\n", local_fname);
            }
            de = add_file(s, fo, fd, &st, name, dir);
        }
        de->mark = 1;
        fname = compose_path(state->fl_path, name);
        fs_sync_commit_rec(s, fd, de->inode, fname, local_fname, fo);
        free(fname);
    } else {
        /* file */
        if (de) {
            n = de->inode;
            if (same_file(s, fd, &st, n)) {
                /* no modification */
            } else {
                if (same_content(s, fd, &st, n)) {
                    if (s->verbose) {
                        printf("Changing attributes of '%s'\n", local_fname);
                    }
                    setattr_file(s, n, &st);
                } else {
                    if (s->verbose) {
                        printf("Modifying '%s'\n", local_fname);
                    }
                    rm_file(s, fo, dir, de, state->local_path, FALSE);
                    de = add_file(s, fo, fd, &st, name, dir);
                }
            }
        } else {
            if (s->verbose) {
                printf("Adding '%s'\n", local_fname);
            }
            de = add_file(s, fo, fd, &st, name, dir);
        }
        de->mark = 1;
    }
    free(local_fname);
    fs->fs_delete(fs, fd);
    return 0;
}

/* 'local_path' is the local path (relative to s->local_, 'fl_path' is the path in the
   repository. */
static void fs_sync_commit_rec(FSSyncState *s, FSFile *dir_fd,
                               FLINode *dir, const char *fl_path,
                               const char *local_path, FSStream *fo)
{
    FSDevice *fs = s->fs;
    FLDirEntry *de;
    struct list_head *el, *el1;
    FSSyncCommitState state;

    if (dir) {
        list_for_each(el, &dir->u.dir.de_list) {
            de = list_entry(el, FLDirEntry, link);
            de->mark = 0;
        }
    }

    state.s = s;
    state.dir = dir;
    state.local_path = local_path; /* local path */
    state.fl_path = fl_path; /* path in the repository */
    state.fo = fo;
    fs_iterate_dir(fs, dir_fd, fs_sync_commit_rec_file, &state);

    if (dir) {
        list_for_each_safe(el, el1, &dir->u.dir.de_list) {
            de = list_entry(el, FLDirEntry, link);
            if (!strcmp(de->name, ".") || !strcmp(de->name, ".."))
                continue;
            if (!de->mark) {
                /* file/dir was removed */
                rm_file(s, fo, dir, de, local_path, s->verbose);
            }
        }
    }
}

static void filelist_write_dir(FLINode *n, FSStream *fo);

static void filelist_write_dirent(FLDirEntry *de, FSStream *fo)
{
    FLINode *n;
    const char *name;
    uint32_t v;
    char *fname;

    n = de->inode;
    name = de->name;
    fs_printf(fo, "%06o %u %u", n->mode | (n->type << 12), n->uid, n->gid);
    switch(n->type) {
    case FT_CHR:
    case FT_BLK:
        fs_printf(fo, " %u %u", n->u.dev.major, n->u.dev.minor);
        break;
    case FT_REG:
        fs_printf(fo, " %" PRIu64, (uint64_t)n->u.reg.size);
        break;
    default:
        break;
    }
    fs_printf(fo, " %u", n->mtime_sec);
    v = n->mtime_nsec;
    if (v != 0) {
        fs_printf(fo, ".");
        while (v != 0) {
            fs_printf(fo, "%u", v / 100000000);
            v = (v % 100000000) * 10;
        }
    }
    fname = quoted_str(name);
    fs_printf(fo, " %s", fname);
    free(fname);
    if (n->type == FT_LNK) {
        fname = quoted_str(n->u.symlink.name);
        fs_printf(fo, " %s", fname);
        free(fname);
    } else if (n->type == FT_REG && n->u.reg.size > 0) {
        fs_printf(fo, " %" PRIx64, n->u.reg.file_id);
    }
    fs_printf(fo, "\n");
    if (n->type == FT_DIR) {
        filelist_write_dir(n, fo);
    }
}

static void filelist_write_dir(FLINode *n, FSStream *fo)
{
    struct list_head *el;
    FLDirEntry *de;

    assert(n->type == FT_DIR);
    list_for_each(el, &n->u.dir.de_list) {
        de = list_entry(el, FLDirEntry, link);
        filelist_write_dirent(de, fo);
    }
    fs_printf(fo, ".\n");
}

static void filelist_write(FSStream *fo, FLINode *root_inode)
{
    fs_printf(fo, "Version: 1\n");
    fs_printf(fo, "\n");
    filelist_write_dir(root_inode, fo);
}

static void filelist_add(FSSyncState *s, FLINode *fl, FSStream *fo)
{
    FSDevice *fs = s->fs;
    FSQID qid;
    FSFile *fd;
    FSStream fp_s, *fp = &fp_s;
    FSFileID file_id;

    fd = fs_dup(fs, s->syncdir_fd);
    if (fs->fs_create(fs, &qid, fd, FILELIST_FILENAME ".new",
                      P9_O_RDWR | P9_O_TRUNC, 0600, 0) < 0) {
        fatal_error("cannot create new_filelist");
    }
    fp->fs = fs;
    fp->fd = fd;
    fp->pos = 0;
    filelist_write(fp, fl);

    add_inode(s, fo, fd, fp->pos, &file_id);

    fs->fs_delete(fs, fd);

    /* remove the previous root */
    if (s->has_root_id) {
        fs_printf(fo, "rm %" PRIx64 "\n", s->root_id);
    }

    /* set the new root */
    fs_printf(fo, "setroot %" PRIx64 "\n", file_id);
    s->has_root_id = TRUE;
    s->root_id = file_id;
}

static void fs_sync_commit_cb(FSSyncState *s);

static void fs_sync_commit(const char *local_dir, int flags)
{
    FSDevice *fs;
    FSSyncState *s;
    FSFile *fo;
    FSStream fp_s, *fp = &fp_s;
    FSQID qid;
    FLINode *fl_cur;
    BOOL dry_run;

    dry_run = ((flags & SYNC_FLAG_DRY_RUN) != 0);
    s = fs_sync_start(local_dir, flags);
    if (!s)
        return;
    fs = s->fs;
    if (s->revision == 0)
        fatal_error("Need to update repository before commiting\n");

    s->new_fs_key = NULL;
    if (!s->key_available) {
        if (s->revision == 1) {
            /* no key: create one */
            printf("Generating encryption key.\n");
            s->new_fs_key = create_fs_key(s->user_password);
            fs_sync_set_fs_key(s, s->new_fs_key);
            s->key_available = TRUE;
        } else {
            fatal_error("encryption key not available: update the repository first");
        }
    }

    if (s->verbose)
        printf("Committing:\n");

    /* load the current file list, if any */
    fl_cur = inode_new(FT_DIR, 0777, 0, 0);
    {
        int size, err;
        uint8_t *buf;
        size = fs_sync_load_file(fs, &buf, s->syncdir_fd, FILELIST_FILENAME, INT_MAX);
        if (size >= 0) {
            err = filelist_load(fl_cur, (char *)buf);
            if (err < 0)
                fatal_error("error while loading new file list");
            free(buf);
        } else {
            if (s->revision != 1)
                fatal_error("commit: no file list");
        }
    }
    s->fl_updated = FALSE;

    fo = fs_dup(fs, s->syncdir_fd);
    if (fs->fs_create(fs, &qid, fo, "commit", P9_O_RDWR | P9_O_TRUNC,
                      0600, 0) < 0)
        fatal_error("cannot create commit file");
    fp->fs = fs;
    fp->fd = fo;
    fp->pos = 0;
    fs_printf(fp, "Version: %u\nRevision: %" PRIu64 "\n\n",
              1, s->revision);

    if (s->new_fs_key) {
        fs_printf(fp, "setkey %s\n", s->new_fs_key);
    }

    fs_sync_commit_rec(s, s->root_fd,
                       inode_search_path(fl_cur, s->root_path),
                       s->root_path + 1, "", fp);
    if (s->fl_updated) {
        /* add new file list in commit */
        filelist_add(s, fl_cur, fp);
    }
    fs->fs_delete(fs, fo);
    inode_free(fl_cur);

    if (dry_run) {
        /* for testing: keep the commit file */
        if (s->verbose)
            printf("Dry run: commit file is saved\n");
        fs_sync_end(s, FS_ERR_OK);
    } else if (!s->fl_updated) {
        /* no change */
        if (s->verbose)
            printf("No local change\n");
        fs->fs_unlinkat(fs, s->syncdir_fd, "commit");
        fs_sync_end(s, FS_ERR_OK);
    } else {
        char *commit_url;
        int ret;
        /* post the commit */
        commit_url = compose_path(s->url, "commit");
        ret = fs_wget_file3(s, SYNCDIR_NAME "/commit_result",
                            commit_url, s->user, s->http_password,
                            SYNCDIR_NAME "/commit", FALSE);
        if (ret < 0) {
            http_error(s, ret, commit_url);
        }
        free(commit_url);

        /* set the agent password only if we got at least one URL correctly */
        if (s->need_agent_set) {
            fs_sync_agent_set_get_password(s, TRUE);
        }

        fs_sync_commit_cb(s);
    }
}

static void fs_sync_commit_cb(FSSyncState *s)
{
    FSDevice *fs = s->fs;
    int result;
    char *buf;
    char buf1[256];

    if (fs_sync_load_file(fs, (uint8_t **)&buf, s->syncdir_fd,
                          "commit_result", INT_MAX) < 0)
        fatal_error("Could not open %s\n", "commit_result");

    if (parse_tag(buf1, sizeof(buf1), buf, "Result") < 0) {
        fprintf(stderr, "invalid commit result format\n");
        result = FS_ERR_SYNTAX;
    } else {
        result = strtol(buf1, NULL, 0);
    }
    if (result != FS_ERR_OK) {
        fprintf(stderr, "Commit error=%d", result);
        if (parse_tag(buf1, sizeof(buf1), buf, "Message") >= 0) {
            fprintf(stderr, " (%s)", buf1);
        }
        fprintf(stderr, "\n");
    }
    free(buf);

    fs->fs_unlinkat(fs, s->syncdir_fd, "commit_result");

    /* remove commit file */
    fs->fs_unlinkat(fs, s->syncdir_fd, "commit");

    if (result == FS_ERR_OK) {
        s->new_revision = s->revision + 1;
        /* use the new file list */
        ERR(fs->fs_renameat(fs, s->syncdir_fd, FILELIST_FILENAME ".new",
                            s->syncdir_fd, FILELIST_FILENAME));

        update_current_revision(s);
    } else {
        fs->fs_unlinkat(fs, s->syncdir_fd, FILELIST_FILENAME ".new");
    }

    fs_sync_end(s, result);
}

/* XXX: factorize */
ssize_t get_pass(char **pbuf)
{
    struct termios old, new;
    char *buf;
    size_t size;
    ssize_t len;

    if (tcgetattr(0, &old) < 0)
        return -1;
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(0, TCSAFLUSH, &new) < 0)
        return -1;

    buf = NULL;
    size = 0;
    len = getline (&buf, &size, stdin);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        len--;
    }
    putchar('\n');
    tcsetattr(0, TCSAFLUSH, &old);
    *pbuf = buf;
    return len;
}

static void checkout(const char *url, const char *dir1, const char *user,
                     const char *pwd, int flags)
{
    FSDevice *fs;
    int err;
    char *dir;

    err = mkdir(dir1, 0755);
    if (err < 0 && errno != EEXIST) {
        perror(dir1);
        exit(1);
    }

    dir = realpath(dir1, NULL);
    fs = fs_disk_init(dir);
    if (!fs) {
        fprintf(stderr, "%s: not a directory\n", dir);
        exit(1);
    }

    fs_sync_init(fs, url, user, pwd, FALSE);
    fs_end(fs);

    fs_sync_update(dir, flags | SYNC_FLAG_CHECKOUT);
    fs_net_event_loop(NULL, NULL);

    free(dir);
}

static char *find_local_dir(void)
{
    char *dir, *p;
    char *path;
    struct stat st;

    dir = get_current_dir_name();
    for(;;) {
        path = compose_path(dir, SYNCDIR_NAME);
        if (stat(path, &st) == 0 &&
            S_ISDIR(st.st_mode)) {
            free(path);
            return dir;
        }
        free(path);
        /* go up one directory if possible */
        p = strrchr(dir, '/');
        if (!p || p == dir) {
            free(dir);
            return NULL;
        }
        *p = '\0';
    }
}

static void info(void)
{
    FSSyncState *s;
    char *local_dir;

    local_dir = find_local_dir();
    if (!local_dir) {
        fprintf(stderr, "Could not find local repository\n");
        exit(1);
    }
    s = fs_sync_start(local_dir, 0);

    printf("Local repository: %s\n", local_dir);
    printf("Local revision: ");
    if (s->revision == 0) {
        printf("N/A\n");
    } else {
        printf("%" PRIu64 "\n", s->revision);
    }
    printf("Remote directory: %s\n", s->root_path);
    printf("Remote repository: %s\n", s->url);
    if (s->user)
        printf("User name: %s\n", s->user);
    fs_sync_end(s, FS_ERR_OK);
    free(local_dir);
}

static void update_or_commit(BOOL update, BOOL commit, int flags)
{
    char *local_dir;

    local_dir = find_local_dir();
    if (!local_dir) {
        fprintf(stderr, "Could not find local repository\n"
                "For help, type vfsync -h\n");
        exit(1);
    }

    if (update) {
        fs_sync_update(local_dir, flags);
        fs_net_event_loop(NULL, NULL);
    }
    if (commit) {
        fs_sync_commit(local_dir, flags);
        fs_net_event_loop(NULL, NULL);
    }

    free(local_dir);
}

static void help(void)
{
    printf("vfsync version " CONFIG_VERSION ", Copyright (c) 2017 Fabrice Bellard\n"
           "usage: vfsync [options] [command] [args]\n"
           "\n"
           "command is:\n"
           "help [command]          show the help for 'command'\n"
           "checkout (co) url dir   checkout files from url to dir\n"
           "sync                    update then commit (default command)\n"
           "update (up)             update local files from server\n"
           "commit (ci)             commit local files to server\n"
           "info                    info about the files\n"
           "\n"
           "Global options:\n"
           "-h           show this help\n"
           "-n           dry run (do not send the commit to the server)\n"
           "-q           quiet mode\n"
           "-g           restore user/group (default for super-user)\n"
           "-p password  set password\n"
           );
    exit(1);
}

static void help_cmd(const char *cmd)
{
    if (!cmd) {
        help();
    } else if (!strcmp(cmd, "checkout") || !strcmp(cmd, "co")) {
        printf("usage: checkout url dir\n"
               "Checkout the remote repository from 'url' to local 'dir'\n"
               "\n"
               "Options:\n"
               "-u user              set user name\n"
               "-saved-password pwd  set password and save it in .vfsync/info.txt\n"
               "                     vfagent should be used instead (safer)\n"
               );
    } else {
        help();
    }
    exit(1);
}

static struct option options[] = {
    { "saved-password", required_argument },
    { NULL },
};

int main(int argc, char **argv)
{
    const char *cmd, *user, *saved_pwd;
    int c, flags, option_index;

    user = NULL;
    saved_pwd = NULL;
    flags = 0;
    if (getuid() == 0)
        flags |= SYNC_FLAG_PRESERVE_UID_GID;

    for(;;) {
        c = getopt_long_only(argc, argv, "hu:nqgp:", options, &option_index);
        if (c == -1)
            break;
        switch(c) {
        case 0:
            switch(option_index) {
            case 0: /* saved-password */
                saved_pwd = optarg;
                break;
            default:
                fprintf(stderr, "unknown option index: %d\n", option_index);
                exit(1);
            }
            break;
        case 'h':
            help();
        case 'u':
            user = optarg;
            break;
        case 'p':
            cmdline_pwd = optarg;
            break;
        case 'n':
            flags |= SYNC_FLAG_DRY_RUN;
            break;
        case 'q':
            flags |= SYNC_FLAG_QUIET;
            break;
        case 'g':
            flags |= SYNC_FLAG_PRESERVE_UID_GID;
            break;
        default:
            exit(1);
        }
    }

    fs_wget_init();

    if (optind >= argc)
        goto do_sync;

    cmd = argv[optind++];
    if (!strcmp(cmd, "help")) {
        help_cmd(argv[optind]);
    } else if (!strcmp(cmd, "checkout") || !strcmp(cmd, "co")) {
        const char *url, *dir;
        if (optind + 1 >= argc)
            help();
        url = argv[optind++];
        dir = argv[optind++];
        checkout(url, dir, user, saved_pwd, flags);
    } else if (!strcmp(cmd, "info")) {
        info();
    } else if (!strcmp(cmd, "update") || !strcmp(cmd, "up")) {
        update_or_commit(TRUE, FALSE, flags);
    } else if (!strcmp(cmd, "commit") || !strcmp(cmd, "ci")) {
        update_or_commit(FALSE, TRUE, flags);
    } else if (!strcmp(cmd, "sync")) {
    do_sync:
        update_or_commit(TRUE, TRUE, flags);
    } else {
        fprintf(stderr, "Invalid command: '%s'\n"
                "Type 'fssync help' for help\n", cmd);
        exit(1);
    }

    fs_wget_end();

    return 0;
}
