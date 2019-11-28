/*
 * Filesystem synchronization agent
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
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "cutils.h"
#include "fs_utils.h"
#include "list.h"

//#define DEBUG

typedef struct {
    struct list_head link;
    char *url;
    char *user;
    char *password1;
    char *password2;
    char *password3;
} FSUserEntry;

struct list_head user_list; /* FSUserEntry.link */

static FSUserEntry *find_user(const char *url, const char *user)
{
    struct list_head *el;
    FSUserEntry *fu;
    list_for_each(el, &user_list) {
        fu = list_entry(el, FSUserEntry, link);
        if (!strcmp(fu->url, url) && !strcmp(fu->user, user)) {
            return fu;
        }
    }
    return NULL;
}

static void handle_client(int fd)
{
    char buf[4096], cmd[16], url[1024];
    char user[256], password1[256], password2[256], password3[256];
    int len, err;
    const char *p;
    FSUserEntry *fu;

    len = read(fd, buf, sizeof(buf) - 1);
    if (len <= 0)
        return;
    buf[len] = '\0';
#ifdef DEBUG
    printf("got cmd='%s'\n", buf);
#endif
    p = buf;
    if (parse_fname(cmd, sizeof(cmd), &p) < 0)
        return;
    if (!strcmp(cmd, "set")) {
        if (parse_fname(url, sizeof(url), &p) < 0)
            return;
        if (parse_fname(user, sizeof(user), &p) < 0)
            return;
        if (parse_fname(password1, sizeof(password1), &p) < 0)
            return;
        if (parse_fname(password2, sizeof(password2), &p) < 0)
            return;
        if (parse_fname(password3, sizeof(password3), &p) < 0)
            return;
#ifdef DEBUG
        printf("set %s %s %s %s %s %s\n",
               url, user, password1, password2, password3);
#endif
        fu = find_user(url, user);
        if (!fu) {
            fu = mallocz(sizeof(*fu));
            fu->url = strdup(url);
            fu->user = strdup(user);
            list_add_tail(&fu->link, &user_list);
        } else {
            free(fu->password1);
            free(fu->password2);
            free(fu->password3);
        }
        fu->password1 = strdup(password1);
        fu->password2 = strdup(password2);
        fu->password3 = strdup(password3);
        snprintf(buf, sizeof(buf), "ok");
    } else if (!strcmp(cmd, "get")) {
        char *s1, *s2, *s3;
        if (parse_fname(url, sizeof(url), &p) < 0)
            return;
        if (parse_fname(user, sizeof(user), &p) < 0)
            return;
        fu = find_user(url, user);
        if (fu) {
            s1 = quoted_str(fu->password1);
            s2 = quoted_str(fu->password2);
            s3 = quoted_str(fu->password3);
            snprintf(buf, sizeof(buf), "ok %s %s %s", s1, s2, s3);
            free(s1);
            free(s2);
            free(s3);
        } else {
            snprintf(buf, sizeof(buf), "error");
        }
    } else {
        snprintf(buf, sizeof(buf), "error");
    }
#ifdef DEBUG
    printf("reply: '%s'\n", buf);
#endif
    err = write(fd, buf, strlen(buf));
    if (err < 0) {
       perror("write");
       exit(1);
    }
}


static void server(const char *sock_path)
{
    struct sockaddr_un addr;
    int fd, fd1;

    init_list_head(&user_list);

    addr.sun_family = AF_UNIX;
    pstrcpy(addr.sun_path, sizeof(addr.sun_path), sock_path);
    unlink(sock_path);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    if (bind(fd, &addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (chmod(sock_path, 0600) < 0) {
        perror("chmod");
        exit(1);
    }

    if (listen(fd, 5) < 0) {
        perror("listen");
        exit(1);
    }
    for(;;) {
        fd1 = accept(fd, NULL, NULL);
        if (fd1 < 0)
            continue;
        handle_client(fd1);
        close(fd1);
    }
}

static void help(void)
{
    printf("vfagent version " CONFIG_VERSION ", Copyright (c) 2017 Fabrice Bellard\n"
           "usage: vfagent [-h] [-n] [-p]\n"
           "\n"
           "Options:\n"
           "-h        show this help\n"
           "-n        do not daemonize\n"
           "-p        only print the socket path instead of shell export command\n"
           );
    exit(1);
}


int main(int argc, char **argv)
{
    int c, pid, err;
    BOOL daemon_flag, path_only;
    char sock_path[1024];

    daemon_flag = TRUE;
    path_only = FALSE;
    for(;;) {
        c = getopt(argc, argv, "hnp");
        if (c == -1)
            break;
        switch(c) {
        case 'h':
            help();
        case 'n':
            daemon_flag = FALSE;
            break;
        case 'p':
            path_only = TRUE;
            break;
        default:
            exit(1);
        }
    }

    snprintf(sock_path, sizeof(sock_path), "/var/tmp/.vfsync_%d", getpid());

    if (daemon_flag) {
        /* daemonize */
        pid = fork();
        if (pid == 0) {
            setsid();
            pid = fork();
            if (pid == 0) {
                err = chdir("/");
                close(0);
                close(1);
                close(2);
                open("/dev/null", O_RDWR);
                dup2(0, 1);
                dup2(0, 2);
                server(sock_path);
                if (err < 0) {
                   perror("chdir");
                }
                exit(1);
            } else {
                exit(0);
            }
        }
    }

    if (path_only)
        printf("%s", sock_path);
    else
        printf("export VFSYNC_SOCK=%s\n", sock_path);

    if (!daemon_flag)
        server(sock_path);
    return 0;
}
