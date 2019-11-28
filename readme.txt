VFsync file synchronization client
==================================

1) Introduction
---------------

VFsync is a simple server-based file synchronization system.

WARNING: it is still in alpha stage, so data loss is likely.

Features:

- Secure: client based encryption using 128 bit AES. The encryption
  key is not stored on the server. Transmission using the HTTPS protocol.

- Simple key management (single password for authentication and encryption).

- Synchronization between multiple clients with conflict
  detection. Transaction based commit.

- Command line interface similar to Subversion.

- Works on Linux systems. No installation is necessary.

- Open source license (MIT license)

2) Installation
---------------

- Currently the client was only tested on Linux.

- The libraries libcurl and OpenSSL must be installed. On a Fedora
  system you can do it with:

  sudo yum install openssl-devel libcurl-devel

- Use 'make' to compile the programs.

- You can optionally install the programs to '/usr/local/bin' with:

  make install

3) Usage
--------

3.1) Quick example
------------------

Assume your account user1 is created on vfsync.org.

- launch the 'vfagent' daemon in order to avoid typing your password
  every time. Its usage is similar to ssh-agent:

  eval `vfagent`

- If not done before, check out your files from the server:

  vfsync -u user1 co https://vfsync.org/u/user1/home my_home

  The files are written to the 'my_home' directory. The hidden
  directory '.vfsync' contains the information necessary to connect to
  the repository when launching again the vfsync command.

- If you want to commit the local modifications to the server or get
  changes from other clients, just type somewhere in the 'my_home'
  directory:

  vfsync

- If there are conflicts (file modified both locally and on the
  server), the local file is renamed with the '.n' suffix (where n is
  a number) and the new file from the server replaces the local file.

3.2) Comparison with Subversion
-------------------------------

The concepts are very similar to Subversion or other source management
systems. However, there are important differences:

- By default, vfsync does an update (update from server), then a
  commit (commit changes to the server). You can do them separately if
  needed.

- All the data and metadata (excluding the approximate file size) are
  encrypted on the server. The encryption key is only known to the
  client.

- When a file is locally removed, it is removed on the server without
  an explicit 'remove' command.

- Currently only the "head" revision (=last revision) is kept on the
  server. So when a modification is made it is not possible to undo
  it.

- No automatic merge is done when there is a conflict. The conflicting
  file is renamed with a '.n' suffix (where n is a number).

4) Technical notes
------------------

4.1) File system storage
------------------------

All the file system metadata (directory layout, filenames,
permissions, file owner, ...) are stored in a single text file (the
"file list"). The server maintains a list of inodes (=binary blobs)
having a 64 bit unique identifier. The file list and the data files
are stored as inodes on the server.

The filesystem state is described by the "head" server file which
gives the ID of the inode file list ("root inode") and the current
revision number.

A client commit atomically adds or removes inodes, increments the
current revision number and change the ID of the root inode.

4.2) Security
-------------

When a repository is encrypted, the file data is encrypted with the
128 bit AES CBC algorithm. A random 128 bit initial vector (IV) is
used for each file.

The encryption key is encrypted with the user password. The encryption
uses PBKDF2 HMAC SHA-256 with 4096 iterations and a 256 bit salt. The
resulting encrypted key is stored on the server for convenience.

The file metadata (aka "file list") is stored like a normal encrypted
file. So the server only knows the approximate file sizes (because the
files are padded to 16 byte AES blocks).

The communication with the server is done thru HTTPS. The user account
accesses are authenticated with the basic HTTP authentication
algorithm. The HTTP password is generated from the user password with
PBKDF2 HMAC SHA-256 with 4096 iterations and a salt based on the user
name.

Known weaknesses:

- The HTTP password generation from the user password does not use a
  random salt (but it is still salted with the user name). It is a
  compromise to allow to compute the encryption key from the user
  login while not using the real password for HTTP authentication.

- No data authentication is done yet.

- In the current release the user cannot specify its own encryption
  key in case it does not want to store the encrypted key on the
  server.

- The server knows the approximate file sizes. It could be possible to
  modify the client to hide the information without changing the
  protocol.
