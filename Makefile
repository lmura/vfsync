#
# VFsync client
# 
# Copyright (c) 2017 Fabrice Bellard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

# If set, the network access are done by the underlying filesystem
# which must be the 9p virtio filesystem from riscvemu.
#CONFIG_FS_CMD=y

CC=gcc
CFLAGS=-O2 -Wall -g -Werror -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -MMD
CFLAGS+=-D_GNU_SOURCE -DCONFIG_VERSION=\"$(shell cat VERSION)\"
LDFLAGS=

VFSYNC_LIBS=-lcrypto
ifdef CONFIG_FS_CMD
CFLAGS+=-DCONFIG_FS_CMD
else
VFSYNC_LIBS+=-lcurl
endif

PROGS= vfsync vfagent

INSTALL_BINDIR=/usr/local/bin
INSTALL=install

all: $(PROGS)

vfsync: vfsync.o fs_wget.o fs.o fs_disk.o fs_utils.o cutils.o
	$(CC) $(LDFLAGS) -o $@ $^ $(VFSYNC_LIBS) -lm

vfagent: vfagent.o fs_utils.o cutils.o
	$(CC) $(LDFLAGS) -o $@ $^ -lm

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(PROGS)
	$(INSTALL) -s -m755 $(PROGS) "$(INSTALL_BINDIR)"

clean:
	rm -f *.o *.d *~ $(PROGS)

-include $(wildcard *.d)
