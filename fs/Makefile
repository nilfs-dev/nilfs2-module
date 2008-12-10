#
# Makefile - Makefile for NILFS kernel module
#
# Copyright (C) 2005-2008 Nippon Telegraph and Telephone Corporation.
#

ifndef CONFIG_NILFS
  EXTERNAL_BUILD=y
  CONFIG_NILFS=m
  # Uncomment below to do debug build.
  #CONFIG_NILFS_DEBUG=y
  # Uncomment below to enable bmap validity check.
  #CONFIG_NILFS_BMAP_DEBUG=y
endif

# Some assembler options.
ifneq ($(CONFIG_NILFS_DEBUG),)
  EXTRA_CFLAGS += -g -fno-omit-frame-pointer
endif

list-$(CONFIG_NILFS) += nilfs2

obj-$(CONFIG_NILFS) += nilfs2.o

nilfs2-objs := inode.o file.o dir.o super.o namei.o page.o mdt.o \
	btnode.o bmap.o btree.o direct.o dat.o \
	recovery.o the_nilfs.o segbuf.o segment.o cpfile.o sufile.o \
	ifile.o alloc.o gcinode.o ioctl.o gcdat.o

ifneq ($(CONFIG_NILFS_DEBUG),)
	nilfs2-objs += debug.o
endif

#
# We support only external build, and does not support kernel build.
# 
ifneq ($(KERNELRELEASE),)

ifeq ($(EXTERNAL_BUILD),y)
  EXTRA_CFLAGS += -U CONFIG_NILFS_XATTR       # not supported yet
  EXTRA_CFLAGS += -U CONFIG_NILFS_POSIX_ACL   # not supported yet

  ifneq ($(CONFIG_NILFS_DEBUG),)
    EXTRA_CFLAGS += -D CONFIG_NILFS_DEBUG
  endif
  ifneq ($(CONFIG_NILFS_BMAP_DEBUG),)
    EXTRA_CFLAGS += -D CONFIG_NILFS_BMAP_DEBUG	# bmap validity check
  endif

  # Internal switches
  EXTRA_CFLAGS += -D NILFS_ATIME_DISABLE
endif

else

#
# Description for external build begins here
#

KVER := $(shell uname -r)
KSRC := /lib/modules/$(KVER)/build
MDIR := /lib/modules/$(KVER)/kernel/fs/nilfs2/
PWD := $(shell pwd)

CFLAGS += -Wall

default:
	$(MAKE) -C $(KSRC) SUBDIRS=$(PWD) BUILD_DIR=$(PWD) modules

install: unload
	install -d $(MDIR)
	install -m 644 -c $(addsuffix .ko,$(list-m)) $(MDIR)
	/sbin/depmod $(KVER) -A

uninstall: unload
	rm -rf $(addprefix $(MDIR),$(addsuffix .ko,$(list-m)))
	/sbin/depmod $(KVER) -A

load:
	modprobe $(list-m)

unload:
	@test "`uname -r`" != "$(KVER)" || \
	     if [ -n "`mount -t $(list-m)`" ]; then \
	         echo "Unmount $(list-m) first."; false; \
	     elif (/sbin/lsmod | grep -e ^$(list-m)' ') > /dev/null; then /sbin/rmmod $(list-m); \
	     	 if [ $$? != 0 ]; then echo "failed to unload $(list-m)"; false; \
	         else echo "unloaded $(list-m)"; fi \
	     fi \

clean:
	rm -f *.mod.c *.mod *.o *.ko .*.cmd .*.flags *.lst *~ .#*
	rm -f modules.order Module.symvers
	rm -rf .tmp_versions .$(obj-m:.o=)*

endif

TAGS:
	etags *.h *.c

.PHONY: TAGS
