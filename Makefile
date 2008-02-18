#
# Makefile - for NILFS (top)
#
# Makefile,v 1.6 2007-06-13 05:54:51 amagai Exp
#
# Written by Seiji Kihara <kihara@osrg.net>
#

SUBDIRS = fs

.PHONY: subdirs $(SUBDIRS)

subdirs: $(SUBDIRS)

clean: RULE = clean
install: RULE = install
uninstall: RULE = uninstall

all clean install uninstall: $(SUBDIRS)

$(SUBDIRS):
	  $(MAKE) -C $@ $(RULE)
