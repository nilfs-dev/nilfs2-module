#
# Makefile - for NILFS (top)
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
