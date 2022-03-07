SUBDIRS = $(shell ls -d binaries/*)

binaries:
	for dir in $(SUBDIRS); do \
		make -C $$dir all; \
	done
.PHONY: binaries