SUBDIRS := src tools


DIST_SUBDIRS := src tests tools

noinst_SCRIPTS = \
	$(wildcard contrib/scripts/*)

EXTRA_DIST = \
	build \
	contrib \
	debian \
	BUILD.txt \
	install.sh \
	journal.txt \
	LOC_exclude_VMA.txt \
	LOC.sh \
	README.txt \
	VMA_VERSION


.PHONY: tests

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README.txt journal.txt VMA_VERSION

install-exec-hook:
	$(top_srcdir)/config/install-sh -m 755 -d $(DESTDIR)/$(sysconfdir)/init.d
	cp $(top_builddir)/contrib/scripts/vma.init $(DESTDIR)/$(sysconfdir)/init.d/vma
	chmod 755 $(DESTDIR)/$(sysconfdir)/init.d/vma

uninstall-hook:
	rm -rf $(DESTDIR)/$(sysconfdir)/init.d

install-all: install

uninstall-all: uninstall

tests:
	$(MAKE)
	$(MAKE) -C tests/gtest
	$(MAKE) -C tests/latency_test
	$(MAKE) -C tests/throughput_test
	$(MAKE) -C tests/pps_test

demo:
	$(MAKE)
	$(MAKE) -C src/vma/infra

rpmspec: build/libvma.spec

debian: debian/changelog
