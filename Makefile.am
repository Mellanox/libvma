SUBDIRS := src tools


DIST_SUBDIRS := src tests tools

noinst_SCRIPTS = \
	$(wildcard contrib/scripts/*)

EXTRA_DIST = \
	build \
	contrib \
	debian \
	install.sh \
	journal.txt \
	README.txt \
	VMA_VERSION


.PHONY: tests

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README.txt journal.txt VMA_VERSION

install-exec-hook:
	mkdir -p $(DESTDIR)/$(sysconfdir)/init.d
	cp $(top_builddir)/contrib/scripts/vma.init $(DESTDIR)$(sysconfdir)/init.d/vma
	chmod 755 $(DESTDIR)$(sysconfdir)/init.d/vma
	if type systemctl >/dev/null 2>&1; then \
		$(top_srcdir)/config/install-sh -m 755 -d $(DESTDIR)$(sysconfdir)/systemd/system/; \
		cp $(top_builddir)/contrib/scripts/vma.service $(DESTDIR)$(sysconfdir)/systemd/system/vma.service; \
		chmod 644 $(DESTDIR)$(sysconfdir)/systemd/system/vma.service; \
	fi

uninstall-hook:
	rm -rf $(DESTDIR)$(sysconfdir)/init.d/vma
	rm -rf $(DESTDIR)$(sysconfdir)/systemd/system/vma.service

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
