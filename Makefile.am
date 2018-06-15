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
	if type systemctl >/dev/null 2>&1; then \
		cp $(top_builddir)/contrib/scripts/vma.init $(DESTDIR)$(sbindir)/vma; \
		chmod 755 $(DESTDIR)$(sbindir)/vma; \
		mkdir -p $(DESTDIR)$(prefix)/lib/systemd/system/; \
		cp $(top_builddir)/contrib/scripts/vma.service $(DESTDIR)$(prefix)/lib/systemd/system/vma.service; \
		chmod 644 $(DESTDIR)$(prefix)/lib/systemd/system/vma.service; \
	else \
		mkdir -p $(DESTDIR)/$(sysconfdir)/init.d; \
		cp $(top_builddir)/contrib/scripts/vma.init $(DESTDIR)$(sysconfdir)/init.d/vma; \
		chmod 755 $(DESTDIR)$(sysconfdir)/init.d/vma; \
	fi

uninstall-hook:
	if type systemctl >/dev/null 2>&1; then \
		rm -rf $(DESTDIR)$(sbindir)/vma; \
		rm -rf $(DESTDIR)$(prefix)/lib/systemd/system/vma.service; \
	else \
		rm -rf $(DESTDIR)$(sysconfdir)/init.d/vma; \
	fi

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
