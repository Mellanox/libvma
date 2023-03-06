SUBDIRS := src tools docs/man


DIST_SUBDIRS := src tests tools docs/man

noinst_SCRIPTS = \
	$(wildcard contrib/scripts/*)

EXTRA_DIST = \
	contrib \
	debian \
	LICENSE \
	CHANGES \
	README


.PHONY: tests

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README CHANGES

install-exec-hook:
	if command -v systemctl >/dev/null 2>&1; then \
		mkdir -p $(DESTDIR)$(prefix)/lib/systemd/system/; \
		cp $(top_builddir)/contrib/scripts/vma.service $(DESTDIR)$(prefix)/lib/systemd/system/vma.service; \
		chmod 644 $(DESTDIR)$(prefix)/lib/systemd/system/vma.service; \
	fi

uninstall-hook:
	if command -v systemctl >/dev/null 2>&1; then \
		rm -rf $(DESTDIR)$(prefix)/lib/systemd/system/vma.service; \
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

