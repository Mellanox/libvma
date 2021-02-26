SUBDIRS := src tools doc/man


DIST_SUBDIRS := src tests tools doc/man

noinst_SCRIPTS = \
	$(wildcard contrib/scripts/*)

EXTRA_DIST = \
	contrib \
	debian \
	journal.txt \
	README.txt


.PHONY: tests

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README.txt journal.txt

install-exec-hook:
	if type systemctl >/dev/null 2>&1; then \
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

