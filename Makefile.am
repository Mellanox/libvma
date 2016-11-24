SUBDIRS := src tools


DIST_SUBDIRS := src tests tools
EXTRA_DIST = \
	build \
	contrib \
	debian \
	BUILD \
	install.sh \
	journal.txt \
	LOC_exclude_VMA.txt \
	LOC.sh \
	README.txt \
	VMA_VERSION


.PHONY: tests

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README.txt journal.txt VMA_VERSION

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
