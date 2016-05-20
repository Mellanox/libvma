SUBDIRS := src


DIST_SUBDIRS := src tests
EXTRA_DIST = \
	build \
	debian \
	BUILD \
	coverity_vma_config.xml \
	install.sh \
	journal.txt \
	LOC_exclude_VMA.txt \
	LOC.sh \
	README.txt \
	VMA_VERSION \
	config/m4/pkg.m4


.PHONY: tests

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README.txt journal.txt VMA_VERSION

install-all: install

uninstall-all: uninstall

tests:
	$(MAKE)
	$(MAKE) -C tests/latency_test
	$(MAKE) -C tests/throughput_test
	$(MAKE) -C tests/pps_test

demo:
	$(MAKE)
	$(MAKE) -C src/vma/infra

rpmspec: build/libvma.spec

debian: debian/changelog

cov:
	PATH=/hpc/local/commercial/coverity/cov-sa/bin:$$PATH && rm -rf $(PWD)/cov-build && make clean && cov-build --dir $(PWD)/cov-build --config coverity_vma_config.xml make all && cov-analyze --dir $(PWD)/cov-build && cov-format-errors --dir $(PWD)/cov-build 
