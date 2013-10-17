SUBDIRS := src 

.PHONY: sockperf tests

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README.txt journal.txt

sockperf :
	$(MAKE)
	$(MAKE) -C tests sockperf

install-sockperf:
	$(MAKE) -C tests sockperf-install
	
install-all: install sockperf-install

uninstall-sockperf:
	$(MAKE) -C tests sockperf-uninstall

uninstall-all: uninstall uninstall-sockperf

tests:
	$(MAKE)
	$(MAKE) -C tests/latency_test
	$(MAKE) -C tests/throughput_test
	$(MAKE) -C tests/pps_test

demo:
	$(MAKE)
	$(MAKE) -C src/vma/infra

cov:
	PATH=/hpc/local/commercial/coverity/cov-sa/bin:$$PATH && rm -rf $(PWD)/cov-build && make clean && cov-build --dir $(PWD)/cov-build --config coverity_vma_config.xml make all && cov-analyze --dir $(PWD)/cov-build && cov-format-errors --dir $(PWD)/cov-build 
