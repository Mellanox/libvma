SUBDIRS := latency_test pps_test throughput_test

SOCKPERF_VERSION := 2.5.244

sockperf: 
	@(tar xfz sockperf-$(SOCKPERF_VERSION).tar.gz && mv sockperf-$(SOCKPERF_VERSION) sockperf && cd sockperf && ./configure --prefix $(prefix) $(SOCKPERF_FLAG) && make)

sockperf-install:
	$(MAKE) -C sockperf install

sockperf-uninstall:
	$(MAKE) -C sockperf uninstall

clean-local:
	    @(rm -rf sockperf)
