vma_man_pages = \
	vma.7 \
	vma_get_api.3 \
	vma_add_conf_rule.3 \
	vma_dump_fd_stats.3 \
	vma_thread_offload.3 \
	vma_register_recv_callback.3 \
	vma_recvfrom_zcopy.3 \
	vma_free_packets.3

man_MANS = $(vma_man_pages)
CLEANFILES = $(vma_man_pages)
EXTRA_DIST = \
	$(vma_man_pages:.7=.7.in) \
	$(vma_man_pages:.3=.3.in)

%.3: %.3.in
	@cp $< $@
	@perl -i -pe 's/#BUILD_DATE#/@BUILD_DATE@/g; s/#BUILD_VERSION#/@BUILD_VERSION@/g' $@

%.7: %.7.in
	@cp $< $@
	@perl -i -pe 's/#BUILD_DATE#/@BUILD_DATE@/g; s/#BUILD_VERSION#/@BUILD_VERSION@/g' $@
