vma_man_pages = \
	vma.7 \
	vmad.8 \
	vma_stats.8

man_MANS = $(vma_man_pages)
CLEANFILES = $(vma_man_pages)
EXTRA_DIST = \
	$(vma_man_pages:.7=.7.in) \
	$(vma_man_pages:.8=.8.in)

%.7: %.7.in
	@cp $< $@
	@sed -i 's/#BUILD_DATE#/@BUILD_DATE@/g' $@
	@sed -i 's/#VMA_LIBRARY_MAJOR#/@VMA_LIBRARY_MAJOR@/g' $@
	@sed -i 's/#VMA_LIBRARY_MINOR#/@VMA_LIBRARY_MINOR@/g' $@
	@sed -i 's/#VMA_LIBRARY_REVISION#/@VMA_LIBRARY_REVISION@/g' $@

%.8: %.8.in
	@cp $< $@
	@sed -i 's/#BUILD_DATE#/@BUILD_DATE@/g' $@
	@sed -i 's/#VMA_LIBRARY_MAJOR#/@VMA_LIBRARY_MAJOR@/g' $@
	@sed -i 's/#VMA_LIBRARY_MINOR#/@VMA_LIBRARY_MINOR@/g' $@
	@sed -i 's/#VMA_LIBRARY_REVISION#/@VMA_LIBRARY_REVISION@/g' $@
