
NETMAP_SRC_DIR = /path_to_the_netmap_sources
BITSTREAM_DIR = /path_to_the_folder_where_bitstream_is_located

VMA_TOP_DIR = ../../../..
NETMAP_VMA_SRC_DIR = ..

PROGS = nm-ex1-vma nm-ex1

CFLAGS = -O2 -Wall -Wextra -g
CFLAGS += -I$(NETMAP_SRC_DIR)/sys/net -I$(NETMAP_SRC_DIR)/apps/include -I$(NETMAP_VMA_SRC_DIR)
CFLAGS += -I$(BITSTREAM_DIR)

LDLIBS += -lrt
LDLIBS_VMA += $(NETMAP_VMA_SRC_DIR)/netmap_vma.so
LDLIBS_VMA += -L $(VMA_TOP_DIR)/src/vma/.libs -lvma

all: $(PROGS)

nm-ex1-vma: LDLIBS += $(LDLIBS_VMA)
nm-ex1-vma.o: nm-ex1.c
	$(CC) $(CFLAGS) -DNETMAP_VMA -c $^ -o $@

nm-ex1.o: nm-ex1.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f nm-ex1 nm-ex1.o nm-ex1-vma nm-ex1-vma.o
