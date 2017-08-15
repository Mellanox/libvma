
The sample requires some small modifications to support the netmap_vma API.

* #include "netmap_vma.h"
  The header contains the new functions that implement the netmap_vma API.

* The ioctl(NETMAP_FD(d), NIOCRXSYNC, NULL) is not needed for the netmap_vma API

* poll input/output multiplexing
  - netmap API
        int poll(struct pollfd *fds, nfds_t nfds, int timeout);
        poll(&pfd, nfds, -1);

  - netmap_vma API
        poll_nm_vma(struct nm_desc *d, int timeout);
        The poll_nm_vma API simulates the events POLLIN|POLLERR only
        poll_nm_vma(d, -1);

* Packet processing
  - neatmp API
        cur = rxring->cur;
        while (!nm_ring_empty(rxring)) {
            *slot = &rxring->slot[cur];
            *src = (uint8_t*)NETMAP_BUF(rxring, slot->buf_idx);
            // process packet
            handle(src, slot->len);
            //next packet
            cur = nm_ring_next(rxring, cur);
        }
        // update ring buffer
        rxring->head = rxring->cur = nm_ring_next(rxring, cur);

  - netmap_vma API
        while ((buf = (uint8_t*)nm_nextpkt(d, &h))) {
            // process the packet
            handle(h.buf, h.len);
        }
        The h.buf returned to the user consists of all packets in one big buffer
        The h.len returns the number of packets in the buffer

Rgarding the Multi Packet Receive Queue (MP-RQ) and the Cyclic Buffer (CB)
please refer to the User Manual
"Mellanox Messaging Accelerator (VMA) Library for Linux" 8.7 Multi Packet Receive Queue
http://www.mellanox.com/vma

**Build and Run Instructions**

Install the netmap framework https://github.com/luigirizzo/netmap
Install the biTStream https://code.videolan.org/videolan/bitstream.git
To build the application:
make NETMAP_SRC_DIR=/path_to_the_netmap_sources \
	BITSTREAM_DIR=/path_to_the_folder_where_bitstream_is_located

The script run_util.sh requires some small modifications as well.
Please update the interface and the path PRELOAD if needed.
Start sample with netmap_vma API $./run-util.sh -rvma
The pkt-gen can be used to generate a traffic.

