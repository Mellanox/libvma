Update: 25 Jan 2018

Introduction
============

Mellanox's Messaging Accelerator (VMA) is dynamically linked user space Linux
library for transparently enhancing the performance of networking-heavy
applications. It boosts performance for message-based and streaming applications
such as those found in financial services market data environments and Web2.0
clusters.
It allows application written over standard socket API to run over Infiniband
and/or Ethernet from user-space with full network stack bypass.
The result is a reduction in latency by as much as 300%,
an increase in application throughput by as much as 200%,
higher packets rates and better CPU utilization as compared to applications
running on standard Ethernet or InfiniBand interconnect networks.

Build libvma from source
========================

Prerequisites:
1. MLNX_OFED as described in the "Pre Installation" step of next section.
2. Or, upstream kernel and userspace verbs libraries (libibverbs, libmlx4, librdmacm)
3. Autoconf, Automake, libtool, unzip, patch, libnl-devel (netlink 1 or 3)

Build:
1. ./autogen.sh
2. ./configure --with-ofed=/usr --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include --docdir=/usr/share/doc/libvma --sysconfdir=/etc
3. make

You will find libvma.so in path_to_vma_dir/src/vma/.libs/libvma.so.

Install:
1. sudo make install

Tip:
./install.sh can do the build and install steps for you.


Install libvma from rpm or debian
=================================

Pre Installation:
1. If possible, install latest MLNX_OFED with the --vma option.
   This will also install libvma, and you can skip to "Running" step.
2. If installing over existing MLNX_OFED, add the following to
   /etc/modprobe.d/mlnx.conf:
   options ib_uverbs disable_raw_qp_enforcement=1
   options mlx4_core fast_drop=1
   options mlx4_core log_num_mgm_entry_size=-1
   And restart the driver: /etc/init.d/openibd restart

Installing:
Install the package as any other rpm or debian package [rpm -i libvma.X.Y.Z-R.rpm].
The installation copies the VMA library to: /usr/lib[64]/libvma.so
The VMA monitoring utility is installed at: /usr/bin/vma_stat
The VMA extra socket API is located at: /usr/include/mellanox/vma_extra.h
The installation location of the README.txt and version information file
(VMA_VERSION), are as follows:
- Redhat: /usr/share/doc/libvma-X.Y.Z-R/
- SuSE:   /usr/share/doc/packages/libvma-X.Y.Z-R/

Post Installation:
When working over Infiniband, we recommend to manually add persistence
for the following system parameters:
1. Force IPoIB to work in 'datagram' mode (disabling IPoIB 'connected' mode)
   Modify "SET_IPOIB_CM=no" in file "/etc/infiniband/openib.conf"
2. Force IGMP to work in V2 on IB interfaces
   Add "net.ipv4.conf.all.force_igmp_version = 2" in file "/etc/sysctl.conf"

Upgrading:
Use rpm update procedure: # rpm -U libvma.X.Y.Z-R.rpm
You can upgrade by uninstalling (rpm -e) the previously installed package
before starting to install the new VMA rpm.

Uninstalling:
When uninstalling remember to uninstall (rpm -e) the package before you
uninstall ofed.

Running:
Set the environment variable LD_PRELOAD to libvma.so and run your application.
Example: # LD_PRELOAD=libvma.so iperf -uc 224.22.22.22 -t 5



Configuration Values
====================

On default startup the VMA library logs to stderr the VMA version, the modified
configuration parameters being used and their values.
Please notice that except VMA_TRACELEVEL, VMA logs just those parameters whose value != default.

Example:
 VMA INFO: ---------------------------------------------------------------------------
 VMA INFO: VMA_VERSION: 8.4.3-0 Development Snapshot built on Sep  3 2017 11:58:07
 VMA INFO: Cmd Line: sockperf sr -i 4.4.4.3
 VMA INFO: Current Time: Sun Sep  3 12:03:14 2017
 VMA INFO: Pid: 29881
 VMA INFO: OFED Version: MLNX_OFED_LINUX-4.1-2.0.0.0:
 VMA INFO: Architecture: x86_64
 VMA INFO: Node: r-aa-bob3.mtr.labs.mlnx
 VMA INFO: ---------------------------------------------------------------------------
 VMA INFO: Log Level                      DETAILS                    [VMA_TRACELEVEL]
 VMA DETAILS: Log Details                    0                          [VMA_LOG_DETAILS]
 VMA DETAILS: Log Colors                     Enabled                    [VMA_LOG_COLORS]
 VMA DETAILS: Log File                                                  [VMA_LOG_FILE]
 VMA DETAILS: Stats File                                                [VMA_STATS_FILE]
 VMA DETAILS: Stats shared memory directory  /tmp/                      [VMA_STATS_SHMEM_DIR]
 VMA DETAILS: Stats FD Num (max)             100                        [VMA_STATS_FD_NUM]
 VMA DETAILS: Conf File                      /etc/libvma.conf           [VMA_CONFIG_FILE]
 VMA DETAILS: Application ID                 VMA_DEFAULT_APPLICATION_ID [VMA_APPLICATION_ID]
 VMA DETAILS: Polling CPU idle usage         Disabled                   [VMA_CPU_USAGE_STATS]
 VMA DETAILS: SigIntr Ctrl-C Handle          Disabled                   [VMA_HANDLE_SIGINTR]
 VMA DETAILS: SegFault Backtrace             Disabled                   [VMA_HANDLE_SIGSEGV]
 VMA DETAILS: Ring allocation logic TX       0 (Ring per interface)     [VMA_RING_ALLOCATION_LOGIC_TX]
 VMA DETAILS: Ring allocation logic RX       0 (Ring per interface)     [VMA_RING_ALLOCATION_LOGIC_RX]
 VMA DETAILS: Ring migration ratio TX        100                        [VMA_RING_MIGRATION_RATIO_TX]
 VMA DETAILS: Ring migration ratio RX        100                        [VMA_RING_MIGRATION_RATIO_RX]
 VMA DETAILS: Ring limit per interface       0 (no limit)               [VMA_RING_LIMIT_PER_INTERFACE]
 VMA DETAILS: Ring On Device Memory TX       0                          [VMA_RING_DEV_MEM_TX]
 VMA DETAILS: TCP max syn rate               0 (no limit)               [VMA_TCP_MAX_SYN_RATE]
 VMA DETAILS: Tx Mem Segs TCP                1000000                    [VMA_TX_SEGS_TCP]
 VMA DETAILS: Tx Mem Bufs                    200000                     [VMA_TX_BUFS]
 VMA DETAILS: Tx QP WRE                      2048                       [VMA_TX_WRE]
 VMA DETAILS: Tx QP WRE Batching             64                         [VMA_TX_WRE_BATCHING]
 VMA DETAILS: Tx Max QP INLINE               204                        [VMA_TX_MAX_INLINE]
 VMA DETAILS: Tx MC Loopback                 Enabled                    [VMA_TX_MC_LOOPBACK]
 VMA DETAILS: Tx non-blocked eagains         Disabled                   [VMA_TX_NONBLOCKED_EAGAINS]
 VMA DETAILS: Tx Prefetch Bytes              256                        [VMA_TX_PREFETCH_BYTES]
 VMA DETAILS: Rx Mem Bufs                    200000                     [VMA_RX_BUFS]
 VMA DETAILS: Rx QP WRE                      16000                      [VMA_RX_WRE]
 VMA DETAILS: Rx QP WRE Batching             64                         [VMA_RX_WRE_BATCHING]
 VMA DETAILS: Rx Byte Min Limit              65536                      [VMA_RX_BYTES_MIN]
 VMA DETAILS: Rx Poll Loops                  100000                     [VMA_RX_POLL]
 VMA DETAILS: Rx Poll Init Loops             0                          [VMA_RX_POLL_INIT]
 VMA DETAILS: Rx UDP Poll OS Ratio           100                        [VMA_RX_UDP_POLL_OS_RATIO]
 VMA DETAILS: HW TS Conversion               3                          [VMA_HW_TS_CONVERSION]
 VMA DETAILS: Rx SW CSUM                     1                          [VMA_RX_SW_CSUM]
 VMA DETAILS: Rx Poll Yield                  Disabled                   [VMA_RX_POLL_YIELD]
 VMA DETAILS: Rx Prefetch Bytes              256                        [VMA_RX_PREFETCH_BYTES]
 VMA DETAILS: Rx Prefetch Bytes Before Poll  0                          [VMA_RX_PREFETCH_BYTES_BEFORE_POLL]
 VMA DETAILS: Rx CQ Drain Rate               Disabled                   [VMA_RX_CQ_DRAIN_RATE_NSEC]
 VMA DETAILS: GRO max streams                32                         [VMA_GRO_STREAMS_MAX]
 VMA DETAILS: TCP 3T rules                   Disabled                   [VMA_TCP_3T_RULES]
 VMA DETAILS: ETH MC L2 only rules           Disabled                   [VMA_ETH_MC_L2_ONLY_RULES]
 VMA DETAILS: Force Flowtag for MC           Disabled                   [VMA_MC_FORCE_FLOWTAG]
 VMA DETAILS: Select Poll (usec)             100000                     [VMA_SELECT_POLL]
 VMA DETAILS: Select Poll OS Force           Disabled                   [VMA_SELECT_POLL_OS_FORCE]
 VMA DETAILS: Select Poll OS Ratio           10                         [VMA_SELECT_POLL_OS_RATIO]
 VMA DETAILS: Select Skip OS                 4                          [VMA_SELECT_SKIP_OS]
 VMA DETAILS: CQ Drain Interval (msec)       10                         [VMA_PROGRESS_ENGINE_INTERVAL]
 VMA DETAILS: CQ Drain WCE (max)             10000                      [VMA_PROGRESS_ENGINE_WCE_MAX]
 VMA DETAILS: CQ Interrupts Moderation       Enabled                    [VMA_CQ_MODERATION_ENABLE]
 VMA DETAILS: CQ Moderation Count            48                         [VMA_CQ_MODERATION_COUNT]
 VMA DETAILS: CQ Moderation Period (usec)    50                         [VMA_CQ_MODERATION_PERIOD_USEC]
 VMA DETAILS: CQ AIM Max Count               560                        [VMA_CQ_AIM_MAX_COUNT]
 VMA DETAILS: CQ AIM Max Period (usec)       250                        [VMA_CQ_AIM_MAX_PERIOD_USEC]
 VMA DETAILS: CQ AIM Interval (msec)         250                        [VMA_CQ_AIM_INTERVAL_MSEC]
 VMA DETAILS: CQ AIM Interrupts Rate (per sec) 5000                       [VMA_CQ_AIM_INTERRUPTS_RATE_PER_SEC]
 VMA DETAILS: CQ Poll Batch (max)            16                         [VMA_CQ_POLL_BATCH_MAX]
 VMA DETAILS: CQ Keeps QP Full               Enabled                    [VMA_CQ_KEEP_QP_FULL]
 VMA DETAILS: QP Compensation Level          256                        [VMA_QP_COMPENSATION_LEVEL]
 VMA DETAILS: Offloaded Sockets              Enabled                    [VMA_OFFLOADED_SOCKETS]
 VMA DETAILS: Timer Resolution (msec)        10                         [VMA_TIMER_RESOLUTION_MSEC]
 VMA DETAILS: TCP Timer Resolution (msec)    100                        [VMA_TCP_TIMER_RESOLUTION_MSEC]
 VMA DETAILS: TCP control thread             0 (Disabled)               [VMA_TCP_CTL_THREAD]
 VMA DETAILS: TCP timestamp option           0                          [VMA_TCP_TIMESTAMP_OPTION]
 VMA DETAILS: TCP nodelay                    0                          [VMA_TCP_NODELAY]
 VMA DETAILS: TCP quickack                   0                          [VMA_TCP_QUICKACK]
 VMA DETAILS: Exception handling mode        -1(just log debug message) [VMA_EXCEPTION_HANDLING]
 VMA DETAILS: Avoid sys-calls on tcp fd      Disabled                   [VMA_AVOID_SYS_CALLS_ON_TCP_FD]
 VMA DETAILS: Allow privileged sock opt      Enabled                    [VMA_ALLOW_PRIVILEGED_SOCK_OPT]
 VMA DETAILS: Delay after join (msec)        0                          [VMA_WAIT_AFTER_JOIN_MSEC]
 VMA DETAILS: Internal Thread Affinity       -1                         [VMA_INTERNAL_THREAD_AFFINITY]
 VMA DETAILS: Internal Thread Cpuset                                    [VMA_INTERNAL_THREAD_CPUSET]
 VMA DETAILS: Internal Thread Arm CQ         Disabled                   [VMA_INTERNAL_THREAD_ARM_CQ]
 VMA DETAILS: Internal Thread TCP Handling   0 (deferred)               [VMA_INTERNAL_THREAD_TCP_TIMER_HANDLING]
 VMA DETAILS: Thread mode                    Multi spin lock            [VMA_THREAD_MODE]
 VMA DETAILS: Buffer batching mode           1 (Batch and reclaim buffers) [VMA_BUFFER_BATCHING_MODE]
 VMA DETAILS: Mem Allocate type              1 (Contig Pages)           [VMA_MEM_ALLOC_TYPE]
 VMA DETAILS: Num of UC ARPs                 3                          [VMA_NEIGH_UC_ARP_QUATA]
 VMA DETAILS: UC ARP delay (msec)            10000                      [VMA_NEIGH_UC_ARP_DELAY_MSEC]
 VMA DETAILS: Num of neigh restart retries   1                          [VMA_NEIGH_NUM_ERR_RETRIES]
 VMA DETAILS: IPOIB support                  Enabled                    [VMA_IPOIB]
 VMA DETAILS: BF (Blue Flame)                Enabled                    [VMA_BF]
 VMA DETAILS: fork() support                 Enabled                    [VMA_FORK]
 VMA DETAILS: close on dup2()                Enabled                    [VMA_CLOSE_ON_DUP2]
 VMA DETAILS: MTU                            0 (follow actual MTU)      [VMA_MTU]
 VMA DETAILS: MSS                            0 (follow VMA_MTU)         [VMA_MSS]
 VMA DETAILS: TCP CC Algorithm               0 (LWIP)                   [VMA_TCP_CC_ALGO]
 VMA DETAILS: Polling Rx on Tx TCP           Disabled                   [VMA_RX_POLL_ON_TX_TCP]
 VMA DETAILS: Trig dummy send getsockname()  Disabled                   [VMA_TRIGGER_DUMMY_SEND_GETSOCKNAME]
 VMA INFO: ---------------------------------------------------------------------------

VMA_TRACELEVEL
Logging level the VMA library will be using. Default is info
Example: # VMA_TRACELEVEL=debug

none
    Print no log at all
panic
    Panic level logging, this would generally cause fatal behavior and an exception
    will be thrown by the VMA library. Typically, this is caused by memory
    allocation problems. This level is rarely used.
error
    Runtime ERRORs in the VMA.
    Typically, these can provide insight for the developer of wrong internal
    logic like: Errors from underlying OS or Infiniband verbs calls. internal
    double mapping/unmapping of objects.
warn
    Runtime warning that do not disrupt the workflow of the application but
    might warn of a problem in the setup or the overall setup configuration.
    Typically, these can be address resolution failure (due to wrong routing
    setup configuration), corrupted ip packets in the receive path or
    unsupported functions requested by the user application
info
    General information passed to the user of the application. Bring up
    configuration logging or some general info to help the user better
    use the VMA library
details
    Complete VMA's configuration information.
    Very high level insight of some of the critical decisions done in VMA.
debug
    High level insight to the operations done in the VMA. All socket API calls
    are logged and internal high level control channels log there activity.
fine
    Low level run time logging of activity. This logging level includes basic
    Tx and Rx logging in the fast path and it will lower application
    performance. It is recommended to use this level with VMA_LOG_FILE parameter.
finer
    Very low level run time logging of activity!
    This logging level will DRASTICALLY lower application performance.
    It is recommended to use this level with VMA_LOG_FILE parameter.
all
    today this level is identical to finer

VMA_LOG_DETAILS
Add details on each log line.
0 = Basic log line
1 = ThreadId
2 = ProcessId + ThreadId
3 = Time + ProcessId + ThreadId [Time is in milli-seconds from start of process]
Default value is 0

VMA_LOG_COLORS
Use color scheme when logging. Red for errors, purple for warnings and dim for
low level debugs. VMA_LOG_COLORS is automatically disabled when logging is direct
to a non terminal device (e.g. VMA_LOG_FILE is configured).
Default value is 1 (Enabled)

VMA_LOG_FILE
Redirect all VMA logging to a specific user defined file.
This is very useful when raising the VMA_TRACELEVEL
VMA will replace a single '%d' appearing in the log file name with the pid of
the process loaded with VMA. This can help in running multiple instances of VMA
each with it's own log file name.
Example:  VMA_LOG_FILE=/tmp/vma_log.txt

VMA_SPEC
VMA predefined specification profiles.

latency
    Optimized for use cases that are keen on latency. i.e. Ping-Pong tests.

    Latency SPEC changes the following default configuration
     VMA_RING_DEV_MEM_TX = 16384              (default: 0)
     VMA_TX_WRE = 256                         (default: 2048)
     VMA_TX_WRE_BATCHING = 4                  (default: 64)
     VMA_RX_WRE = 256                         (default: 16000)
     VMA_RX_WRE_BATCHING = 4                  (default: 64)
     VMA_RX_POLL = -1                         (default: 100000)
     VMA_RX_PREFETCH_BYTES_BEFORE_POLL = 256  (default: 0)
     VMA_GRO_STREAMS_MAX = 0                  (default: 32)
     VMA_SELECT_POLL = -1                     (default: 100000)
     VMA_SELECT_POLL_OS_FORCE = Enable        (default: Disabled)
     VMA_SELECT_POLL_OS_RATIO = 1             (default: 10)
     VMA_SELECT_SKIP_OS = 1                   (default: 4)
     VMA_PROGRESS_ENGINE_INTERVAL = 100       (default: 10)
     VMA_CQ_MODERATION_ENABLE = Disable       (default: Enabled)
     VMA_CQ_AIM_MAX_COUNT = 128               (default: 560)
     VMA_CQ_AIM_INTERVAL_MSEC = Disable       (default: 250)
     VMA_CQ_KEEP_QP_FULL = Disable            (default: Enable)
     VMA_TCP_NODELAY = Enable                 (default: Disable)
     VMA_AVOID_SYS_CALLS_ON_TCP_FD = Enable   (default: Disable)
     VMA_INTERNAL_THREAD_AFFINITY = 0         (default: -1)
     VMA_THREAD_MODE = Single                 (default: Multi spin lock)
     VMA_MEM_ALLOC_TYPE = 2                   (default: 1 (Contig Pages))

    Example: VMA_SPEC=latency

multi_ring_latency
     Optimized for use cases that are keen on latency where two applications communicate using send-only and receive-only TCP sockets

    Multi ring latency SPEC changes the following default configuration
     VMA_MEM_ALLOC_TYPE = 2                    (default: 1 (Contig Pages))
     VMA_SELECT_POLL = -1                      (default: 100000)
     VMA_RX_POLL = -1                          (default: 100000)
     VMA_RING_ALLOCATION_LOGIC_TX = 20         (default: Ring per interface)
     VMA_RING_ALLOCATION_LOGIC_RX = 20         (default: Ring per interface)
     VMA_SELECT_POLL_OS_RATIO = 0              (default: 10)
     VMA_SELECT_SKIP_OS = 0                    (default: 4)
     VMA_RX_POLL_ON_TX_TCP = true              (default: false)
     VMA_TRIGGER_DUMMY_SEND_GETSOCKNAME = true (default: false)

    Example: VMA_SPEC=multi_ring_latency

VMA_STATS_FILE
Redirect socket statistics to a specific user defined file.
VMA will dump each socket's statistics into a file when closing the socket.
Example:  VMA_STATS_FILE=/tmp/stats

VMA_STATS_SHMEM_DIR
Set the directory path for VMA to create the shared memory files for vma_stats.
No files will be created when setting this value to empty string "".
Default value is /tmp/

VMA_STATS_FD_NUM
Max number of sockets monitored by VMA statistic mechanism.
Value range is 0 to 1024.
Default value is 100

VMA_CONFIG_FILE
Sets the full path to the VMA configuration file.
Default values is: /etc/libvma.conf
Example: VMA_CONFIG_FILE=/tmp/libvma.conf

VMA_APPLICATION_ID
Specify a group of rules from libvma.conf for VMA to apply.
Example: 'VMA_APPLICATION_ID=iperf_server'.
Default is "VMA_DEFAULT_APPLICATION_ID" (match only the '*' group rule)

VMA_CPU_USAGE_STATS
Calculate VMA CPU usage during polling HW loops.
This information is available through VMA stats utility.
Default value is 0 (Disabled)

VMA_HANDLE_SIGINTR
When Enabled, VMA handler will be called when interrupt signal is sent to the process.
VMA will also call to application's handler if exist.
Value range is 0 to 1
Default value is 0 (Disabled)

VMA_HANDLE_SIGSEGV
When Enabled, print backtrace if segmentation fault happens.
Value range is 0 to 1
Default value is 0 (Disabled)

VMA_TX_SEGS_TCP
Number of TCP LWIP segments allocation for each VMA process.
Default value is 1000000

VMA_TX_BUFS
Number of global Tx data buffer elements allocation.
Default value is 200000

VMA_TX_WRE
Number of Work Request Elements allocated in all transmit QP's.
The number of QP's can change according to the number of network offloaded
interfaces.
Default value is 2048

VMA_TX_WRE_BATCHING
The number of Tx Work Request Elements used until a completion signal is requested.
Tuning this parameter allows a better control of the jitter encountered from the
Tx CQE handling. Setting a high batching value results in high PPS and lower
average latency. Setting a low batching value results in lower latency std-dev.
Value range is 1-64
Default value is 64

VMA_TX_MAX_INLINE
Max send inline data set for QP.
Data copied into the INLINE space is at least 32 bytes of headers and
the rest can be user datagram payload.
VMA_TX_MAX_INLINE=0 disables INLINEing on the Tx transmit path.
In older releases this parameter was called: VMA_MAX_INLINE
Default VMA_TX_MAX_INLINE is 204

VMA_TX_MC_LOOPBACK
This parameter sets the initial value used by VMA internally to controls the
multicast loopback packets behavior during transmission.
An application that calls setsockopt() with IP_MULTICAST_LOOP will run over
the initial value set by this parameter.
Read more in 'Multicast loopback behavior' in notes section below
Default value is 1 (Enabled)

VMA_TX_NONBLOCKED_EAGAINS
Return value 'OK' on all send operation done on a non-blocked UDP sockets. This
is the OS default behavior. The datagram sent is silently dropped inside VMA
or the network stack.
When set Enabled (set to 1), VMA will return with error EAGAIN if it was unable
accomplish the send operation and the datagram was dropped.
In both cases a dropped Tx statistical counter is incremented.
Default value is 0 (Disabled)

VMA_TX_PREFETCH_BYTES
Accelerate offloaded send operation by optimizing cache. Different values
give optimized send rate on different machines. We recommend you tune this
for your specific hardware.
Value range is 0 to MTU size
Disable with a value of 0
Default value is 256 bytes

VMA_RING_ALLOCATION_LOGIC_TX
VMA_RING_ALLOCATION_LOGIC_RX
Ring allocation logic is used to separate the traffic to different rings.
By default all sockets use the same ring for both RX and TX over the same interface.
Even when specifying the logic to be per socket or thread, for different interfaces
we use different rings. This is useful when tuning for a multi-threaded application
and aiming for HW resource separation.
Warning: This feature might hurt performance for applications which their main
processing loop is based in select() and/or poll().
The logic options are:
0  - Ring per interface
10 - Ring per socket (using socket fd as separator)
20 - Ring per thread (using the id of the thread in which the socket was created)
30 - Ring per core (using cpu id)
31 - Ring per core - attach threads : attach each thread to a cpu core
40 - Ring per ip address (using ip address)
Default value is 0

VMA_RING_MIGRATION_RATIO_TX
VMA_RING_MIGRATION_RATIO_RX
Ring migration ratio is used with the "ring per thread" logic in order to decide when
it is beneficial to replace the socket's ring with the ring allocated for the current thread.
Each VMA_RING_MIGRATION_RATIO iterations (of accessing the ring) we check the current
thread ID and see if our ring is matching the current thread.
If not, we consider ring migration. If we keep accessing the ring from the same thread for some
iterations, we migrate the socket to this thread ring.
Use a value of -1 in order to disable migration.
Default value is 100

VMA_RING_LIMIT_PER_INTERFACE
Limit the number of rings that can be allocated per interface.
For example, in ring allocation per socket logic, if the number of sockets using
the same interface is larger than the limit, then several sockets will be sharing the
same ring.
[Note:VMA_RX_BUFS might need to be adjusted in order to have enough buffers for all
rings in the system. Each ring consume VMA_RX_WRE buffers.]
Use a value of 0 for unlimited number of rings.
Default value is 0 (no limit)

VMA_RING_DEV_MEM_TX
VMA can use the On Device Memory to store the egress packet if it does not fit into
the BF inline buffer. This improves application egress latency by reducing PCI transactions.
Using VMA_RING_DEV_MEM_TX, the user can set the amount of On Device Memory buffer allocated
for each TX ring.
The total size of the On Device Memory is limited to 256k for a single port HCA and to
128k for dual port HCA.
Default value is 0

VMA_RX_BUFS
Number Rx data buffer elements allocation for the processes. These data buffers
may be used by all QPs on all HCAs
Default value is 200000

VMA_RX_WRE
Number of Work Request Elements allocated in all receive QP's.
Default value is 16000

VMA_RX_WRE_BATCHING
Number of Work Request Elements and RX buffers to batch before recycling.
Batching decrease latency mean, but might increase latency STD.
Value range is 1-1024.
Default value is 64

VMA_RX_BYTES_MIN
Minimum value in bytes that will be used per socket by VMA when applications
call to setsockopt(SO_RCVBUF). If application tries to set a smaller value then
configured in VMA_RX_BYTES_MIN, VMA will force this minimum limit value on the
socket.VMA offloaded socket's receive max limit of ready bytes count. If the
application does not drain a sockets and the byte limit is reached, new
received datagrams will be dropped.
Monitor of the applications socket's usage of current, max and dropped bytes
and packet counters can be done with vma_stats.
Default value is 65536

VMA_RX_POLL
The number of times to poll on Rx path for ready packets before going to sleep
(wait for interrupt in blocked mode) or return -1 (in non-blocked mode).
This Rx polling is done when the application is working with direct blocked
calls to read(), recv(), recvfrom() & recvmsg().
When Rx path has successful poll hits (see performance monitoring) the latency
is improved dramatically. This comes on account of CPU utilization.
Value range is -1, 0 to 100,000,000
Where value of -1 is used for infinite polling
Default value is 100000

VMA_RX_POLL_INIT
VMA maps all UDP sockets as potential offloaded capable. Only after the
ADD_MEMBERSHIP does the offload start to work and the CQ polling kicks in VMA.
This parameter control the polling count during this transition phase where the
socket is a UDP unicast socket and no multicast addresses where added to it.
Once the first ADD_MEMBERSHIP is called the above VMA_RX_POLL takes effect.
Value range is similar to the above VMA_RX_POLL
Default value is 0

VMA_RX_UDP_POLL_OS_RATIO
The above parameter will define the ratio between VMA CQ poll and OS FD poll.
This will result in a single poll of the not-offloaded sockets every
VMA_RX_UDP_POLL_OS_RATIO offloaded socket (CQ) polls. No matter if the CQ poll
was a hit or miss. No matter if the socket is blocking or non-blocking.
When disabled, only offloaded sockets are polled.
This parameter replaces the two old parameters: VMA_RX_POLL_OS_RATIO and
VMA_RX_SKIP_OS
Disable with 0
Default value is 100

VMA_HW_TS_CONVERSION
The above parameter defines the time stamp conversion method.
Experimental verbs is required for converting the time stamp from hardware time (Hz)
to system time (seconds.nano_seconds). Hence, hardware support is not guaranteed.
The value of VMA_HW_TS_CONVERSION is determined by all devices - i.e if the hardware of
one device does not support the conversion, then it will be disabled for the other devices.
Currently only UDP RX flow is supported.
Options = [0,1,2,3,4]:
0 = Disabled
1 = Raw-HW time                           - only convert the time stamp to seconds.nano_seconds time
                                            units (or disable if hardware does not supports).
2 = Best possible - Raw-HW or system time - Sync to system time, then Raw hardware time -
                                            disable if none of them are supported by hardware.
3 = Sync to system time                   - convert the time stamp to seconds.nano_seconds time units.
                                            comparable to UDP receive software timestamp.
                                            disable if hardware does not supports.
4 = PTP Sync                              - convert the time stamp to seconds.nano_seconds time units.
                                            in case it is not supported - will apply option 3 (or disable
                                            if hardware does not supports).
Default value: 3

VMA_RX_POLL_YIELD
When an application is running with multiple threads, on a limited number of
cores, there is a need for each thread polling inside the VMA (read, readv,
recv & recvfrom) to yield the CPU to other polling thread so not to starve
them from processing incoming packets.
Default value is 0 (Disable)

VMA_RX_PREFETCH_BYTES
Size of receive buffer to prefetch into cache while processing ingress packets.
The default is a single cache line of 64 bytes which should be at least 32
bytes to cover the IPoIB+IP+UDP headers and a small part of the users payload.
Increasing this can help improve performance for larger user payload sizes.
Value range is 32 bytes to MTU size
Default value is 256 bytes

VMA_RX_PREFETCH_BYTES_BEFORE_POLL
Same as the above VMA_RX_PREFETCH_BYTES, only that prefetch is done before
actually getting the packets.
This benefit low pps traffic latency.
Disable with 0.
Default value is 0

VMA_RX_CQ_DRAIN_RATE_NSEC
Socket's receive path CQ drain logic rate control.
When disabled (Default) the socket's receive path will first try to return a
ready packet from the socket's receive ready packet queue. Only if that queue
is empty will the socket check the CQ for ready completions for processing.
When enabled, even if the socket's receive ready packet queue is not empty it
will still check the CQ for ready completions for processing. This CQ polling
rate is controls in nano-second resolution to prevent CPU consumption because
of over CQ polling. This will enable a more 'real time' monitoring of the
sockets ready packet queue.
Recommended value is 100-5000 (nsec)
Default value is 0 (Disable)

VMA_RX_POLL_ON_TX_TCP
This parameter enables/disables TCP RX polling during TCP TX operation for faster
TCP ACK reception.
Default: 0 (Disable)

VMA_TRIGGER_DUMMY_SEND_GETSOCKNAME
This parameter triggers dummy packet send from getsockname(), this
will warm up the caches.
For more information regarding dummy send, see VMA user manual document.
Default: 0 (Disable)

VMA_GRO_STREAMS_MAX
Control the number of TCP streams to perform GRO (generic receive offload) simultaneously.
Disable GRO with a value of 0.
Default value is 32

VMA_TCP_3T_RULES
Use only 3 tuple rules for TCP, instead of using 5 tuple rules.
This can improve performance for a server with listen socket which accept many
connections.

VMA_ETH_MC_L2_ONLY_RULES
Use only L2 rules for Ethernet Multicast.
All loopback traffic will be handled by VMA instead of OS.

VMA_MC_FORCE_FLOWTAG
Forces the use of flow tag acceleration for multicast flows where setsockopt(SO_REUSEADDR) is
set.
Applicable if there are no other sockets opened for the same flow in system.

VMA_SELECT_POLL
The duration in micro-seconds (usec) in which to poll the hardware on Rx path before
going to sleep (pending an interrupt blocking on OS select(), poll() or epoll_wait().
The max polling duration will be limited by the timeout the user is using when
calling select(), poll() or epoll_wait().
When select(), poll() or epoll_wait() path has successful receive poll hits
(see performance monitoring) the latency is improved dramatically. This comes
on account of CPU utilization.
Value range is -1, 0 to 100,000,000
Where value of -1 is used for infinite polling
Where value of 0 is used for no polling (interrupt driven)
Default value is 100000

VMA_SELECT_POLL_OS_FORCE
This flag forces to poll the OS file descriptors while user thread calls
select(), poll() or epoll_wait() even when no offloaded sockets are mapped.
Enabling this flag causes VMA to set VMA_SELECT_POLL_OS_RATIO and
VMA_SELECT_SKIP_OS to 1. This will result in VMA_SELECT_POLL number of
times VMA will poll the OS file descriptors, along side with offloaded
sockets, if such sockets exists.
Note that setting VMA_SELECT_SKIP_OS and VMA_SELECT_POLL_OS_RATIO
directly will override the values these parameters gets while
VMA_SELECT_POLL_OS_FORCE is enabled.
Enable with 1
Disable with 0
Default value is 0

VMA_SELECT_POLL_OS_RATIO
This will enable polling of the OS file descriptors while user thread calls
select() or poll() and the VMA is busy in the offloaded sockets polling loop.
This will result in a single poll of the not-offloaded sockets every
VMA_SELECT_POLL_RATIO offloaded sockets (CQ) polls.
When disabled, only offloaded sockets are polled.
(See VMA_SELECT_POLL for more info)
Disable with 0
Default value is 10

VMA_SELECT_SKIP_OS
Similar to VMA_RX_SKIP_OS, but in select() or poll() this will force the VMA
to check the non offloaded fd even though an offloaded socket has ready
packets found while polling.
Default value is 4

VMA_PROGRESS_ENGINE_INTERVAL
VMA Internal thread safe check that the CQ is drained at least once
every N milliseconds.
This mechanism allows VMA to progress the TCP stack even when the application
doesn't access its socket (so it doesn't provide a context to VMA).
If CQ was already drained by the application receive
socket API calls then this thread goes back to sleep without any processing.
Disable with 0
Default value is 10 msec

VMA_PROGRESS_ENGINE_WCE_MAX
Each time VMA's internal thread starts it's CQ draining, it will stop when
reach this max value.
The application is not limited by this value in the number of CQ elements
it can ProcessId form calling any of the receive path socket APIs.
Default value is 10000

VMA_CQ_MODERATION_ENABLE
Enable CQ interrupt moderation.
Default value is 1 (Enabled)

VMA_CQ_MODERATION_COUNT
Number of packets to hold before generating interrupt.
Default value is 48

VMA_CQ_MODERATION_PERIOD_USEC
Period in micro-seconds for holding the packet before generating interrupt.
Default value is 50

VMA_CQ_AIM_MAX_COUNT
Maximum count value to use in the adaptive interrupt moderation algorithm.
Default value is 560

VMA_CQ_AIM_MAX_PERIOD_USEC
Maximum period value to use in the adaptive interrupt moderation algorithm.
Default value is 250

VMA_CQ_AIM_INTERVAL_MSEC
Frequency of interrupt moderation adaptation.
Interval in milliseconds between adaptation attempts.
Use value of 0 to disable adaptive interrupt moderation.
Default value is 250

VMA_CQ_AIM_INTERRUPTS_RATE_PER_SEC
Desired interrupts rate per second for each ring (CQ).
The count and period parameters for CQ moderation will change automatically
to achieve the desired interrupt rate for the current traffic rate.
Default value is 5000

VMA_CQ_POLL_BATCH_MAX
Max size of the array while polling the CQs in the VMA
Default value is 16

VMA_CQ_KEEP_QP_FULL
If disabled (default), CQ will not try to compensate for each poll on the
receive path. It will use a "debt" to remember how many WRE miss from each QP
to fill it when buffers become available.
If enabled, CQ will try to compensate QP for each polled receive completion. If
buffers are short it will re-post a recently completed buffer. This causes a packet
drop and will be monitored in the vma_stats.
Default value is 1 (Enabled)

VMA_QP_COMPENSATION_LEVEL
Number of spare receive buffer CQ holds to allow for filling up QP while full
receive buffers are being processes inside VMA.
Default value is 256 buffers

VMA_OFFLOADED_SOCKETS
Create all sockets as offloaded/not-offloaded by default.
Value of 1 is for offloaded, 0 for not-offloaded.
Default value is 1 (Enabled)

VMA_TIMER_RESOLUTION_MSEC
Control VMA internal thread wakeup timer resolution (in milliseconds)
Default value is 10 (milliseconds)

VMA_TCP_TIMER_RESOLUTION_MSEC
Control VMA internal TCP timer resolution (fast timer) (in milliseconds).
Minimum value is the internal thread wakeup timer resolution (VMA_TIMER_RESOLUTION_MSEC).
Default value is 100 (milliseconds)

VMA_TCP_CTL_THREAD
Do all TCP control flows in the internal thread.
This feature should be kept disabled if using blocking poll/select (epoll is OK).
Use value of 0 to disable.
Use value of 1 for waking up the thread when there is work to do.
Use value of 2 for waiting for thread timer to expire.
Default value is disabled

VMA_TCP_TIMESTAMP_OPTION
If set, enable TCP timestamp option.
Currently, LWIP is not supporting RTTM and PAWS mechanisms.
See RFC1323 for info.
Use value of 0 to disable.
Use value of 1 for enable.
Use value of 2 for OS follow up.
Disabled by default (enabling causing a slight performance degradation).

VMA_TCP_NODELAY
If set, disable the Nagle algorithm option for each TCP socket during initialization.
This means that TCP segments are always sent as soon as possible, even if there is
only a small amount of data.
For more information on TCP_NODELAY flag refer to TCP manual page.
Valid Values are:
Use value of 0 to disable.
Use value of 1 for enable.
Default value is Disabled.

VMA_TCP_QUICKACK
If set, disable delayed acknowledge ability.
This means that TCP responds after every packet.
For more information on TCP_QUICKACK flag refer to TCP manual page.
Valid Values are:
Use value of 0 to disable.
Use value of 1 for enable.
Default value is Disabled.

VMA_RX_SW_CSUM
This parameter enables/disables software checksum validation for ingress TCP/UDP IP packets.
Most Mellanox HCAs support hardware offload checksum validation. If the hardware does not
support checksum validation offload, software checksum validation is required.
When this parameter is enabled, software checksum validation is calculated only if hardware
offload checksum validation is not performed.
Performance degradation might occur if hardware offload fails to validate checksum and
software calculation is used.
Note that disabling software calculation might cause corrupt packets to be
processed by VMA and the application, when the hardware does not perform this action.
For further details on which adapter card supports hardware offload checksum validation,
please refer to the VMA Release Notes.
Valid Values are:
Use value of 0 to disable.
Use value of 1 for enable.
Default value is Enabled.

VMA_EXCEPTION_HANDLING
Mode for handling missing support or error cases in Socket API or functionality by VMA.
Useful for quickly identifying VMA unsupported Socket API or features
Use value of -2 to exit() on VMA startup failure.
Use value of -1 for just handling at DEBUG severity.
Use value of 0 to log DEBUG message and try recovering via Kernel network stack (un-offloading the socket).
Use value of 1 to log ERROR message and try recovering via Kernel network stack (un-offloading the socket).
Use value of 2 to log ERROR message and return API respectful error code.
Use value of 3 to log ERROR message and abort application (throw vma_error exception).
Default value is -1 (notice, that in the future the default value will be changed to 0)

VMA_AVOID_SYS_CALLS_ON_TCP_FD
For TCP fd, avoid system calls for the supported options of:
ioctl, fcntl, getsockopt, setsockopt.
Non-supported options will go to OS.
To activate, use VMA_AVOID_SYS_CALLS_ON_TCP_FD=1.
Default value is disabled

VMA_INTERNAL_THREAD_AFFINITY
Control which CPU core(s) the VMA internal thread is serviced on. The cpu set
should be provided as *EITHER* a hexadecimal value that represents a bitmask. *OR* as a
comma delimited of values (ranges are ok). Both the bitmask and comma delimited list
methods are identical to what is supported by the taskset command. See the man page
on taskset for additional information.
Where value of -1 disables internal thread affinity setting by VMA
Bitmask Examples:
0x00000001 - Run on processor 0.
0x00000007 - Run on processors 1,2, and 3.
Comma Delimited Examples:
0,4,8      - Run on processors 0,4, and 8.
0,1,7-10   - Run on processors 0,1,7,8,9 and 10.
Default value is -1 (Disabled).

VMA_INTERNAL_THREAD_CPUSET
Select a cpuset for VMA internal thread (see man page of cpuset).
The value is the path to the cpuset (for example: /dev/cpuset/my_set), or an empty
string to run it on the same cpuset the process runs on.
Default value is an empty string.

VMA_INTERNAL_THREAD_TCP_TIMER_HANDLING
Select the internal thread policy when handling TCP timers
Use value of 0 for deferred handling. The internal thread will not handle TCP timers upon timer
expiration (once every 100ms) in order to let application threads handling it first
Use value of 1 for immediate handling. The internal thread will try locking and handling TCP timers upon
timer expiration (once every 100ms).  Application threads may be blocked till internal thread finishes handling TCP timers
Default value is 0 (deferred handling)

VMA_INTERNAL_THREAD_ARM_CQ
Wakeup the internal thread for each packet that the CQ receive.
Poll and process the packet and bring it to the socket layer.
This can minimize latency in case of a busy application which is not available to
receive the packet when it arrived.
However, this might decrease performance in case of high pps rate application.
Default value is 0 (Disabled)

VMA_WAIT_AFTER_JOIN_MSEC
This parameter indicates the time of delay the first packet send after
receiving the multicast JOINED event from the SM
This is helpful to over come loss of first few packets of an outgoing stream
due to SM lengthy handling of MFT configuration on the switch chips
Default value is 0 (milliseconds)

VMA_THREAD_MODE
By default VMA is ready for multi-threaded applications, meaning it is thread safe.
If the users application is a single threaded one, then using this configuration
parameter you can help eliminate VMA locks and get even better performance.
Single threaded application value is 0
Multi threaded application using spin lock value is 1
Multi threaded application using mutex lock value is 2
Multi threaded application with more threads than cores using spin lock value is 3
Default value is 1 (Multi with spin lock)

VMA_BUFFER_BATCHING_MODE
Batching of returning Rx buffers and pulling Tx buffers per socket.
In case the value is 0 then VMA will not use buffer batching.
In case the value is 1 then VMA will use buffer batching and will try to periodically reclaim unused buffers.
In case the value is 2 then VMA will use buffer batching with no reclaim.
[future: other values are reserved]
Default value is 1

VMA_MEM_ALLOC_TYPE
This replaces the VMA_HUGETBL parameter logic.
VMA will try to allocate data buffers as configured:
	0 - "ANON" - using malloc
	1 - "CONTIG" - using contiguous pages
	2 - "HUGEPAGES" - using huge pages.
OFED will also try to allocate QP & CQ memory accordingly:
	0 - "ANON" - default - use current pages ANON small ones.
	"HUGE" - force huge pages
	"CONTIG" - force contig pages
	1 - "PREFER_CONTIG" - try contig fallback to ANON small pages.
	"PREFER_HUGE" - try huge fallback to ANON small pages.
	2 - "ALL" - try huge fallback to contig if failed fallback to ANON small pages.
To override OFED use: (MLX_QP_ALLOC_TYPE, MLX_CQ_ALLOC_TYPE)
Default value is 1 (Contiguous pages)

The following VMA neigh parameters are for advanced users or Mellanox support only:

VMA_NEIGH_UC_ARP_QUATA
VMA will send UC ARP in case neigh state is NUD_STALE.
In case that neigh state is still NUD_STALE VMA will try
VMA_NEIGH_UC_ARP_QUATA retries to send UC ARP again and then will send BC ARP.

VMA_NEIGH_UC_ARP_DELAY_MSEC
This parameter indicates number of msec to wait between every UC ARP.

VMA_NEIGH_NUM_ERR_RETRIES
This number indicates number of retries to restart neigh state machine in case neigh got ERROR event.
Default value is 1

VMA_BF
This flag enables / disables BF (Blue Flame) usage of the ConnectX
Default value is 1 (Enabled)

VMA_FORK
Control whether VMA should support fork. Setting this flag on will cause VMA to
call ibv_fork_init() function. ibv_fork_init() initializes libibverbs's data
structures to handle fork() function calls correctly and avoid data corruption.
If ibv_fork_init() is not called or returns a non-zero status, then libibverbs
data structures are not fork()-safe and the effect of an application calling
fork() is undefined.
ibv_fork_init() works on Linux kernels 2.6.17 and higher which support the
MADV_DONTFORK flag for madvise().
Note that VMA's default with huge pages enabled (VMA_HUGETBL) you should use an
OFED stack version that support fork()ing of with huge pages (OFED 1.5 and higher).
Default value is 0 (Disabled)

VMA_CLOSE_ON_DUP2
When this parameter is enabled, VMA will handle the duplicate fd (oldfd),
as if it was closed (clear internal data structures) and only then,
will forward the call to the OS.
This is, in practice, a very rudimentary dup2 support.
It only supports the case, where dup2 is used to close file descriptors,
Default value is 1 (Enabled)

VMA_MTU
Size of each Rx and Tx data buffer (Maximum Transfer Unit).
This value sets the fragmentation size of the packets sent by the VMA library.
If VMA_MTU is 0 then for each interface VMA will follow the actual MTU.
If VMA_MTU is greater than 0 then this MTU value is applicable to all interfaces regardless of their actual MTU
Default value is 0 (following interface actual MTU)

VMA_MSS
VMA_MSS define the max TCP payload size that can sent without IP fragmentation.
Value of 0 will set VMA's TCP MSS to be aligned with VMA_MTU configuration
(leaving 40 bytes room for IP + TCP headers; "TCP MSS = VMA_MTU - 40").
Other VMA_MSS values will force VMA's TCP MSS to that specific value.
Default value is 0 (following VMA_MTU)

VMA_TCP_CC_ALGO
TCP congestion control algorithm.
The default algorithm coming with LWIP is a variation of Reno/New-Reno.
The new Cubic algorithm was adapted from FreeBsd implementation.
Use value of 0 for LWIP algorithm.
Use value of 1 for Cubic algorithm.
Use value of 2 in order to disable the congestion algorithm.
Default value is 0 (LWIP).

VMA_TCP_MAX_SYN_RATE
Limit the number of TCP SYN packets that VMA will handle
per second per listen socket.
For example, in case you use 10 for this value than VMA will accept at most 10
(could be less) new connections per second per listen socket.
Use a value of 0 for un-limiting the number of TCP SYN packets that can be handled.
Value range is 0 to 100000.
Default value is 0 (no limit)


VMA Monitoring & Performance Counters
=====================================
The VMA internal performance counters include information per user
sockets and a global view on select() and epoll_wait() usage by the application.

Use the 'vma_stats' included utility to view the per socket information and
performance counters during run time.
Usage:
        vma_stats [-p pid] [-k directory] [-v view] [-d details] [-i interval]

Defaults:
        find_pid=enabled, directory="/tmp/", view=1, details=1, interval=1,

Options:
  -p, --pid=<pid>               Show VMA statistics for process with pid: <pid>
  -k, --directory=<directory>   Set shared memory directory path to <directory>
  -n, --name=<application>      Show VMA statistics for application: <application>
  -f, --find_pid                Find and show statistics for VMA instance running (default)
  -F, --forbid_clean            By setting this flag inactive shared objects would not be removed
  -i, --interval=<n>            Print report every <n> seconds
  -c, --cycles=<n>              Do <n> report print cycles and exit, use 0 value for infinite (default)
  -v, --view=<1|2|3|4|5>        Set view type:1- basic info,2- extra info,3- full info,4- mc groups,5- similar to 'netstat -tunaep'
  -d, --details=<1|2>           Set details mode:1- to see totals,2- to see deltas
  -z, --zero                    Zero counters
  -l, --log_level=<level>       Set VMA log level to <level>(1 <= level <= 7)
  -S, --fd_dump=<fd> [<level>]  Dump statistics for fd number <fd> using log level <level>. use 0 value for all open fds
  -D, --details_level=<level>   Set VMA log details level to <level>(0 <= level <= 3)
  -s, --sockets=<list|range>    Log only sockets that match <list> or <range>, format: 4-16 or 1,9 (or combination)
  -V, --version                 Print version
  -h, --help                    Print this help message


Use VMA_STATS_FILE to get internal VMA statistics like vma_stats provide.
If this parameter is set and the user application performed transmit or receive
activity on a socket, then these values will be logs once the sockets are closed.

Below is a logout example of a socket performance counters.
Below the logout example there is some explanations about the numbers.

VMA: [fd=10] Tx Offload: 455 KB / 233020 / 0 / 3 [bytes/packets/drops/errors]
VMA: [fd=10] Tx OS info:   0 KB /      0 / 0 [bytes/packets/errors]
VMA: [fd=10] Rx Offload: 455 KB / 233020 / 0 / 0 [bytes/packets/eagains/errors]
VMA: [fd=10] Rx byte: max 200 / dropped 0 (0.00%) / limit 2000000
VMA: [fd=10] Rx pkt : max 1 / dropped 0 (0.00%)
VMA: [fd=10] Rx OS info:   0 KB /      0 / 0 [bytes/packets/errors]
VMA: [fd=10] Rx poll: 0 / 233020 (100.00%) [miss/hit]

Looking good :)
- No errors on transmit or receive on this socket (user fd=10)
- All the traffic was offloaded. No packets transmitted or receive via the OS.
- Just about no missed Rx polls (see VMA_RX_POLL & VMA_SELECT_POLL), meaning
 the receiving thread did not get to a blocked state to cause a contexts
 switch and hurt latency.
- No dropped packets caused by socket receive buffer limit (see VMA_RX_BYTES_MIN)

Interrupt Moderation
====================
The basic idea behind interrupt moderation is that the HW will not generate
interrupt for each packet, but instead only after some amount of packets received
or after the packet was held for some time.

The adaptive interrupt moderation change this packet count and time period
automatically to reach a desired rate of interrupts.


1. Use VMA_RX_POLL=0 and VMA_SELECT_POLL=0 to work in interrupt driven mode.

2. Control the period and frame count parameters with:
    VMA_CQ_MODERATION_COUNT - hold #count frames before interrupt
    VMA_CQ_MODERATION_PERIOD_USEC - hold #usec before interrupt

3. Control the adaptive algorithm with the following:
    VMA_CQ_AIM_MAX_COUNT - max possible #count frames to hold
    VMA_CQ_AIM_MAX_PERIOD_USEC - max possible #usec to hold
    VMA_CQ_AIM_INTERRUPTS_RATE_PER_SEC - desired interrupt rate
    VMA_CQ_AIM_INTERVAL_MSEC - frequency of adaptation

4. Disable CQ moderation with VMA_CQ_MODERATION_ENABLE=0
5. Disable Adaptive CQ moderation with VMA_CQ_AIM_INTERVAL_MSEC=0




Notes
=====
* Multicast loopback behavior:
	There is a different behavior between IPoIB and VMA when dealing with
	multicast packets at the same machine:
	- When sending from VMA application to IPoIB application on the same
	machine the packet will never be accepted by the IPoIB side (even when
	the loopback is enabled)
	- When sending from IPoIB application to VMA application on the same
	machine, the packet will always be accepted by the VMA side (even when
	the loop is disabled


Troubleshooting
===============

* High log level:

  VMA WARNING: *************************************************************
  VMA WARNING: * VMA is currently configured with high log level           *
  VMA WARNING: * Application performance will decrease in this log level!  *
  VMA WARNING: * This log level is recommended for debugging purposes only *
  VMA WARNING: *************************************************************
This warning message means that you are using VMA with high log level:
VMA_TRACELEVEL variable value is set to 4 or more.
In order to fix it - set VMA_TRACELEVEL to it's default value: 3


* Ethernet RAW_PACKET_QP limited to privilege users

 VMA WARNING: ******************************************************************************
 VMA WARNING: * Verbs RAW_PACKET QP type creation is limited for root user access          *
 VMA WARNING: * Working in this mode might causes VMA malfunction over Ethernet interfaces *
 VMA WARNING: * WARNING: the following steps will restart your network interface!          *
 VMA WARNING: * 1. "echo options ib_uverbs disable_raw_qp_enforcement=1 > /etc/modprobe.d/ib_uverbs.conf" *
 VMA WARNING: * 2. "/etc/init.d/openibd restart"                                           *
 VMA WARNING: * Read the RAW_PACKET QP root access enforcement section in the VMA's User Manual for more information *
 VMA WARNING: ******************************************************************************
This warning message means that VMA tried to create a HW QP resource over Eth
interface while the kernel requires this operation to be done only by privileged
users. root can enable this for regular users as well by:
 1. "echo options ib_uverbs disable_raw_qp_enforcement=1 > /etc/modprobe.d/ib_uverbs.conf"
 2. "/etc/init.d/openibd restart"


* CAP_NET_RAW and root access

VMA_WARNING: ******************************************************************************
VMA_WARNING: * Interface <Interface Name> will not be offloaded.
VMA_WARNING: * Offloaded resources are restricted to root or user with CAP_NET_RAW privileges
VMA_WARNING: * Read the CAP_NET_RAW and root access section in the VMA's User Manual for more information
VMA_WARNING: ******************************************************************************
This warning message means that VMA tried to create a hardware QP resource
while the kernel requires this operation to be performed only by privileged
users. Run as user root or grant CAP_NET_RAW privileges to your user
1. "setcap cap_net_raw=ep /usr/bin/sockperf"
2. "chmod u+s </usr/lib64/libvma.so>"

* Huge pages out of resource:

  VMA WARNING: ***************************************************************
  VMA WARNING: * NO IMMEDIATE ACTION NEEDED!                                 *
  VMA WARNING: * Not enough hugepage resources for VMA memory allocation.    *
  VMA WARNING: * VMA will continue working with regular memory allocation.   *
  VMA INFO   : * Optional: 1. Switch to a different memory allocation type   *
  VMA_INFO   : * 	      (VMA_MEM_ALLOC_TYPE= 0 or 1)		     *	
  VMA INFO   : *           2. Restart process after increasing the number of *
  VMA INFO   : *              hugepages resources in the system:             *
  VMA INFO   : * "cat /proc/meminfo |  grep -i HugePage"                     *
  VMA INFO   : * "echo 1000000000 > /proc/sys/kernel/shmmax"                 *
  VMA INFO   : * "echo 800 > /proc/sys/vm/nr_hugepages"                      *
  VMA WARNING: * Please refer to the memory allocation section in the VMA's  *
  VMA WARNING: * User Manual for more information			     *
  VMA WARNING: ***************************************************************
This warning message means that you are using VMA with hugepages memory allocation,
but not enough huge pages resources are available in the system.
If you want VMA to take full advantage of the performance benefits of huge pages then
you should restart the application after adding more hugepages resources in your
system similar to the details in the warning message above or trying to free unused hupepages
shared memory segments with the below script.

NOTE: Use 'ipcs -m' and 'ipcrm -m shmid' to check and clean unused shared memory segments.
Below is a short script to help you release VMAs unused huge pages resources:
    for shmid in `ipcs -m | grep 0x00000000 | awk '{print $2}'`;
    do echo 'Clearing' $shmid; ipcrm -m $shmid;
    done;


* Not supported Bonding Configuration:

 VMA WARNING: ******************************************************************************
 VMA WARNING: VMA doesn't support current bonding configuration of bond0.
 VMA WARNING: The only supported bonding mode is "802.3ad(#4)" or "active-backup(#1)"
 VMA WARNING: with "fail_over_mac=1" or "fail_over_mac=0".
 VMA WARNING: The effect of working in unsupported bonding mode is undefined.
 VMA WARNING: Read more about Bonding in the VMA's User Manual
 VMA WARNING: ******************************************************************************

This warning message means that VMA has detected bonding device which is configured
to work in mode which is not supported by VMA, this means that VMA will not support
high availability events for that interface.
VMA currently supports just active-backup(#1) or 802.3ad(#4) and fail_over_mac = 1 or 0 mode.
In order to fix this issue please change the bonding configuration.

Example:

Lets assume that the bonding device is bond0, which has two slaves: ib0 and
ib1.

Shut down the bond0 interface:
#ifconfig bond0 down

Find all the slaves of bond0:
#cat sys/class/net/bond0/bonding/slaves
ib0 ib1

Free all the slaves:
#echo -ib0 > /sys/class/net/bond0/bonding/slaves
#echo -ib1 > /sys/class/net/bond0/bonding/slaves

Change the bond mode:
#echo active-backup > /sys/class/net/bond0/bonding/mode

Change the fail_over_mac mode:
#echo 1 > /sys/class/net/bond0/bonding/fail_over_mac

Enslave the interfaces back:
#echo +ib0 > /sys/class/net/bond0/bonding/slaves
#echo +ib1 > /sys/class/net/bond0/bonding/slaves

Bring up the bonding interface:
#ifconfig bond0 up
OR
#ifconfig bond0 <ip> netmask <netmask> up

* Not supported Bonding & VLAN Configuration:

 VMA WARNING: ******************************************************************
 VMA WARNING: bond0.10: vlan over bond while fail_over_mac=1 is not offloaded
 VMA WARNING: ******************************************************************

This warning message means that VMA has detected bonding device which is configured with
VLAN over it while fail_over_mac=1.
This means that the bond will not be offloaded.
In order to fix this issue please change the bonding configuration.

