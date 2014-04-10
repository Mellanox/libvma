Updated: 10 Apr 2014

Introduction
============

libvma is a Mellanox multicast-offload, dynamically linked user space Linux library
for transparently enhancing the performance of multicast networking-heavy
applications over the InfiniBand networkinterface and OFED.


Using libvma
============

Installing:
Install the package as any other rpm package [rpm -i libvma.X.Y.Z-R.rpm].
The installation copies the VMA library to: /usr/lib[64]/libvma.so
The VMA monitoring utility is installed at: /usr/bin/vma_stat
The VMA extra socket API is located at: /usr/include/mellanox/vma_extra.h
A proprietary synthetic latency test for multicast is installed at: /usr/bin/udp_lat
The installation location of the README.txt and version information file 
(VMA_VERSION), latneyc testing tool source code (udp_lat.c) and a VMA performance 
envelop script (vma_perf_envelope.sh) files are as follows:
- Redhat: /usr/share/doc/libvma-X.Y.Z-R/
- SuSE:   /usr/share/doc/packages/libvma-X.Y.Z-R/

Post Installation:
After the installation is finished we recommend to manually add persistence
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
Set the env variable LD_PRELOAD to libvma.so and run your application.
Example: # LD_PRELOAD=libvma.so iperf -uc 224.22.22.22 -t 5



Configuration Values
====================

On default startup the VMA library logs to stderr the VMA version, the modified
configuration parameters being used and their values.
Please notice that except the following parameters:VMA_TRACELEVEL, VMA_LOG_DETAILS,
VMA_LOG_FILE, VMA logs just those parameters whose value != default.

Example:
 VMA INFO   : ---------------------------------------------------------------------------
 VMA INFO   : VMA_VERSION: 6.6.3-0
 VMA INFO   : Cmd Line: sockperf sr
 VMA INFO   : Current Time: Mon Apr 10 13:09:29 2014
 VMA INFO   : Pid:  7256
 VMA INFO   : OFED Version: MLNX_OFED_LINUX-2.2-0.1.0:
 VMA INFO   : Architecture: x86_64
 VMA INFO   : Node: r-sw-bolt4 
 VMA INFO   : ---------------------------------------------------------------------------
 VMA INFO   : Log Level                      4                          [VMA_TRACELEVEL]
 VMA DEBUG  : Log Details                    0                          [VMA_LOG_DETAILS]
 VMA DEBUG  : Log Colors                     Enabled                    [VMA_LOG_COLORS]
 VMA DEBUG  : Log File                                                  [VMA_LOG_FILE]
 VMA DEBUG  : Stats File                                                [VMA_STATS_FILE]
 VMA DEBUG  : Stats FD Num (max)             100                        [VMA_STATS_FD_NUM]
 VMA DEBUG  : Conf File                      /etc/libvma.conf           [VMA_CONFIG_FILE]
 VMA DEBUG  : Application ID                 VMA_DEFAULT_APPLICATION_ID [VMA_APPLICATION_ID]
 VMA DEBUG  : Polling CPU idle usage         Disabled                   [VMA_CPU_USAGE_STATS]
 VMA DEBUG  : SigIntr Ctrl-C Handle          Disabled                   [VMA_HANDLE_SIGINTR]
 VMA DEBUG  : SegFault Backtrace             Disabled                   [VMA_HANDLE_SIGSEGV]
 VMA DEBUG  : Ring allocation logic TX       0 (Ring per interface)     [VMA_RING_ALLOCATION_LOGIC_TX]
 VMA DEBUG  : Ring allocation logic RX       0 (Ring per interface)     [VMA_RING_ALLOCATION_LOGIC_RX]
 VMA DEBUG  : Ring migration ratio TX        100                        [VMA_RING_MIGRATION_RATIO_TX]
 VMA DEBUG  : Ring migration ratio RX        100                        [VMA_RING_MIGRATION_RATIO_RX]
 VMA DEBUG  : Ring limit per interface       0 (no limit)               [VMA_RING_LIMIT_PER_INTERFACE]
 VMA DEBUG  : Tx Mem Segs TCP                1000000                    [VMA_TX_SEGS_TCP]
 VMA DEBUG  : Tx Mem Bufs                    200000                     [VMA_TX_BUFS]
 VMA DEBUG  : Tx QP WRE                      16000                      [VMA_TX_WRE]
 VMA DEBUG  : Tx Max QP INLINE               224                        [VMA_TX_MAX_INLINE]
 VMA DEBUG  : Tx MC Loopback                 Enabled                    [VMA_TX_MC_LOOPBACK]
 VMA DEBUG  : Tx non-blocked eagains         Disabled                   [VMA_TX_NONBLOCKED_EAGAINS]
 VMA DEBUG  : Tx Prefetch Bytes              256                        [VMA_TX_PREFETCH_BYTES]
 VMA DEBUG  : Tx backlog max                 100                        [VMA_TX_BACKLOG_MAX]
 VMA DEBUG  : Rx Mem Bufs                    200000                     [VMA_RX_BUFS]
 VMA DEBUG  : Rx QP WRE                      16000                      [VMA_RX_WRE]
 VMA DEBUG  : Rx Byte Min Limit              65536                      [VMA_RX_BYTES_MIN]
 VMA DEBUG  : Rx Poll Loops                  100000                     [VMA_RX_POLL]
 VMA DEBUG  : Rx Poll Init Loops             0                          [VMA_RX_POLL_INIT]
 VMA DEBUG  : Rx UDP Poll OS Ratio           100                        [VMA_RX_UDP_POLL_OS_RATIO]
 VMA DEBUG  : Rx Poll Yield                  Disabled                   [VMA_RX_POLL_YIELD]
 VMA DEBUG  : Rx Prefetch Bytes              256                        [VMA_RX_PREFETCH_BYTES]
 VMA DEBUG  : Rx Prefetch Bytes Before Poll  256                        [VMA_RX_PREFETCH_BYTES_BEFORE_POLL]
 VMA DEBUG  : Rx CQ Drain Rate               Disabled                   [VMA_RX_CQ_DRAIN_RATE_NSEC]
 VMA DEBUG  : GRO max streams                32                         [VMA_GRO_STREAMS_MAX]
 VMA DEBUG  : TCP 3T rules                   Disabled                   [VMA_TCP_3T_RULES]
 VMA DEBUG  : ETH MC L2 only rules           Disabled                   [VMA_ETH_MC_L2_ONLY_RULES]
 VMA DEBUG  : Select Poll (usec)             100000                     [VMA_SELECT_POLL]
 VMA DEBUG  : Select Poll OS Force           Disabled                   [VMA_SELECT_POLL_OS_FORCE]
 VMA DEBUG  : Select Poll OS Ratio           10                         [VMA_SELECT_POLL_OS_RATIO]
 VMA DEBUG  : Select Poll Yield              Disabled                   [VMA_SELECT_POLL_YIELD]
 VMA DEBUG  : Select Skip OS                 4                          [VMA_SELECT_SKIP_OS]
 VMA DEBUG  : Select CQ Interrupts           Enabled                    [VMA_SELECT_CQ_IRQ]
 VMA DEBUG  : CQ Drain Interval (msec)       10                         [VMA_PROGRESS_ENGINE_INTERVAL]
 VMA DEBUG  : CQ Drain WCE (max)             10000                      [VMA_PROGRESS_ENGINE_WCE_MAX]
 VMA DEBUG  : CQ Interrupts Moderation       Enabled                    [VMA_CQ_MODERATION_ENABLE]
 VMA DEBUG  : CQ Moderation Count            48                         [VMA_CQ_MODERATION_COUNT]
 VMA DEBUG  : CQ Moderation Period (usec)    50                         [VMA_CQ_MODERATION_PERIOD_USEC]
 VMA DEBUG  : CQ AIM Max Count               160                        [VMA_CQ_AIM_MAX_COUNT]
 VMA DEBUG  : CQ AIM Max Period (usec)       200                        [VMA_CQ_AIM_MAX_PERIOD_USEC]
 VMA INFO   : CQ AIM Interval (msec)         250                        [VMA_CQ_AIM_INTERVAL_MSEC]
 VMA DEBUG  : CQ AIM Interrupts Rate (per sec) 5000                       [VMA_CQ_AIM_INTERRUPTS_RATE_PER_SEC]
 VMA DEBUG  : CQ Poll Batch (max)            16                         [VMA_CQ_POLL_BATCH_MAX]
 VMA DEBUG  : CQ Keeps QP Full               Enabled                    [VMA_CQ_KEEP_QP_FULL]
 VMA DEBUG  : QP Compensation Level          256                        [VMA_QP_COMPENSATION_LEVEL]
 VMA DEBUG  : Offloaded Sockets              Enabled                    [VMA_OFFLOADED_SOCKETS]
 VMA DEBUG  : Timer Resolution (msec)        10                         [VMA_TIMER_RESOLUTION_MSEC]
 VMA DEBUG  : TCP Timer Resolution (msec)    100                        [VMA_TCP_TIMER_RESOLUTION_MSEC]
 VMA DEBUG  : Delay after join (msec)        0                          [VMA_WAIT_AFTER_JOIN_MSEC]
 VMA DEBUG  : Delay after rereg (msec)       500                        [VMA_WAIT_AFTER_REREG_MSEC]
 VMA DEBUG  : Internal Thread Affinity       0                          [VMA_INTERNAL_THREAD_AFFINITY]
 VMA DEBUG  : Internal Thread Cpuset                                    [VMA_INTERNAL_THREAD_CPUSET]
 VMA DEBUG  : Internal Thread Arm CQ	     Disabled			[VMA_INTERNAL_THREAD_ARM_CQ]
 VMA DEBUG  : Thread mode                    Multi spin lock            [VMA_THREAD_MODE]
 VMA DEBUG  : Mem Allocate type              1 (Contig Pages)           [VMA_MEM_ALLOC_TYPE]
 VMA DEBUG  : Num of UC ARPs                 3                          [VMA_NEIGH_UC_ARP_QUATA]
 VMA DEBUG  : UC ARP delay (msec)            10000                      [VMA_NEIGH_UC_ARP_DELAY_MSEC]
 VMA DEBUG  : Num of neigh restart retries   1                          [VMA_NEIGH_NUM_ERR_RETRIES]
 VMA DEBUG  : IPOIB support                  Enabled                    [VMA_IPOIB]
 VMA DEBUG  : BF (Blue Flame)                Enabled                    [VMA_BF]
 VMA DEBUG  : fork() support                 Enabled                    [VMA_FORK]
 VMA DEBUG  : close on dup2()                Enabled                    [VMA_CLOSE_ON_DUP2]
 VMA DEBUG  : MTU                            1500                       [VMA_MTU]
 VMA DEBUG  : MSS                            0 (follow VMA_MTU)         [VMA_MSS]
 VMA DEBUG  : TCP CC Algorithm               0 (LWIP)                   [VMA_TCP_CC_ALGO]
 VMA DEBUG  : TCP scaling window             3		                [VMA_WINDOW_SCALING]
 VMA DEBUG  : Suppress IGMP ver. warning     Disabled                   [VMA_SUPPRESS_IGMP_WARNING]
 VMA INFO   : ---------------------------------------------------------------------------


VMA_TRACELEVEL 
Logging level the VMA library will be using. Default is 3 (INFO)
Example: # VMA_TRACELEVEL=4

0 = PANIC   
    Panic level logging, this would generally cause fatal behavior and an exception
    will be thrown by the VMA library. Typically, this is caused by memory 
    allocation problems. This level is rarely used.
1 = ERROR
    Runtime ERRORs in the VMA.
    Typically, these can provide insight for the developer of wrong internal
    logic like: Errors from underlaying OS or Infiniband verbs calls. internal
    double mapping/unmapping of objects.
2 = WARNING
    Runtime warning that do not disrupt the workflow of the application but 
    might warn of a problem in the setup or the overall setup configuration. 
    Typically, these can be address resolution failure (due to wrong routing 
    setup configuration), corrupted ip packets in the receive path or 
    unsupported functions requested by the user application
3 = INFO
    General information passed to the user of the application. Bring up 
    configuration logging or some general info to help the user better 
    use the VMA library
4 = DEBUG
    Complete VMA's configuration information.
    High level insight to the operations done in the VMA. All socket API calls
    are logged and internal high level control channels log there activity.
5 = FUNC
    Low level run time logging of activity. This logging level includes basic 
    Tx and Rx logging in the fast path and it will lower application 
    performance. It is recommended to use this level with VMA_LOG_FILE param.
6 = FUNC_ALL
    Very low level run time logging of activity!
    This logging level will DRASTICALLY lower application performance.
    It is recommended to use this level with VMA_LOG_FILE param.

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

VMA_STATS_FILE
Redirect socket statistics to a specific user defined file.
VMA will dump each socket's statistics into a file when closing the socket.
Example:  VMA_STATS_FILE=/tmp/stats

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
Default value is 16000

VMA_TX_MAX_INLINE
Max send inline data set for QP. 
Data copied into the INLINE space is at least 32 bytes of headers and
the rest can be user datagram payload.
VMA_TX_MAX_INLINE=0 disables INLINEing on the tx transmit path.
In older releases this parameter was called: VMA_MAX_INLINE
Default VMA_TX_MAX_INLINE is 224

VMA_TX_MC_LOOPBACK
This parameter sets the initial value used by VMA internally to controls the
multicast loopback packets behavior during transmission.
An application that calls setsockopt() with IP_MULTICAST_LOOP will run over
the initial value set by this parameter.
Read more in 'Multicast loopback behavior' in notes section below
Default value is 1 (Enabled)

VMA_TX_NONBLOCKED_EAGAINS
Return value 'OK' on all send operation done on a non-blocked udp sockets. This
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

VMA_TX_DROP_MODE
Debug parameter used to check various sent packet dropping modules. Assigning this
parameter any value other than 0 (zero) makes it visible on the VMA startup log.
0 - Disabled (Don't drop anything)
1 - Drop All
2 - Drop only MC offloaded traffic
3 - Drop only UC offloaded traffic
Default value is 0 (Disabled) which is not shown on the VMA startup log.

VMA_RING_ALLOCATION_LOGIC_TX
VMA_RING_ALLOCATION_LOGIC_RX
Ring allocation logic is used to separate the traffic to different rings.
By default all sockets use the same ring for both RX and TX over the same interface.
Even when specifing the logic to be per socket or thread, for different interfaces 
we use different rings.
The logic options are:
0  - Ring per interface
10 - Ring per socket (using socket fd as separator)
20 - Ring per thread (using the id of the thread in which the socket was created)
30 - Ring per core (using cpu id)
31 - Ring per core - attach threads : attach each thread to a cpu core
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

VMA_RX_BUFS
Number Rx data buffer elements allocation for the processes. These data buffers
will be used by all QPs on all HCAs as determined by the VMA_QP_LOGIC.
Default value is 200000

VMA_RX_WRE
Number of Work Request Elements allocated in all receive QP's. 
The number of QP's can change according to the VMA_QP_LOGIC.
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
Default value is 2000000

VMA_RX_POLL
The number of times to poll on Rx path for ready packets before going to sleep
(wait for interrupt in blocked mode) or return -1 (in non-blocked mode).
This Rx polling is done when the application is working with direct blocked
calls to read(), recv(), recvfrom() & recvmsg().
When Rx path has successfull poll hits (see performace monitoring) the latency
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
The above param will define the ratio between VMA CQ poll and OS FD poll.
This will result in a signle poll of the not-offloaded sockets every
VMA_RX_UDP_POLL_OS_RATIO offlaoded socket (CQ) polls. No matter if the CQ poll 
was a hit or miss. No matter if the socket is blocking or non-blocking.
When disabled, only offlaoded sockets are polled.
This parameter replaces the two old parameters: VMA_RX_POLL_OS_RATIO and 
VMA_RX_SKIP_OS
Disable with 0
Default value is 100

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
acutally getting the packets.
This benefit low pps traffic latency.
Disable with 0.
Default value is 256 bytes

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

VMA_SELECT_POLL
The duration in micro-seconds (usec) in which to poll the hardware on Rx path before
going to sleep (pending an interrupt blocking on OS select(), poll() or epoll_wait().
The max polling duration will be limited by the timeout the user is using when 
calling select(), poll() or epoll_wait().
When select(), poll() or epoll_wait() path has successfull receive poll hits
(see performace monitoring) the latency is improved dramatically. This comes 
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
select(), poll() or epoll_wait() and the VMA is busy in the offloaded sockets
polling loop. This will result in a signle poll of the not-offloaded sockets
every VMA_SELECT_POLL_RATIO offlaoded sockets (CQ) polls.
When disabled, only offlaoded sockets are polled. 
(See VMA_SELECT_POLL for more info)
Disable with 0
Default value is 10

VMA_SELECT_POLL_YIELD
When an application is running with multiple threads, on a limited number 
of cores, there is a need for each thread polling inside the VMA (select, 
poll & epoll) to yield the CPU to other polling thread so not to starve 
them from processing incoming packets.
Default value is 0 (Disable)

VMA_SELECT_SKIP_OS
Similar to VMA_RX_SKIP_OS, but in select(), poll() or epoll_wait() this will
force the VMA to check the non offloaded fd even though an offloaded socket
has ready packets found while polling.
Default value is 4

VMA_SELECT_CQ_IRQ
When disbaled no IB interrupts will be used during select(), poll() or
epoll_wait() socket calls. This mode of work is not recommended. 
It can be used by applications that use select(), poll() or epoll_wait()
as polling.
Default value is 1 (Enabled)

VMA_PROGRESS_ENGINE_INTERVAL
VMA Internal thread safe check that the CQ is drained at least onse
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
Default value is 2048

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
Intervall in milli-seconds between adaptation attempts.
Use value of 0 to disable adaptive interrupt moderation.
Default value is 250

VMA_CQ_AIM_INTERRUPTS_RATE_PER_SEC
Desired interrupts rate per second for each ring (CQ).
The count and period parameters for CQ moderation will change automatically
to achieve the desired interrupt rate for the current traffic rate.
Default value is 5000

VMA_CQ_POLL_BATCH_MAX
Max size of the array while polling the CQs in the VMA
Default value is 8

VMA_CQ_KEEP_QP_FULL
If disabled (default), CQ will not try to compensate for each poll on the
receive path. It will use a "debth" to remember how many WRE miss from each QP
to fill it when buffers become avilable.
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
Control VMA internal thread wakeup timer resolution (in milli seconds)
Default value is 10 (milli-sec)

VMA_TCP_TIMER_RESOLUTION_MSEC
Control VMA internal TCP timer resolution (fast timer) (in milli seconds).
Minimum value is the internal thread wakeup timer resolution (VMA_TIMER_RESOLUTION_MSEC).
Default value is 100 (milli-sec)

VMA_INTERNAL_THREAD_AFFINITY
Control which CPU core(s) the VMA internal thread is serviced on. The cpu set
should be provided as *EITHER* a hexidecmal value that represents a bitmask. *OR* as a 
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
Default value is cpu-0.

VMA_INTERNAL_THREAD_CPUSET
Select a cpuset for VMA internal thread (see man page of cpuset).
The value is the path to the cpuset (for example: /dev/cpuset/my_set), or an empty
string to run it on the same cpuset the process runs on.
Default value is an empty string. 

VMA_INTERNAL_THREAD_ARM_CQ
Wakeup the internal thread for each packet that the CQ recieve. 
Poll and process the packet and bring it to the socket layer.
This can minimize latency in case of a busy application which is not available to 
recieve the packet when it arrived.
However, this might decrease performance in case of high pps rate application.   
Default value is 0 (Disabled)

VMA_WAIT_AFTER_JOIN_MSEC
This parameter indicates the time of delay the first packet send after
receiving the multicast JOINED event from the SM
This is helpful to over come loss of first few packets of an outgoing stream
due to SM lengthy handling of MFT configuration on the switch chips
Default value is 0 (milli-sec)

VMA_WAIT_AFTER_REREG_MSEC
This parameter indicates the time of delay before and after sending 
a multicast LEAVE (after sm restart / failover event).
Default value is 500 (milli-sec)

VMA_THREAD_MODE
By default VMA is ready for multi-threaded applications, meaning it is thread safe.
If the users application is a single threaded one, then using this configuration
parameter you can help eliminate VMA locks and get even better performance.
Single threaded application value is 0
Multi threaded application using spin lock value is 1
Multi threaded application using mutex lock value is 2 
Multi threaded application with more threads than cores using spin lock value is 3
Default value is 1 (Multi with spin lock)

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
To overrive OFED use: (MLX_QP_ALLOC_TYPE, MLX_CQ_ALLOC_TYPE)
Default value is 1 (Contiguous pages)

The following VMA neigh parameters are for advanced users or Mellanox support only: 

VMA_NEIGH_UC_ARP_QUATA
VMA will send UC ARP in case neigh state is NUD_STALE.
In case that neigh state is still NUD_STALE VMA will try 
VMA_NEIGH_UC_ARP_QUATA retries to send UC ARP again and then will send BC ARP.  

VMA_NEIGH_UC_ARP_DELAY_MSEC
This parameter indicates number of msec to wait betwen every UC ARP.

VMA_NEIGH_NUM_ERR_RETRIES
This number inidcates number of retries to restart neigh state machine in case neigh got ERROR event.
Deafult value is 1

VMA_BF
This flag enables / disables BF (Blue Flame) usage of the ConnectX
Deafult value is 1 (Enabled)

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
When this parameter is enabled, VMA will handle the dupped fd (oldfd),
as if it was closed (clear internal data structures) and only then,
will forward the call to the OS.
This is, in practice, a very rudimentary dup2 support.
It only supports the case, where dup2 is used to close file descriptors,
Default value is 1 (Enabled)

VMA_MTU
Size of each Rx and Tx data buffer. 
This value set the fragmentation size the packets sent by the VMA library.
Default value is 1500

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
Use value of 1 for the Cubic algorithm.
Default value is 0 (LWIP).

VMA_WINDOW_SCALING
TCP scaling window. 
This value (factor range from 0 to 14, -1 to disable, -2 to use OS value) set
the factor in which the TCP window is scaled.
Factor of 0 allow using the tcp scaling window of the remote host, while not
changing the window of the local host. 
Value of -1 disable both direction.
Value of -2 use the OS maximum receive buffer value to calculate the factor.
Make sure that VMA buffers are big enough to support the window.
Default value is 3 

VMA_IPERF
Support iperf server default test which is multithreaded. 
In you run the iperf server with the additional flag -U and you feel that the 
VMA can do better, you can disable this function (VMA_IPERF=0)
Default value is 1 (Enabled)

VMA_SUPPRESS_IGMP_WARNING
Use VMA_SUPPRESS_IGMP_WARNING=1 to suppress the warnings about igmp version not forced to be 2.
Default value is 0 (Disabled)



VMA Monitoring & Performance Counters
=====================================
The VMA internal performance counters include information per user DATAGRAM
sockets and a global view on select() and epoll_wait() usage by the application.
Use the 'vma_stats' included utility to view the per socket information and
performance counters during run time.
usage: vma_stats <pid> [<info_level>]
- where pid is the process id that is using libvma.so
- info_level = 0 Show runtime performance counters (default)
- info_level = 1 Show additional application runtime configuration information
- info_level = 2 Show multicast group membership information (similar to 'netstat -g')

If the user application performed transmite or receive activity on a socket
then these values will be logs once the sockets are closed. The VMA logs its
internal performance counters if VMA_TRACELEVEL=4.

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
- No errors on transmite or receive on this socket (user fd=10)
- All the traffic was offloaded. No packets transmitted or receive via the OS. 
- Just about no missed Rx polls (see VMA_RX_POLL & VMA_SELECT_POLL), meaning
 the receiving thread did not get to a blocked state to cause a contexts
 switch and hurt latency.
- No dropped packets caused by socket receive buffer limit (see VMA_RX_BYTES_MIN)


IGMP 
====
To participate in a multicast that spans multiple networks, a host must inform 
local routers. The local routers contact other routers, passing on the membership
information and establishing routes.

Routers and hosts that implement multicast use the Internet Group Management 
Protocol (IGMP) to communicate group membership information, later the local 
router can propagate multicast membership information to other routers through 
the Internet.

In order to enable this behavior at applications running over IPoIB networks 
please use IGMPv2 on the network:
   'echo 2 > /proc/sys/net/ipv4/conf/ibX/force_igmp_version'



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
	- When sending from VMA application to ipoib application on the same
	machine the packet will never be accepted by the ipoib side (even when 
	the loopback is enabled)
	- When sending from ipoib application to VMA application on the same 
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


* IGMP not forced to V2:

  VMA WARNING: ************************************************************************
  VMA WARNING: IGMP Version flag is not forced to IGMPv2 for interface ib2!
  VMA WARNING: Working in this mode might causes VMA functionality degradation
  VMA WARNING: Please "echo 2 > /proc/sys/net/ipv4/conf/ib2/force_igmp_version"
  VMA WARNING: before loading your application with VMA library
  VMA WARNING: Please refer to the IGMP section in the VMA's User Manual for more information
  VMA WARNING: ************************************************************************
This warning message means that you are using on IB interfaces IGMP version other then 2 which is supported by VMA.
You can disabled VMA_IGMP=0 if you do not need to receive multicast packets from the Ethernet to 
the InfiniBand fabric or if you are using a Ethernet switch that does not do IGMP snooping.
If you do expect to receive multicast packets from the Ethernet to the InfiniBand fabric with VMA 
or if your Ethernet switch does IGMP snooping then you should force IGMP working mode to version 2
in all your hosts as well as your routers.
You can also do: "echo 2 > /proc/sys/net/ipv4/conf/all/force_igmp_version"


* IGMP Forced Version info missing:

  VMA WARNING: ************************************************************************
  VMA WARNING: Error in reading IGMP Version flag for interface 192.168.0.10!
  VMA WARNING: Working in this mode most probably causes VMA performance degradation
  VMA WARNING: Please refer to the IGMP section in the VMA's User Manual for more information
  VMA WARNING: ************************************************************************
This warning message means that you are using VMA with an older version of OFED
which does not support user space IGMP. 
If you do expect to receive multicast packets from the Ethernet to the
InfiniBand fabric with VMA then you need to upgrade your OFED based network stack.


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
system similar to the details in the warning message above or trying to free unused hupge
pages shared memory segments with the below script.

NOTE: Use 'ipcs -m' and 'ipcrm -m shmid' to check and clean unused shared memory segments.
Below is a short script to help you release VMAs unused huge pages resources:
    for shmid in `ipcs -m | grep 0x00000000 | awk '{print $2}'`; 
    do echo 'Clearing' $shmid; ipcrm -m $shmid; 
    done;


* Not supported Bonding Configuration:

 VMA WARNING:******************************************************************************
 VMA WARNING: VMA doesn't support current bonding configuration of bond0.
 VMA WARNING: The only supported bonding mode is "active-backup(#1)" with "fail_over_mac=1".
 VMA WARNING: The effect of working in unsupported bonding mode is undefined.
 VMA WARNING: Read more about Bonding in the VMA's User Manual
 VMA WARNING: ******************************************************************************

This warning message means that VMA has detected bonding device which is configured 
to work in mode which is not supported by VMA, this means that VMA will not support 
high avilability events for that interface. 
VMA currently supports just active-backup(#1) fail_over_mac = 'active'(#1) mode.
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



