import socket
import threading
import argparse
from time import sleep
from time import time

TCP_SOCKET_ARGS = socket.AF_INET, socket.SOCK_STREAM
UDP_SOCKET_ARGS = socket.AF_INET, socket.SOCK_DGRAM
NUMBER_OF_CONNECTIONS = 5
DATA_SIZE = 64  # (2**4) * (2**2) chars
DATA = '0123456789ABCDEF'* (2**2)
DATA_LAST = "FIN"
START_COMM = "START_COMM"
STOP_COMM = "STOP_COMM"


class DynamicMemHost(object):
    def __init__(self, parsed_args):
        self.server_ip = parsed_args.server_ip

        self.control_port = parsed_args.ports[0]
        self.free_port = parsed_args.ports[1]
        self.congested_port = parsed_args.ports[2]

        self.transport = parsed_args.transport

        self.iterations = parsed_args.test_iterations
        self.interval = parsed_args.interval
        self.interval_increase = parsed_args.interval_increase

        self.control_socket_elem = socket.socket(*(TCP_SOCKET_ARGS))
        self.free_socket_elem = socket.socket(*(TCP_SOCKET_ARGS))
        self.congested_socket_elem =\
            socket.socket(*(TCP_SOCKET_ARGS if
                            self.transport == 'tcp' else UDP_SOCKET_ARGS))

        self.flag_do_bg_communication = True

    def set_stop_bg_communication(self):
        self.flag_do_bg_communication = False


class ServerRX(DynamicMemHost):
    def __init__(self, parsed_args):
        DynamicMemHost.__init__(self, parsed_args)

        self.control_socket_elem.bind((self.server_ip, self.control_port))
        self.free_socket_elem.bind((self.server_ip, self.free_port))
        self.congested_socket_elem.bind((self.server_ip, self.congested_port))

        self.flag_send_to_client = False

    def set_send_to_client(self, val):
        self.flag_send_to_client = val

    def run_background_communication(self):
        def run_comm_server_tcp(so):
            so.listen(1)
            ss, _ = so.accept()

            print "server accepted connection"
            try:
                while self.flag_do_bg_communication:
                    sleep(0.1)
                    print "waiting for start"
                    while self.flag_send_to_client:
                        sleep(0.05)
                        ss.sendall(DATA)
                    ss.sendall(DATA_LAST)
                    sleep(1)

            except socket.error as e:
                print e
            finally:
                ss.close()

        def run_comm_server_udp(so):
            iteration = 0
            data, address = so.recvfrom(DATA_SIZE)
            if data != START_COMM:
                print "wrong start message"

            try:
                while self.flag_do_bg_communication:
                    sleep(0.1)
                    print "waiting for start"
                    while self.flag_send_to_client:
                        sleep(0.2)
                        so.sendto(DATA, address)
                        iteration += 1
                    so.sendto(DATA_LAST, address)
                    sleep(1)

            except socket.error as e:
                print e

        td_servers = []

        # free server - data constantly recv'd on client side
        td_servers.append(threading.Thread(target=run_comm_server_tcp,
                                           args=[self.free_socket_elem]))

        # congestion server = data recv'd on client side on intervals
        if self.transport == 'tcp':
            td_servers.append(threading.Thread(target=run_comm_server_tcp,
                                               args=
                                               [self.congested_socket_elem]))
        else: #  udp
            td_servers.append(threading.Thread(target=run_comm_server_udp,
                                               args=
                                               [self.congested_socket_elem]))

        for td in td_servers:
            td.start()

        return td_servers

    def close_background_communication(self, td_servers):
        self.set_stop_bg_communication()
        for td in td_servers:
            td.join()

    def run(self):
        tds = self.run_background_communication()

        print "waiting for client"
        self.control_socket_elem.listen(1)
        ss, _ = self.control_socket_elem.accept()
        print "control accepted connection"
        try:
            while True:
                print "wait for control command"
                data = ss.recv(DATA_SIZE)
                if data:
                    print "received data: ", data
                    if data == START_COMM:
                        self.set_send_to_client(True)
                    elif data == STOP_COMM:
                        self.set_send_to_client(False)
                else:
                    # Client disconnected
                    break
        except socket.error as e:
            print e
        finally:
            ss.close()

        self.close_background_communication(tds)


class ClientRX(DynamicMemHost):
    def __init__(self, parsed_args):
        DynamicMemHost.__init__(self, parsed_args)

    def run(self):
        if self.transport == 'tcp': #(socket.AF_INET, socket.SOCK_STREAM)
            self.run_congested_client_tcp()
        else:
            self.run_congested_client_udp()

    def run_congested_client_tcp(self):
        ret = self.control_socket_elem.connect_ex((self.server_ip,
                                                   self.control_port))
        count_connect_errors = 0
        while ret:
            if count_connect_errors > 10:
                print "error in connecting to server"
                exit(1)
            print "return value for connect is %d" % ret
            sleep(1)
            count_connect_errors += 1
            ret = self.control_socket_elem.connect_ex((self.server_ip,
                                                       self.control_port))

        ret = self.free_socket_elem.connect_ex((self.server_ip,
                                                self.free_port))
        count_connect_errors = 0
        while ret:
            if count_connect_errors > 10:
                print "error in connecting to server"
                exit(1)
            print "return value for connect is %d" % ret
            sleep(1)
            count_connect_errors += 1
            ret = self.free_socket_elem.connect_ex((self.server_ip,
                                                    self.free_port))

        ret = self.congested_socket_elem.connect_ex((self.server_ip,
                                                     self.congested_port))
        count_connect_errors = 0
        while ret:
            if count_connect_errors > 10:
                print "error in connecting to server"
                exit(1)
            print "return value for connect is %d" % ret
            sleep(1)
            count_connect_errors += 1
            ret = self.congested_socket_elem.connect_ex((self.server_ip,
                                                         self.congested_port))


        try:
            for _ in range(self.iterations):
                self.control_socket_elem.send(START_COMM)
                start_time = time()
                # consume data for {interval} seconds
                while time() < start_time + self.interval:
                    data = self.free_socket_elem.recv(DATA_SIZE)

                print "send stop"
                self.control_socket_elem.send(STOP_COMM)

                message_iterations = 0
                print "recv'd data"
                flag_do_recv = True
                accumulated_data = ""
                while flag_do_recv:
                    data = self.congested_socket_elem.recv(DATA_SIZE)
                    if data == DATA_LAST:
                        flag_do_recv = False
                        continue

                    accumulated_data.join(data)
                    if len(accumulated_data) >= DATA_SIZE:
                        if accumulated_data[:DATA_SIZE] != DATA:
                            print "warning: data mismatch."
                        accumulated_data = accumulated_data[DATA_SIZE:]

                    message_iterations += 1
                print "messages received: %d" % message_iterations

                self.interval += self.interval_increase

        except socket.error as e:
            print e
        finally:
            self.congested_socket_elem.close()
            self.free_socket_elem.close()
            self.control_socket_elem.close()

    def run_congested_client_udp(self):
        ret = self.control_socket_elem.connect_ex((self.server_ip,
                                                   self.control_port))
        count_connect_errors = 0
        while ret:
            if count_connect_errors > 10:
                print "error in connecting to server"
                exit(1)
            print "return value for connect is %d" % ret
            sleep(1)
            count_connect_errors += 1
            ret = self.control_socket_elem.connect_ex((self.server_ip,
                                                       self.control_port))

        ret = self.free_socket_elem.connect_ex((self.server_ip,
                                                self.free_port))
        count_connect_errors = 0
        while ret:
            if count_connect_errors > 10:
                print "error in connecting to server"
                exit(1)
            print "return value for connect is %d" % ret
            sleep(1)
            count_connect_errors += 1
            ret = self.free_socket_elem.connect_ex((self.server_ip,
                                                    self.free_port))

        self.congested_socket_elem.sendto(START_COMM,
                                          (self.server_ip,
                                           self.congested_port))
        try:
            for _ in range(self.iterations):
                self.control_socket_elem.send(START_COMM)
                start_time = time()
                # consume data for {interval} seconds
                while time() < start_time + self.interval:
                    data = self.free_socket_elem.recv(DATA_SIZE)

                print "send stop"
                self.control_socket_elem.send(STOP_COMM)

                message_iterations = 0
                print "recv'd data"
                flag_do_recv = True
                accumulated_data = ""
                while flag_do_recv:
                    data, _ = self.congested_socket_elem.recvfrom(DATA_SIZE)
                    if data == DATA_LAST:
                        flag_do_recv = False
                    else:
                        accumulated_data += data
                        if len(accumulated_data) >= DATA_SIZE:
                            if accumulated_data[:DATA_SIZE] != DATA:
                                print "warning: data mismatch."
                            accumulated_data = accumulated_data[DATA_SIZE:]

                    message_iterations += 1
                print "messages received: %d" % message_iterations

                self.interval += self.interval_increase

        except socket.error as e:
            print e
        finally:
            self.free_socket_elem.close()
            self.control_socket_elem.close()


if __name__ == "__main__":
    EPILOG = """
server is a simple echo server. client should be run with VMA.
check client's vma_stats to check for bpool status.

example tcp:
server:
$ python tests/dynamic_memory_pools/test_rx.py -host server -trans tcp -ip 1.2.105.2 -ports 12345 12346 12347
client:
$ VMA_QP_COMPENSATION_LEVEL=10 VMA_RX_WRE_BATCHING=10 VMA_RX_WRE=10 VMA_BPOOL_TIMER=2 VMA_RX_BUFS=200:5:200000:300 LD_PRELOAD=src/vma/.libs/libvma.so python tests/dynamic_memory_pools/test_rx.py -host client -trans tcp -ip 1.2.105.2 -ports 12345 12346 12347

- replace 'tcp' with 'udp' for testing udp.
- run vma_stats on client and make sure buffer pools are allocated.
"""

    parser = argparse.ArgumentParser(epilog=EPILOG,
                                     formatter_class=argparse.
                                     RawDescriptionHelpFormatter)
    parser.add_argument('-host', dest="host", type=str,
                        choices=["server", "client"], default=None,
                        help="server or client", required=True)
    parser.add_argument('-trans', dest="transport", type=str,
                        choices=["tcp", "udp"], default="tcp",
                        help="tcp (default) or udp", required=True)
    parser.add_argument('-ip', dest="server_ip", type=str,
                        default='', #default: localhost
                        help="server ip. default: localhost",
                        required=True)
    parser.add_argument('-ports', nargs=3, type=int,
                        default=None, required=True,
                        help=\
"3 ports: control_port, free_port, and congested_port. "
"usage: -ports 7888 7889 7890")

    parser.add_argument('-iterations', dest="test_iterations",
                        type=int, default=10,
                        help="number of total iterations of the test.")
    parser.add_argument('-interval', dest="interval", type=int, default=3,
                        help=\
"initial interval of server sending data in seconds.")
    parser.add_argument('-interval_increase', dest="interval_increase",
                        type=int, default=2,
                        help=\
"increase quanta of interval of server sending data (if init is 3,"
" will be 3 seconds, then 5 for the next iteration and so forth).")

    parsed_args = parser.parse_args()

    if parsed_args.host == 'server':
        host = ServerRX(parsed_args)
    else:
        host = ClientRX(parsed_args)

    exit(host.run())
