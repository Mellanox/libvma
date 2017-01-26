import socket
import threading
import argparse
from time import sleep


TCP_SOCKET_ARGS = socket.AF_INET, socket.SOCK_STREAM
UDP_SOCKET_ARGS = socket.AF_INET, socket.SOCK_DGRAM
NUMBER_OF_CONNECTIONS = 100
DATA_SIZE = 128  # (2**4) * (2**3) chars
DATA = '0123456789ABCDEF'* (2**3)

class DynamicMemHost(object):
    def __init__(self, parsed_args):
        self.server_ip = parsed_args.server_ip
        self.port = parsed_args.port
        self.transport = parsed_args.transport
        self.socket_elem = None

class ServerTX(DynamicMemHost):
    def __init__(self, parsed_args):
        DynamicMemHost.__init__(self, parsed_args)

        self.socket_elem = socket.socket(*(TCP_SOCKET_ARGS if
                                           self.transport == 'tcp' else
                                           UDP_SOCKET_ARGS))
        self.socket_elem.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket_elem.bind((self.server_ip, self.port))

    def run(self):
        if self.transport == 'tcp': #(socket.AF_INET, socket.SOCK_STREAM)
            return self.run_tcp()
        else:
            return self.run_udp()

    def run_tcp(self):
        def listen_to_client(client):
            while True:
                try:
                    data = client.recv(DATA_SIZE)
                    if data:
                        client.send(DATA)
                    else:
                        raise socket.error('Client disconnected')
                except socket.error as e:
                    print e
                finally:
                    client.close()


        self.socket_elem.listen(NUMBER_OF_CONNECTIONS)
        while True:
            ss, address = self.socket_elem.accept()
            ss.settimeout(60)
            td = threading.Thread(target=listen_to_client,
                                  args=(ss))
            td.start()

    def run_udp(self):
        while True:
            data, _ = self.socket_elem.recvfrom(DATA_SIZE)
            if len(data) != DATA_SIZE or data != DATA:
                print "ERROR: data received corrupted."


class ClientTX(DynamicMemHost):
    def __init__(self, parsed_args):
        DynamicMemHost.__init__(self, parsed_args)

    def run(self):
        def create_tcp_sockets(step_connections):
            connect_error = 0
            for _ in range(step_connections): #open [step_connections] socket
                cs = socket.socket(socket.AF_INET)
                while True:
                    try:
                        cs.connect((self.server_ip, self.port))
                        break
                    except socket.error as e:
                        sleep(1)
                        connect_error += 1
                        print "Connect ERROR: %d" % connect_error
                        continue

                client_sockets.append(cs)
                sleep(0.1)

        def send_tcp():
            for cs in client_sockets:
                cs.send(DATA)

        def recv_tcp():
            for cs in client_sockets:
                recieved_data = cs.recv(DATA_SIZE)
                #print recieved_data
                if len(recieved_data) != DATA_SIZE or recieved_data != DATA:
                    print "ERROR: data returned corrupted."
                    return False
            return True

        def create_udp_sockets(step_connections):
            for _ in range(step_connections): #open [step_connections] socket
                cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_sockets.append(cs)
                sleep(0.1)

        def send_udp():
            for cs in client_sockets:
                cs.sendto(DATA, (self.server_ip, self.port))

        step_iterations = 10
        step_connections = NUMBER_OF_CONNECTIONS/10
        client_sockets = []

        for i in range(step_iterations):
            print "Step %d:\trunning with %d sockets."\
                "" %(i + 1, (i + 1)*step_connections)
            if self.transport == 'tcp':
                create_tcp_sockets(step_connections)
                send_tcp()
                if not recv_tcp():
                    return -1

            else:  # 'udp'
                create_udp_sockets(step_connections)
                send_udp()
            sleep(1)

        for cs in client_sockets:
            cs.close()


if __name__ == "__main__":
    EPILOG = """
server is a simple echo server. client should be run with VMA.
check client's vma_stats to check for bpool status.

example udp:
server:
    $ python tests/dynamic_memory_pools/test_tx.py -host server -trans udp -ip 1.2.105.2 -port 12345
client:
    $ VMA_RING_ALLOCATION_LOGIC_TX=20 VMA_TX_BUFS=5000:100:10000:5000 LD_PRELOAD=src/vma/.libs/libvma.so python tests/dynamic_memory_pools/test_tx.py -host client -trans udp -ip 1.2.105.2 -port 12345 

replace 'udp' with 'tcp' for testing tcp.
"""

    parser = argparse.ArgumentParser(epilog=EPILOG,
                                     formatter_class=argparse.
                                     RawDescriptionHelpFormatter)
    parser.add_argument('-host', dest="host", type=str,
                        choices=["server", "client"], default=None,
                        help="server or client")
    parser.add_argument('-trans', dest="transport", type=str,
                        choices=["tcp", "udp"], default="tcp",
                        help="tcp (default) or udp")
    parser.add_argument('-ip', dest="server_ip", type=str,
                        default='', #default: localhost
                        help="server ip, default: localhost")
    parser.add_argument('-port', dest="port", type=int, default=None,
                        help="port")


    parsed_args = parser.parse_args()

    if parsed_args.host == 'server':
        host = ServerTX(parsed_args)
    else:
        host = ClientTX(parsed_args)

    exit(host.run())
