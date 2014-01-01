To compile it you simply need to run the following commands:
>g++ -lpthread exchange.cpp -o exchange
>g++ -lpthread -lrt trader.cpp -o trader

The test app includes two applications - exchange and trader:
Exchange:
1.	Opens a MC socket and sends MC packets in a predefined rate (one every 10usec by default).
2.	Open a UC TCP socket and blocks on recvfrom().
a.	If an ORDER packet is received --> send ORD_ACK
b.	If a keep alive packet is received --> send KA_ACK
3.	Every X MC packets (configurable) --> send a MC QUOTE packet.

Trader:
1.	Open one MC socket and one TCP socket.
2.	On thread #1, the MC socket blocks on recv(). If it encounters the QUOTE packet it immediately sends a TPC ORDER packet through the TCP socket, and and measure the time it the send operation took.
3.	On thread #2 (optional), the TCP socket blocks on recv():
a.	Receives reply for ORDER packet (i.e. ORD_ACK)
b.	Receives reply for keep alive packet (i.e. KA_ACK)
4.	On thread #3 (optional), the TCP socket send keep alive packet every X usecs (configurable)

Running the application:
1.	First run the exchange app on one server and then the trader on another.
2.	If you run the app with no parameters (or with --help flag) you will get a usage print.
All of the configurable parameters are described along with their default parameters.
3.	There are only 2 mandatory parameters for the trader app (local interface IP and peer UC IP), and one mandatory parameter for the exchange app (local interface IP).
4.	Make sure to attach each thread to different core, there are parameters to control it.

