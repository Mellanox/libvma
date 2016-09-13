CC = gcc
LDFLAGS += -lrt 
TARGETS = client server

all: $(TARGETS)

client: tcp_wnd_test_client.c
	$(CC) $(LDFLAGS) $^ -o client

server: tcp_wnd_test_server.c
	$(CC) $(LDFLAGS) $^ -o server

clean:
	rm -f $(TARGETS)
