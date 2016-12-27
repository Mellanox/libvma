CC = gcc
LDFLAGS += -lrt 
OBJECTS = client server

all: $(OBJECTS)

client: tcp_wnd_test_client.c
	$(CC) $(LDFLAGS) $< -o client
server: tcp_wnd_test_server.c
	$(CC) $(LDFLAGS) $< -o server

clean:
	rm -f $(OBJECTS) $(TARGETS)
