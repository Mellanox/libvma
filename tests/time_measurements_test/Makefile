CC = g++
CFLAGS += -DLINUX -O3 -Wall -D_GNU_SOURCE 
#CFLAGS += -Werror -Wswitch-enum -W
#CFLAGS += -pedantic #-ansi
CFLAGS += -I../../src/vma/
LDFLAGS += 
OBJECTS = timetest.o rdtsc.o
TARGETS = timetest

all: $(TARGETS)

timetest: $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

timetest.o: timetest.cpp
	$(CC) -c $(CFLAGS) $<

rdtsc.o: ../../src/vma/util/rdtsc.cpp
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(OBJECTS) $(TARGETS)

#g++ -O3 -lrt timetest.cpp -o timetest
