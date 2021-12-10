CC = gcc 
CFLAGS = -Wall -W -Wshadow -std=gnu99 
TARGETS = scanner
 
all: $(TARGETS)

scanner: main.o fill_packet.o pcap.o

clean: 
	rm -f *.o	

distclean: clean
	rm -f $(TARGETS)