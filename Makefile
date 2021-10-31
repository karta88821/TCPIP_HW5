CC = gcc 
CFLAGS = -Wall -W -Wshadow -std=gnu99 
TARGETS = scanner
 
all: $(TARGETS)

scanner: scanner.o fill_packet.o pcap.o shared.o -lpcap

clean: 
	rm -f *.o	

distclean: clean
	rm -f $(TARGETS)