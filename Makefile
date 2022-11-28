
PROG = projectPart2
PCAP = `pkg-config --cflags --libs libpcap`

$(PROG): $(PROG).c JsonParse.h
	gcc -g -o $(PROG) $(PROG).c $(PCAP)

pcap:
	gcc -g -o pcapTest pcapTest.c -lpcap $(PCAP)

run:
	sudo ./$(PROG)

clean:
	rm -rf projectPart2
	