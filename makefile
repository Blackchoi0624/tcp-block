LDLIBS=-lpcap

all: tcp-block


main.o: mac.h ip.h ethhdr.h tcphdr.h iphdr.h main.cpp

tcphdr.o: tcphdr.h tcphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

mac.o : mac.h mac.cpp

tcp-block: main.o ethhdr.o tcphdr.o iphdr.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
