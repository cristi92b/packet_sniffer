CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-O2
LDFLAGS=-m64
LDLIBS=-lpcap

SRCS=Main.cpp Packet.cpp
OBJS=$(subst .cc,.o,$(SRCS))

all: sniffer

sniffer: $(OBJS)
	$(CXX) $(LDFLAGS) -o sniffer $(OBJS) $(LDLIBS)

sniffer.o: Packet.cpp

clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) sniffer
