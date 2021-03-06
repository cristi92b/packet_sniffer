#ifndef PACKET_H
#define PACKET_H

#include <iostream>
#include <fstream>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdexcept>

class Packet{
    public:
        Packet();
        virtual ~Packet();
        void StartListening();
        static std::ofstream fOutputStream; //TODO: Create interface for output stream
        //Note: fOutputStream is static because the packet handler function must be a static method and we cannot change the signature of PacketHandler() so that we can pass the stream as parameter
    private:
        pcap_t *fHandle;
        std::string fDevice;
        char error_buffer[PCAP_ERRBUF_SIZE];
        static void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
        static void WritePacket(const u_char *packet, struct pcap_pkthdr packet_header);

};


#endif
