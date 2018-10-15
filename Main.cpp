#include <iostream>
#include <pcap.h>
#include "Packet.h"
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char **argv) {

    Packet packetSniffer;
    packetSniffer.StartListening();

    std::cout << "Press enter to continue ...";
    std::cin.get();

    return 0;
}
