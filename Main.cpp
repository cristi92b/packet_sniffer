#include <iostream>
#include <pcap.h>
#include "Packet.h"
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char **argv) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
     struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        std::cout << "Error finding device " << error_buffer << std::endl;
        return 1;
    }

    /* Open device for live capture */
    handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );

     /* Attempt to capture one packet. If there is no network traffic
      and the timeout is reached, it will return NULL */
     packet = pcap_next(handle, &packet_header);
     if (packet == NULL) {
        std::cout << "No packet found" << std::endl;
        return 2;
    }

    /* Our function to output some info */
    print_packet_info(packet, packet_header);

    return 0;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    if(packet != NULL)
    {
        std::cout << "Packet capture length:" <<  packet_header.caplen << std::endl;
        std::cout << "Packet total length:" <<  packet_header.len << std::endl;
    }
}
