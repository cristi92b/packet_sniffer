#include <iostream>
#include <pcap.h>
#include "Packet.h"
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>

//void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char **argv) {

    char *device; /* Name of device (e.g. eth0, wlan0) */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }
    printf("Network device found: %s\n", device);

    //char ip[13];
    std::string ipAddr;
    char subnet_mask[13];
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    int lookup_return_code;
    struct in_addr address; /* Used for both ip & subnet */

    lookup_return_code = pcap_lookupnet(
        device,
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }

    address.s_addr = ip_raw;
    ipAddr = inet_ntoa(address);
    if (ipAddr.empty()) {
        printf("inet_ntoa"); /* print error */
        return 1;
    }
    else
    {
        std::cout << "IP=" << ipAddr.c_str();
    }

    return 0;

/*
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
     struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000;

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        std::cout << "Error finding device " << error_buffer << std::endl;
        return 1;
    }


    handle = pcap_open_live(
            device,
            BUFSIZ,
            packet_count_limit,
            timeout_limit,
            error_buffer
        );

     packet = pcap_next(handle, &packet_header);
     if (packet == NULL) {
        std::cout << "No packet found" << std::endl;
        return 2;
    }

*/
    //print_packet_info(packet, packet_header);

}
/*
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    if(packet != NULL)
    {
        std::cout << "Packet capture length:" <<  packet_header.caplen << std::endl;
        std::cout << "Packet total length:" <<  packet_header.len << std::endl;
    }
}
*/
