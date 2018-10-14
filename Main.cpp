#include <iostream>
#include <pcap.h>
#include "Packet.h"

int main(int argc, char **argv) {
    char *device; /* Name of device (e.g. eth0, wlan0) */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

    /* Find a device */
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        std::cout << "Error finding device: " << error_buffer;
        return 1;
    }
    std::cout << "Network device found: " << device;
    return 0;
}
