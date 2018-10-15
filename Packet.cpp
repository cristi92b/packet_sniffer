#include "Packet.h"

std::ofstream Packet::fOutputStream;

Packet::Packet()
{
    char* device = pcap_lookupdev(error_buffer);
    if (device == NULL)
    {
        std::cout << "Error finding device: " << error_buffer << std::endl;
        throw std::runtime_error(std::string("Error finding device: ") + error_buffer);
    }
    fDevice = device;
    int timeout_limit = 10000;
    fHandle = pcap_open_live(
            device,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );
    if (fHandle == NULL) {
        std::cout << "Could not open device " << device << ": " << error_buffer << std::endl;
        throw std::runtime_error(std::string("Could not open device: ") + error_buffer);
    }
    fOutputStream.open("output.csv");
    if(!fOutputStream.is_open())
    {
        std::cout << "Could not open file for writing: output.cs" << std::endl;
        throw std::runtime_error(std::string("Could not open file for writing: output.cs"));
    }
}

Packet::~Packet()
{
    fOutputStream.close();
}

void Packet::StartListening()
{
    pcap_loop(fHandle, 0, PacketHandler, NULL);
}

void Packet::PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    //TODO: parse relevant data from packet, like source and destination IP addresses
    WritePacket(packet, *header);
}

void Packet::WritePacket(const u_char *packet, struct pcap_pkthdr packet_header)
{
    fOutputStream << packet_header.caplen << "," << packet_header.len << "," << std::endl;
}

