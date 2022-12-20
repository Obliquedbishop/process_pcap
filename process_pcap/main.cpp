#include <iostream>
#include "pcap.h"

using namespace std;

int main(int argc, char* argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    handle = pcap_open_offline("L:\\Projects\\process_pcap\\Resources\\pcap_files\\Coming_back_part_1.pcap", errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
        return -1; 
    }
    
    struct pcap_pkthdr* header;
    const u_char* packet;
    
    int result = pcap_next_ex(handle, &header, &packet);
    if (result == 1) {
        // Packet data and header are now stored in packet and header variables
    }
    else if (result == 0) {
        printf("End of file reached.\n");
    }
    else if (result == -1) {
        fprintf(stderr, "Error reading the packet: %s\n", pcap_geterr(handle));
    }
    
}