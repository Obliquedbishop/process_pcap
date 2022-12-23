#include <iostream>
#include <string.h>

#include "pcap.h"
#include "GlobalHeader.h"
#include "vlp16_packet.h"

using namespace std;

int main(int argc, char* argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* file_name = "L:\\Projects\\process_pcap\\Resources\\pcap_files\\Coming_back_part_1.pcap";

    // Opening a pcap file
    pcap_t* handle;
    handle = pcap_open_offline(file_name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
        return -1; 
    }

    // Reading the global header
    pcap_global_header global_header = get_global_header(file_name);

    // Reading the data packets
    struct pcap_pkthdr* packet_header;
    const u_char* packet_data;
    u_int packet_count = 0;
    int result = 0;
    
    while (result = pcap_next_ex(handle, &packet_header, &packet_data) > 0) {
        
        Packet pckt(packet_header, packet_data, packet_count);

        packet_count++;
    }
    
    
    if (result == 0) {
        cout << "End of file Reached" << endl;
        cout << packet_count << " packets parsed" << endl;
    }
    else if (result == -1) {
        fprintf(stderr, "Error reading the packet: %s\n", pcap_geterr(handle));
    }
    else {
        cerr << "Something broke" << endl;
    }
    cin.get();
}