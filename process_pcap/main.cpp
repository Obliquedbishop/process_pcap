#include <iostream>
#include <string.h>

#include "pcap.h"
#include "GlobalHeader.h"
#include "DataPacket.h"

#include <vector>

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
    
    vector<uint16_t> distance;
    vector<uint16_t> intensity;


    while (result = pcap_next_ex(handle, &packet_header, &packet_data) > 0) {
        
        DataPacket pckt(packet_header, packet_data, packet_count, distance, intensity);
        //pckt.debug_packet_header();
        //cout << packet_count << endl;
        packet_count++;
        if (packet_count % 10000 == 0) {
            std::cout << packet_count << std::endl;
        }
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