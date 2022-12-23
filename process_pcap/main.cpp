#include <iostream>
#include "pcap.h"
#include "GlobalHeader.h"
#include <string.h>

using namespace std;


void debug_packet_header(pcap_pkthdr* packet_header, int packet_count) {
    cout << "Packet Header of packet having count: " << packet_count << endl;
    cout << "caplen " << packet_header->caplen << endl;
    cout << "actual length of packet " << packet_header->len << endl;
    cout << "timestamp of packet " << packet_header->ts.tv_sec << " " << packet_header->ts.tv_usec << endl;
    cin.get();
}

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
    //print_global_header(global_header);

    // Reading the data packets
    struct pcap_pkthdr* packet_header;
    const u_char* packet_data;
    u_int packet_count = 0;
    int result = 0;
    
    while (result = pcap_next_ex(handle, &packet_header, &packet_data) > 0) {

        //debug_packet_header(packet_header, packet_count);

        // Carry all the processing on pcap_pkthdr and packet_data
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