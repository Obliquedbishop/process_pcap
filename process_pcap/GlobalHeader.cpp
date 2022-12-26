#include <iostream>
#include <fstream>
#include "GlobalHeader.h"


pcap_global_header get_global_header(const char* file_name) {

    // Opening the PCAP file
    std::ifstream pcap_file(file_name, std::ios::binary);
    if (!pcap_file) {
        std::cerr << "The file location is incorrect" << std::endl;
    }

    pcap_global_header global_header;

    // Read the global header to a buffer
    char* buffer = new char[sizeof(pcap_global_header)];


    pcap_file.read(buffer, sizeof(buffer));
    if (pcap_file.fail()) {
        std::cerr << "The global header is corrupted" << std::endl;
    }
    pcap_file.close();

    std::memcpy(&global_header, buffer, sizeof(pcap_global_header));

    return (global_header);
}

void print_global_header(pcap_global_header global_header) {
    std::cout << "magic number: " << std::hex << global_header.magic_number << std::endl;
    std::cout << "network: " << std::hex << global_header.network << std::endl;
    std::cout << "accuracy of timestamp: " << std::hex << global_header.sigfigs << std::endl;
    std::cout << "Max length of captured packet (octet): " << std::hex << global_header.snaplen << std::endl;
    std::cout << "GMT to local correction: " << std::hex << global_header.thiszone << std::endl;
    std::cout << "Major version number: " << std::hex << global_header.version_major << std::endl;
    std::cout << "Minor version number: " << std::hex << global_header.version_minor << std::endl;
}

