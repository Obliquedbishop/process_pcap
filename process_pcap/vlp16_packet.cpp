#include "vlp16_packet.h"
#include <iostream>

Packet::Packet(pcap_pkthdr* packet_header, const u_char* packet_data, u_int packet_counter)
{
	this->packet_data = packet_data;
	this->packet_header = packet_header;
	this->packet_counter = packet_counter;
}

Packet::~Packet()
{
}

pcap_pkthdr* Packet::get_packet_header()
{
	return packet_header;
}

const u_char* Packet::get_packet_data()
{
	return packet_data;
}

u_int Packet::get_packet_counter() 
{
	return packet_counter;
}

void Packet::debug_packet_header()
{
	std::cout << "Packet Header of packet having counter: " << packet_counter << std::endl;
	std::cout << "caplen " << packet_header->caplen << std::endl;
	std::cout << "actual length of packet " << packet_header->len << std::endl;
	std::cout << "timestamp of packet " << packet_header->ts.tv_sec << " " << packet_header->ts.tv_usec << std::endl;
	std::cin.get();
}
