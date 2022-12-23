#pragma once

#include "GlobalHeader.h"
#include "pcap.h"

class Packet
{
private:
	Packet() {}

	pcap_pkthdr* packet_header{};
	const u_char* packet_data{};
	u_int packet_counter{};

public:
	Packet(pcap_pkthdr*, const u_char*, u_int);

	~Packet();

	pcap_pkthdr* get_packet_header();
	const u_char* get_packet_data();
	u_int get_packet_counter();
	
	void debug_packet_header();
};