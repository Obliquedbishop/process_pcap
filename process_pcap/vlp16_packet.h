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

	u_int packet_caplen{}; // Short for 'captured length', actual packet size captured, `len` is the total packet size.
	timeval packet_ts{};

	static double azimuth_calculation(char, char);

public:
	Packet(pcap_pkthdr*, const u_char*, u_int);

	~Packet();

	pcap_pkthdr* get_packet_header();
	const u_char* get_packet_data();
	u_int get_packet_counter();
	
	void debug_packet_header();
	void debug_packet_data();
};