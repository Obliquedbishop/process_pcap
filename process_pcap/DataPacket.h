#pragma once

#include "pcap.h"
#include "DataBlock.h"
#include <vector>
#include <iostream>
#include <string>

class DataPacket
{
private:
	DataPacket() {}

	pcap_pkthdr* packet_header{};
	const u_char* packet_data{};
	u_int packet_counter{};

	u_int packet_caplen{}; // Short for 'captured length', actual packet size captured, `len` is the total packet size.
	timeval packet_ts{};

	DataBlock datablock[12]; // A packet will contain 12 datablocks

	u_int time_stamp{};
	u_int laser_return_byte{};
	u_int lidar_type_byte{};

	void process_data_packet(std::vector<uint16_t>&, std::vector<uint16_t>&);

	struct EthernetIIHeader {
		uint8_t destMac[6];  // destination MAC address (6 bytes)
		uint8_t srcMac[6];   // source MAC address (6 bytes)
		uint16_t ethertype;  // Ethertype (2 bytes)
	};

	struct IPv4Header {
		uint8_t version;       // 4-bit field
		uint8_t headerLength;  // 4-bit field
		uint8_t dscp;          // 6-bit field
		uint8_t ecn;           // 2-bit field
		uint16_t totalLength;  // 16-bit field
		uint16_t identification;  // 16-bit field
		uint8_t flags;            // 3-bit field
		uint16_t fragmentOffset;  // 13-bit field
		uint8_t ttl;              // 8-bit field
		uint8_t protocol;         // 8-bit field
		uint16_t checksum;        // 16-bit field
		uint32_t sourceIP;        // 32-bit field
		uint32_t destIP;          // 32-bit field
	};

	struct UDPHeader {
		uint16_t srcPort;   // source port (2 bytes)
		uint16_t destPort;  // destination port (2 bytes)
		uint16_t length;    // length of the UDP header and data (2 bytes)
		uint16_t checksum;  // checksum (2 bytes)
	};

	void fill_packet_headers();

	EthernetIIHeader ethIIheader{};
	IPv4Header ipv4header{};
	UDPHeader updheader{};

public:
	DataPacket(pcap_pkthdr*, const u_char*, u_int, std::vector<uint16_t>&, std::vector<uint16_t>&);

	~DataPacket();

	pcap_pkthdr* get_packet_header();
	const u_char* get_packet_data();
	u_int get_packet_counter();
	
	void debug_packet_header();
	void debug_packet_data();
	//void process_packet();
};