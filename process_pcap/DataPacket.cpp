#include "DataPacket.h"
#include <iomanip>
/*
	* Data Point: Measurement of reflection for a single laser.
	*			(3 Bytes) - (2 bytes of distance) (unsigned int)
	*						(51.154 m - 102.308 m)
	*						(1 byte of reflectivity) (0-255)
	*			Distance 0 indicate non measurement.
	*
	* Elevation angle: Inferred from position of data point in data block.
	*
	* Azimuth angle: (2 bytes) Appear after flag bytes starting of a block.
	*				(unsigned int) (27742 - 277.42 degrees)
	*				(range; 0 to 35999)
	*
	* Data Block: Info of two firing sequence of 16 lasers. Each packet has
	*			  12 such blocks.
	*				(100 bytes) - (2 byte flag 0xffee), (2 byte azimuth)
	*								(32 data points - 96 bytes)
	*			Numbered from 0 to 11 in a data packet.
	*
	* Timestamp: (4 bytes) (32 bit unsigned int)
				(1st data point in 1st firing sequence of 1st data point)
				(Ranges from 0 to 3,599,999,999 microseconds in an hour)
				(Matched to UTC)

	Factory Bytes: (2 bytes) (Indicate how, azimuth and data point are organized in a packet).
					Return mode and product id info

	Data Packet is 1248 bytes long, 42 bytes of header, 1200 bytes of datablock, 4 bytes of timestamp, 2 bytes of FB.
*/


DataPacket::DataPacket(pcap_pkthdr* packet_header, const u_char* packet_data, u_int packet_counter, std::vector<uint16_t> &distance, std::vector<uint16_t> &intensity)
{
	this->packet_data = packet_data;
	this->packet_header = packet_header;
	this->packet_counter = packet_counter;

	this->packet_ts = packet_header->ts;
	this->packet_caplen = packet_header->caplen;

	if (packet_header->caplen < packet_header->len) {
		std::cout << "For packet " << packet_counter << " captured size is less than actual packet size by " << packet_header->caplen << " " << packet_header->len << std::endl;
	}
	this->process_data_packet(distance, intensity);
}

DataPacket::~DataPacket()
{
}

pcap_pkthdr* DataPacket::get_packet_header()
{
	return packet_header;
}

const u_char* DataPacket::get_packet_data()
{
	return packet_data;
}

u_int DataPacket::get_packet_counter() 
{
	return packet_counter;
}

void DataPacket::process_data_packet(std::vector<uint16_t> &distance, std::vector<uint16_t> &intensity) {
	
	// 0 to 41 bytes contain ethernet header, ipv4 header and udp header (no need to read them)
	u_int data_start_point = 42;
	for (u_int i = data_start_point; i < packet_caplen-8; i+=100) {	
		u_int block_id = (i - data_start_point) / 100;
		DataBlock db(packet_data, i, block_id, distance, intensity);
		datablock[block_id] = db;
	}

	// Time Stamp
	uint32_t time_stamp = ((packet_data[1245] << 24) | (packet_data[1244] << 16) | (packet_data[1243] << 8) | packet_data[1242]);
	this->time_stamp = time_stamp;
	std::cout <<this->packet_counter+1<< " Packet time stamp: " << time_stamp/(double)1000000 << std::endl;

	// Factory Bytes
	this->laser_return_byte = packet_data[1246];
	this->lidar_type_byte = packet_data[1247];
	
	if (this->laser_return_byte != 55) std::cerr << "laser return type is not the strongest" << std::endl;
	if (this->lidar_type_byte != 34) std::cerr << "lidar type is not VLP 16" << std::endl;
}

void DataPacket::fill_packet_headers() {

	// Ethernet II header
	u_int start = 0, size=6;
	memcpy(this->ethIIheader.destMac, packet_data + start, size);
	start += size;
	memcpy(this->ethIIheader.srcMac, packet_data + start, size);
	start += size;
	this->ethIIheader.ethertype = ((packet_data[start] << 8) | packet_data[start+1]);
	start += 2;

	// IPV4 header
	this->ipv4header.version = (packet_data[start] >> 4) & 0x0F;
	this->ipv4header.headerLength = (packet_data[start]) & 0x0F;
	start += 1;
	this->ipv4header.dscp = (packet_data[start] >> 2) & 0x3F;
	this->ipv4header.ecn = (packet_data[start]) & 0x03;
	start += 1; size = 2;
	this->ipv4header.totalLength = ((packet_data[start] << 8) | packet_data[start + 1]);
	start += size;
	this->ipv4header.identification = ((packet_data[start] << 8) | packet_data[start + 1]);
	start += size;
	this->ipv4header.flags = (packet_data[start] >> 5) & 0x1F;
	this->ipv4header.fragmentOffset = ((packet_data[start] & 0x1F) << 8) | (packet_data[start + 1]);
	start += size;
	this->ipv4header.ttl = packet_data[start];
	this->ipv4header.protocol = packet_data[start + 1];
	start += size;
	this->ipv4header.checksum = ((packet_data[start] << 8) | packet_data[start + 1]);
	start += size; size = 4;
	this->ipv4header.sourceIP = ((packet_data[start] << 24) | (packet_data[start + 1] << 16) | (packet_data[start + 2] << 8) | packet_data[start +3]);
	start += size;
	this->ipv4header.destIP = ((packet_data[start] << 24) | (packet_data[start + 1] << 16) | (packet_data[start + 2] << 8) | packet_data[start + 3]);
	start += size;

	// UDP header
	size = 2;
	this->updheader.srcPort = (packet_data[start] << 8) | packet_data[start + 1];
	start += size;
	this->updheader.destPort = (packet_data[start] << 8) | packet_data[start + 1];
	start += size;
	this->updheader.length = (packet_data[start] << 8) | packet_data[start + 1];
	start += size;
	this->updheader.checksum = (packet_data[start] << 8) | packet_data[start + 1];
	start += size;
}

void DataPacket::debug_packet_header()
{
	std::cout << "Packet Header of packet having counter: " << packet_counter << std::endl;
	std::cout << "caplen " << std::dec << packet_header->caplen << std::endl;
	std::cout << "actual length of packet " << std::dec << packet_header->len << std::endl;
	std::cout << "timestamp of packet " << std::dec << packet_header->ts.tv_sec << " sec after the hour " << packet_header->ts.tv_usec << " microseconds" << std::endl;

	fill_packet_headers();

	std::cout << "\nEthernet II header:" << std::endl;
	std::cout << "Destination MAC: ";
	for (int i = 0; i < 6; i++) {
		std::cout << std::hex << static_cast<int>(ethIIheader.destMac[i]) << " ";
	}
	std::cout << std::endl;
	std::cout << "Source MAC: ";
	for (int i = 0; i < 6; i++) {
		std::cout << std::hex << static_cast<int>(ethIIheader.srcMac[i]) << " ";
	}
	std::cout << std::endl;
	std::cout << "EtherType: " << std::hex << static_cast<int>(ethIIheader.ethertype) << std::endl;

	std::cout << "\nIPV4 Header:" << std::endl;
	std::cout << "Version: " << std::hex << static_cast<int>(ipv4header.version) << std::endl;
	std::cout << "Header Length: " << std::hex << static_cast<int>(ipv4header.headerLength) << std::endl;
	std::cout << "Differentiated Services Field (dscp): " << std::hex << static_cast<int>(ipv4header.dscp) << std::endl;
	std::cout << "Differentiated Services Field (ecn): " << std::hex << static_cast<int>(ipv4header.ecn) << std::endl;
	std::cout << "Total Length: " << std::dec << static_cast<int>(ipv4header.totalLength) << std::endl;
	std::cout << "Identification: " << std::hex << static_cast<int>(ipv4header.identification) << std::endl;
	std::cout << "flags: " << std::hex << static_cast<int>(ipv4header.flags) << std::endl;
	std::cout << "fragment offset: " << std::dec << static_cast<int>(ipv4header.fragmentOffset) << std::endl;
	std::cout << "Time to live: " << std::dec << static_cast<int>(ipv4header.ttl) << std::endl;
	std::cout << "protocol: " << std::dec << static_cast<int>(ipv4header.protocol) << std::endl;
	std::cout << "checksum: " << std::hex << static_cast<int>(ipv4header.checksum) << std::endl;
	std::cout << "Source IP Address: " << std::hex << static_cast<int>(ipv4header.sourceIP) << std::endl;
	std::cout << "Destination IP Address: " << std::hex << static_cast<int>(ipv4header.destIP) << std::endl;

	std::cout << "\nUDP Header:" << std::endl;
	std::cout << "Source Port: " << std::dec << static_cast<int>(updheader.srcPort) << std::endl;
	std::cout << "Destination Port: " << std::dec << static_cast<int>(updheader.destPort) << std::endl;
	std::cout << "Length of packet including udp header: " << std::dec << static_cast<int>(updheader.length) << std::endl;
	std::cout << "Checksum: " << std::hex << static_cast<int>(updheader.checksum) << std::endl;
	std::cout << "******************************************************************" << std::endl;
	std::cin.get();

}

void DataPacket::debug_packet_data() {
}
