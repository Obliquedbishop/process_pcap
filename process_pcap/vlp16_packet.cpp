#include "vlp16_packet.h"
#include "utils.h"

#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>

Packet::Packet(pcap_pkthdr* packet_header, const u_char* packet_data, u_int packet_counter)
{
	this->packet_data = packet_data;
	this->packet_header = packet_header;
	this->packet_counter = packet_counter;

	this->packet_ts = packet_header->ts;
	this->packet_caplen = packet_header->caplen;

	if (packet_header->caplen < packet_header->len) {
		std::cout << "For packet " << packet_counter << " captured size is less than actual packet size by " << packet_header->caplen << " " << packet_header->len << std::endl;
	}
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

double Packet::azimuth_calculation(char first_byte, char second_byte) {
	/*
	* step1: hex_first, hex_second
	* step2: concatenate hex_second, hex_first
	* step3: convert to int and divide by 100
	* Returns value in degrees.
	*/
	std::string hex_val = utils::ascii_to_hex(second_byte) + utils::ascii_to_hex(first_byte);
	return utils::hex_to_int(hex_val) / (double)100;
}

void Packet::debug_packet_data() {
	double packet_azimuth1 = azimuth_calculation(packet_data[44], packet_data[45]);
	std::cout << "Packet azimuth: " << packet_azimuth1 << std::endl;

	for (u_int i = 46; i < packet_caplen; i++) {
		u_int packet_data_int_val = packet_data[i];
		std::cout << "Bytes from starting: " << std::dec << i + 1 << " " << std::hex<< packet_data_int_val;
		std::cin.get();
	}

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

	Factory Bytes: (2 bytes) (Indicate how, azimuth and data point are					organized in a packet).
					Return mode and product id info

	Data Packet is 1248 bytes long, 42 bytes of header, 1200 bytes of					datablock, 4 bytes of timestamp, 2 bytes of FB.
	*/

	std::cin.get();
}
