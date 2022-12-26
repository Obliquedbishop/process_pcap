#pragma once

#include "pcap.h"
#include <iostream>
#include <vector>
#include <string>

class DataBlock {

private:
	const u_char* block_data{};
	double block_azimuth{};
	u_int block_id{};
	u_int block_start_point{};
	
	void process_data_block(std::vector<uint16_t>&, std::vector<uint16_t>&);

public:
	// Dummy constructor
	DataBlock() {}

	DataBlock(const u_char* , u_int , u_int, std::vector<uint16_t>&, std::vector<uint16_t>&);
	//~DataBlock();

	const u_char* get_block_data();
	double get_block_azimuth();
	u_int get_block_id();

	void debug_data_block();
};