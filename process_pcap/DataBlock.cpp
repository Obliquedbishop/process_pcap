#include "DataBlock.h"
#include "utils.h"

DataBlock::DataBlock(const u_char* block_data, u_int start_point, u_int block_id, std::vector<uint16_t>& distance, std::vector<uint16_t>& intensity)
{
	this->block_data = block_data;
	this->block_start_point = start_point;
	this->block_id = block_id;
	this->block_azimuth = ((block_data[block_start_point + 3] << 8) | block_data[block_start_point + 2]) / (double)100;
	this->process_data_block(distance, intensity);
}

const u_char* DataBlock::get_block_data()
{
	return this->block_data;
}

double DataBlock::get_block_azimuth()
{
	return this->block_azimuth;
}

u_int DataBlock::get_block_id()
{
	return this->block_id;
}

void DataBlock::debug_data_block()
{
}

void DataBlock::process_data_block(std::vector<uint16_t>& distance, std::vector<uint16_t>& intensity)
{
	//std::cout << "Block: " <<get_block_id() << std::endl;
	std::cout << "Block azimuth value: " << get_block_azimuth() << std::endl;
	for (u_int i = this->block_start_point + 4; i < this->block_start_point + 100; i += 3) 
	{
		distance.push_back(((block_data[i + 1] << 8) | (block_data[i]) * 2));
		intensity.push_back(block_data[i + 2]);
	}
	std::cin.get();
}
