#include "utils.h"

std::string utils::ascii_to_hex(char c)
{
	std::stringstream stream;
	stream << std::hex << std::setw(2) << std::setfill('0') << int(c);
	std::string val = stream.str();
	return val.substr(val.size() - 2);
}

int utils::hex_to_int(std::string& hex)
{
	return std::stoi(hex, nullptr, 16);
}
