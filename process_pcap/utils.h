#pragma once

#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>

class utils 
{
public:
	static std::string ascii_to_hex(char);
	static int hex_to_int(std::string&);
};