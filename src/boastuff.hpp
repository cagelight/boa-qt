#pragma once

#include <string>
#include <vector>

namespace boa {
	
	struct entry {
		std::string name;
		std::string email;
		std::string username;
		std::string password;
		std::string addinfo;
	};
	
	typedef std::vector<entry> array;
	typedef std::vector<uint8_t> binary_data;
	
	array from_data(std::string const & key, std::string const & hash_func, std::string const & cipher_func, binary_data const &);
	binary_data to_data(std::string const & key, std::string const & hash_func, std::string const & cipher_func, array &);
	
	std::string hex(binary_data const &);
	binary_data hash(std::string const & input, std::string const & hash_func);
	std::string keygen(uint32_t size, std::vector<char> pool);
	
	void cleanup();
}



