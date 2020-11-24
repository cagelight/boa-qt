#include "boastuff.hpp"

#include <iostream>
#include <unordered_map>
#include <cmath>

#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/cipher_mode.h>

using namespace Botan;

static std::unordered_map<std::string, std::unique_ptr<HashFunction>> hash_func_map;
static std::unique_ptr<HashFunction> & get_hash_func(std::string const & text) {
	auto s = hash_func_map.find(text);
	if (s != hash_func_map.end()) return s->second;
	auto hf = HashFunction::create(text);
	if (!hf) throw std::runtime_error {"invalid hash function"};
	return hash_func_map[text] = std::move(hf);
}

typedef std::unique_ptr<Cipher_Mode> ucmp;
struct cryptor {
	cryptor() = default;
	cryptor(cryptor && other) : enc(std::move(other.enc)), dec(std::move(other.dec)) {}
	ucmp enc;
	ucmp dec;
	operator bool() {return enc && dec;}
};
static std::unordered_map<std::string, std::unique_ptr<cryptor>> cipher_map;
static std::unique_ptr<cryptor> & get_cipher(std::string const & text) {
	auto s = cipher_map.find(text);
	if (s != cipher_map.end()) return s->second;
	std::unique_ptr<cryptor> c {new cryptor};
	c->enc = ucmp(get_cipher_mode(text, ENCRYPTION));
	c->dec = ucmp(get_cipher_mode(text, DECRYPTION));
	if (!*c) throw std::runtime_error("invalid cipher");
	return cipher_map[text] = std::move(c);
}

boa::array boa::from_data(std::string const & key, std::string const & hash_func_name, std::string const & cipher_func_name, boa::binary_data const & dat) {
	array arr;
	
	if (dat.size() < 4) throw std::runtime_error("file too small to be a BOA file");
	std::vector<uint8_t> head {dat.begin(), dat.begin() + 3};
	std::vector<uint8_t> body {dat.begin() + 3, dat.end()};
	
	if (head[0] != 'B' || head[1] != 'O' || head[2] != 'A') throw std::runtime_error("not a BOA file, incorrect header");
	
	auto & hash_func = get_hash_func(hash_func_name);
	auto & cipher = get_cipher(cipher_func_name);
	
	secure_vector<uint8_t> hash_buf = hash_func->process(key);
	if (!cipher->dec->key_spec().valid_keylength(hash_func->output_length())) throw std::runtime_error("hash function does not produce valid key length");
	
	secure_vector<uint8_t> decvec {body.begin(), body.end()};
	
	try {
		cipher->dec->set_key(hash_buf);
		cipher->dec->start();
		cipher->dec->finish(decvec);
	} catch (...) {
		cipher->dec->clear();
		rethrow_exception(std::current_exception());
	}
	
	std::vector<uint8_t> raw_data {decvec.begin(), decvec.end()};
	
	int state = 0;
	long size = raw_data.size();
	entry cur_ent {};
	
	for (long index = 0; index < size; index++) {
		char cur = raw_data[index];
		if (!cur) {
			state++;
			if (state == 5) {
				state = 0;
				arr.push_back(cur_ent);
				cur_ent = {};
			}
			continue;
		}
		switch(state) {
			case 0:
				cur_ent.name += cur;
				break;
			case 1:
				cur_ent.username += cur;
				break;
			case 2:
				cur_ent.email += cur;
				break;
			case 3:
				cur_ent.password += cur;
				break;
			case 4:
				cur_ent.addinfo += cur;
				break;
		};
	}
	
	return arr;
}

boa::binary_data boa::to_data(std::string const & key, std::string const & hash_func_name, std::string const & cipher_func_name, boa::array & arr) {
	binary_data dat;
	
	auto & hash_func = get_hash_func(hash_func_name);
	auto & cipher = get_cipher(cipher_func_name);
	
	for (entry & e : arr) {
		for (char c : e.name) {
			dat.push_back(c);
		}
		dat.push_back(0);
		for (char c : e.username) {
			dat.push_back(c);
		}
		dat.push_back(0);
		for (char c : e.email) {
			dat.push_back(c);
		}
		dat.push_back(0);
		for (char c : e.password) {
			dat.push_back(c);
		}
		dat.push_back(0);
		for (char c : e.addinfo) {
			dat.push_back(c);
		}
		dat.push_back(0);
	}
	
	secure_vector<uint8_t> hash_buf = hash_func->process(key);
	if (!cipher->enc->key_spec().valid_keylength(hash_func->output_length())) throw std::runtime_error("hash function does not produce valid key length");
	
	secure_vector<uint8_t> encvec {dat.begin(), dat.end()};
	cipher->enc->set_key(hash_buf);
	cipher->enc->start();
	cipher->enc->finish(encvec);
	
	binary_data encdat {encvec.begin(), encvec.end()};
	binary_data output {'B', 'O', 'A'};
	output.insert(output.end(), encdat.begin(), encdat.end());
	return output;
}

static constexpr uint8_t hmask = 0b11110000;
static constexpr uint8_t lmask = 0b00001111;

std::string boa::hex(binary_data const & input) {
	std::string ret {};
	ret.reserve(input.size() * 2);
	for (uint8_t ch : input) {
		char vh = (ch & hmask) >> 4;
		char vl = ch & lmask;
		ret += vh > 9 ? 55 + vh : 48 + vh;
		ret += vl > 9 ? 55 + vl : 48 + vl;
	}
	return ret;
}

boa::binary_data boa::hash(std::string const & input, std::string const & hash_func_name) {
	auto & hash_func = get_hash_func(hash_func_name);
	auto dat = hash_func->process(input);
	return {dat.begin(), dat.end()};
}

std::string boa::keygen(uint32_t size, std::vector<char> pool) {
	AutoSeeded_RNG rng;
	std::string ret;
	for (uint32_t i = 0; i < size; i++) {
		auto v = rng.random_vec(4);
		uint32_t index = *reinterpret_cast<uint32_t const *>(v.data());
		index %= pool.size();
		ret += pool[index];
	}
	return ret;
}

void boa::cleanup() {
	hash_func_map.clear();
	cipher_map.clear();
}
