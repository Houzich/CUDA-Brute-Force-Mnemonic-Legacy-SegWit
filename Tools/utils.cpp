/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V2.0.0
  * @date		28-April-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */
#include "../BruteForceMnemonic/stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <omp.h>
#include <iostream>

#include "base58.h"
#include "tools.h"
#include "utils.h"
#include "segwit_addr.h"

namespace tools {
	static LARGE_INTEGER performanceCountStart;
	static LARGE_INTEGER performanceCountStop;

	void start_time(void) {
		QueryPerformanceCounter(&performanceCountStart);
	}

	void stop_time(void) {
		QueryPerformanceCounter(&performanceCountStop);
	}

	void stop_time_and_calc_sec(float* delay) {
		stop_time();
		LARGE_INTEGER perfFrequency;
		QueryPerformanceFrequency(&perfFrequency);
		*delay = (double)(performanceCountStop.QuadPart - performanceCountStart.QuadPart) / (double)perfFrequency.QuadPart;
	}

	std::string formatWithCommas(double val)
	{
		uint64_t value = (uint64_t)val;
		std::stringstream ss;
		ss.imbue(std::locale("en_US.UTF-8"));
		ss << std::fixed << value;
		return ss.str();
	}

	std::string formatWithCommas(uint64_t value)
	{
		std::stringstream ss;
		ss.imbue(std::locale("en_US.UTF-8"));
		ss << std::fixed << value;
		return ss.str();
	}

	std::string formatPrefix(double val)
	{
		const std::string prefixes[5] = { "MEGA", "GIGA", "TERA", "PETA", "EXA" };
		const double prefix_multipliers[5] = { 1000000,1000000000,1000000000000,1000000000000000,1000000000000000000 };
		std::string prefix = "";
		for (int i = 4; i >= 0; i--)
		{
			if (val > prefix_multipliers[i])
			{
				val = (val / (double)prefix_multipliers[i]);
				prefix = prefixes[i];
			}
		}

		std::stringstream ss;
		ss.imbue(std::locale("en_US.UTF-8"));
		ss << std::fixed << val << " " << prefix;
		return ss.str();
	}

	std::vector<uint8_t> hexStringToVector(const std::string& source)
	{
		if (std::string::npos != source.find_first_not_of("0123456789ABCDEFabcdef"))
		{
			// you can throw exception here
			return {};
		}

		union
		{
			uint64_t binary;
			char byte[8];
		} value{};

		auto size = source.size(), offset = (size % 16);
		std::vector<uint8_t> binary{};
		binary.reserve((size + 1) / 2);

		if (offset)
		{
			value.binary = std::stoull(source.substr(0, offset), nullptr, 16);

			for (auto index = (offset + 1) / 2; index--; )
			{
				binary.emplace_back(value.byte[index]);
			}
		}

		for (; offset < size; offset += 16)
		{
			value.binary = std::stoull(source.substr(offset, 16), nullptr, 16);
			for (auto index = 8; index--; )
			{
				binary.emplace_back(value.byte[index]);
			}
		}

		return binary;
	}


	int hexStringToBytes(const std::string& source, uint8_t* bytes, int max_len)
	{
		int len = 0;
		if (std::string::npos != source.find_first_not_of("0123456789ABCDEFabcdef"))
		{
			// you can throw exception here
			return 1;
		}

		union
		{
			uint64_t binary;
			char byte[8];
		} value{};

		auto size = source.size(), offset = (size % 16);

		if (offset)
		{
			value.binary = std::stoull(source.substr(0, offset), nullptr, 16);

			for (auto index = (offset + 1) / 2; index--; )
			{
				if (++len > max_len) return 1;
				*(bytes++) = value.byte[index];
			}
		}

		for (; offset < size; offset += 16)
		{
			value.binary = std::stoull(source.substr(offset, 16), nullptr, 16);
			for (auto index = 8; index--; )
			{
				if (++len > max_len) return 1;
				*(bytes++) = value.byte[index];
			}
		}

		return 0;
	}


	std::string vectorToHexString(std::vector<uint8_t>& data)
	{
		std::stringstream ss;
		ss << std::hex << std::uppercase;
		for (int i = 0; i < data.size(); i++)
			ss << std::setw(2) << std::setfill('0') << (uint16_t)((uint16_t)data[i] & 0xff);
		const std::string hexstr = ss.str();

		return hexstr;
	}

	std::string byteToHexString(uint8_t data)
	{
		std::stringstream ss;
		ss << std::hex << std::uppercase;
		ss << std::setw(2) << std::setfill('0') << (uint16_t)((uint16_t)data & 0xff);
		const std::string hexstr = ss.str();

		return hexstr;
	}

	std::string bytesToHexString(const uint8_t* data, int len)
	{
		std::string hexstr = "";
		for (int i = 0; i < len; i++) {
			hexstr.append(byteToHexString(data[i]));
		}
		return hexstr;
	}


	int encodeAddressBase58(const std::string& hash160hex, std::string& addr)
	{
		std::vector<unsigned char> datastr = hexStringToVector(hash160hex);
		if (datastr.size() != 20) {
			std::cerr << "ERROR SIZE HEX STRING: \"" << hash160hex << "\", LEGHT: " << datastr.size() << " BYTES" << std::endl;
			return -1;
		}
		std::vector<unsigned char> hash160 = { 0 };
		hash160.insert(hash160.end(), datastr.begin(), datastr.end());

		addr = EncodeBase58Check(hash160);

		return 0;
	}

	int encodeAddressBase58(const uint8_t* hash160, std::string& addr)
	{
		std::vector<uint8_t> datastr(hash160, hash160 + 20);
		std::vector<unsigned char> v_hash160 = { 0 };
		v_hash160.insert(v_hash160.end(), datastr.begin(), datastr.end());

		addr = EncodeBase58Check(v_hash160);

		return 0;
	}

	int decodeAddressBase58(const std::string& addr, std::string& hash160hex)
	{
		std::vector<unsigned char> hash160;
		if (DecodeBase58Check(addr, hash160, (int)addr.size())) {
			if (hash160.size() != 21) {
				std::cerr << "ERROR HASH160. ADDRESS: \"" << addr << "\", HASH160 SIZE: " << hash160.size() << std::endl;
				return 1;
			}
			hash160hex = vectorToHexString(hash160);
			if (hash160hex.length() != 42) {
				std::cerr << "ERROR HASH160HEX: \"" << hash160hex << "\", HASH160HEX LENGHT: " << hash160hex.length() << std::endl;
				return 1;
			}
			hash160hex.erase(hash160hex.begin(), hash160hex.begin() + 2);

		}
		else
		{
			std::cerr << "ERROR DecodeBase58Check. LEGACY ADDRESS: \"" << addr << "\", LEGHT: " << addr.size() << std::endl;
			return 1;
		}

		return 0;
	}

	int decodeAddressBase58(const std::string& addr, uint8_t* hash160)
	{
		std::vector<unsigned char> v_hash160;

		if (DecodeBase58Check(addr, v_hash160, (int)addr.size())) {
			if (v_hash160.size() != 21) {
				std::cerr << "ERROR HASH160. ADDRESS: \"" << addr << "\", HASH160 SIZE: " << v_hash160.size() << std::endl;
			}
			for (int i = 1; i < 20 + 1; i++) {
				*(hash160++) = v_hash160[i];
			}

		}
		else
		{
			std::cerr << "ERROR DecodeBase58Check. LEGACY ADDRESS: \"" << addr << "\", ADDRESS LEGHT: " << addr.size() << std::endl;
		}

		return 0;
	}
	int encodeAddressBase32(const std::string& hash160hex, std::string& addr)
	{
		std::vector<unsigned char> datastr = hexStringToVector(hash160hex);
		if (datastr.size() != 20) {
			std::cerr << "ERROR SIZE HEX STRING: \"" << hash160hex << "\", LEGHT: " << datastr.size() << " BYTES" << std::endl;
			return -1;
		}

		char address[42 + 1];
		uint8_t hash[20];

		for (int i = 0; i < 20; i++) hash[i] = datastr[i];

		segwit_addr_encode(address, "bc", 0, (const uint8_t*)hash, 20);
		addr = std::string(address);

		return 0;
	}

	int encodeAddressBase32(const uint8_t* hash160, std::string& addr)
	{
		char address[42 + 1];
		segwit_addr_encode(address, "bc", 0, (const uint8_t*)hash160, 20);
		addr = std::string(address);
		return 0;
	}


	int decodeAddressBase32(const std::string& addr, std::string& hash160hex)
	{
		int witver = 0;
		uint8_t hash160[20];
		size_t hash160_len = sizeof(hash160);

		if (segwit_addr_decode(&witver, hash160, &hash160_len, "bc", addr.c_str()) == 1) {

			hash160hex = bytesToHexString(hash160, 20);
		}
		else
		{
			std::cerr << "ERROR decodeAddressBase32(). SEGWIT ADDRESS: \"" << addr << "\", ADDRESS LEGHT: " << addr.size() << std::endl;
			return 1;
		}

		return 0;
	}

	int decodeAddressBase32(const std::string& addr, uint8_t* bytes)
	{
		int witver = 0;
		uint8_t hash160[20];
		size_t hash160_len = sizeof(hash160);

		if (segwit_addr_decode(&witver, hash160, &hash160_len, "bc", addr.c_str()) == 1) {

			for (int i = 0; i < 20; i++) {
				*(bytes++) = hash160[i];
			}

		}
		else
		{
			std::cerr << "ERROR decodeAddressBase32(). SEGWIT ADDRESS: \"" << addr << "\", ADDRESS LEGHT: " << addr.size() << std::endl;
			return -1;
		}

		return 0;
	}



	int encodeAddressBIP49(const uint8_t* hash160, std::string& addr)
	{
		std::vector<unsigned char> v_hash160temp = { 0x05 };
		v_hash160temp.insert(v_hash160temp.end(), hash160, hash160 + 20);
		addr = EncodeBase58Check(v_hash160temp);
		return 0;
	}

	int encodeAddressBIP49(std::string str, uint16_t* words)
	{

		return 0;
	}

	


}
