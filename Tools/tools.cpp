/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V1.0.0
  * @date		20-March-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */
#include "main.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <omp.h>
#include <set>
#include <random>
#include <fstream>
#include <filesystem>

#include "../BruteForceMnemonic/stdafx.h"
#include "tools.h"
#include "utils.h"
#include "base58.h"
#include "segwit_addr.h"




namespace tools {




	uint64_t getSeedForRandom()
	{
		std::random_device rd;
		return rd() * rd();
	}


	void generateRandomUint64Buffer(uint64_t* buff, size_t len) {
		uint64_t seed_random = getSeedForRandom();

		std::uniform_int_distribution<uint64_t> distr;
		std::mt19937_64 eng(seed_random);

		for (int i = 0; i < len; i++)
		{
			buff[i] = distr(eng);
		}

	}

	int pushToMemory(uint8_t* addr_buff, std::vector<std::string>& lines, int max_len) {
		int err = 0;
		for (int x = 0; x < lines.size(); x++) {
			const std::string line = lines[x];
			err = hexStringToBytes(line, &addr_buff[max_len * x], max_len);
			if (err != 0) {
				std::cerr << "\n!!!ERROR HASH160 TO BYTES: " << line << std::endl;
				return err;
			}
		}
		return err;
	}

	int readAllTables(tableStruct* tables, std::string path, std::string prefix)
	{
		int ret = 0;
		std::string num_tables;
		size_t all_lines = 0;
#pragma omp parallel for 
		for (int x = 0; x < 256; x++) {

			std::string table_name = byteToHexString(x);

			std::string file_path = path + "\\" + prefix + table_name + ".csv";

			std::ifstream inFile(file_path);
			int64_t cnt_lines = std::count(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>(), '\n');
			inFile.close();
			if (cnt_lines != 0) {
				tables[x].table = (uint32_t*)malloc(cnt_lines * 20);
				if (tables[x].table == NULL) {
					printf("Error: malloc failed to allocate buffers.Size %llu. From file %s\n", (unsigned long long int)(cnt_lines * 20), file_path.c_str());
					inFile.close();
					ret = -1;
					break;
				}
				tables[x].size = (uint32_t)_msize((void*)tables[x].table);
				memset((uint8_t*)tables[x].table, 0, cnt_lines * 20);
				inFile.open(file_path, std::ifstream::in);
				if (inFile.is_open())
				{
					std::vector<std::string> lines;
					std::string line;
					while (getline(inFile, line)) {
						lines.push_back(line);
					}

					ret = pushToMemory((uint8_t*)tables[x].table, lines, 20);
					if (ret != 0) {
						std::cerr << "\n!!!ERROR push_to_memory, file: " << file_path << std::endl;
						ret = -1;
						inFile.close();
						break;
					}

					if (cnt_lines != lines.size()) {
						std::cout << "cnt_lines != lines.size(): cnt_lines = " << cnt_lines << " lines.size() = " << lines.size() << std::endl;
					}
					inFile.close();
				}
				else
				{
					std::cerr << "\n!!!ERROR open file: " << file_path << std::endl;
					ret = -1;
					break;
				}
#pragma omp critical 
				{
					all_lines += cnt_lines;
					std::cout << "PROCESSED " << cnt_lines << " ROWS IN FILE " << file_path << "\r";
				}
			}
			else {
#pragma omp critical 
				{
					std::cout << "!!! WORNING !!! COUNT LINES IS 0, FILE " << file_path << std::endl;
				}
			}

		}


#ifdef	USE_REVERSE_64
#pragma omp parallel for 
		for (int i = 0; i < 256; i++) {
			if (table[i] == NULL) continue;
			size_t size = _msize((void*)table[i]) / 4;
			if (size == 0) continue;
			size_t addrs = size / 5;
			for (int x = 0; x < addrs; x++) {
				Reverse_Hash_64(&table[i][x * 5], &table[i][x * 5]);
			}

		}
#endif //USE_REVERSE
#ifdef	USE_REVERSE_32
#pragma omp parallel for 
		for (int i = 0; i < 256; i++) {
			size_t addrs = tables[i].size / 20;
			for (int x = 0; x < addrs; x++) {
				if (tables[i].table != NULL)
					reverseHashUint32(&tables[i].table[x * 5], &tables[i].table[x * 5]);
			}

		}
#endif //USE_REVERSE
		std::cout << "ALL ADDRESSES IN FILES " << all_lines << std::endl;
		std::cout << "MALLOC ALL RAM MEMORY SIZE (DATABASE): " << std::to_string((float)(all_lines * 20) / (1024.0f * 1024.0f * 1024.0f)) << " GB\n";
		return ret;
	}

	void clearFiles() {
		std::ofstream out;
		out.open(FILE_PATH_RESULT);
		out.close();
	}
#define NUM_PACKETS_SAVE_IN_FILE 16
	void saveResult(char* mnemonic, uint8_t* hash160, size_t num_wallets) {
		std::ofstream out;
		for (int x = 0; x < NUM_PACKETS_SAVE_IN_FILE; x++) {
			static bool start_string = false;
			out.open(FILE_PATH_RESULT, std::ios::app);
			if (out.is_open())
			{
				//#pragma omp parallel for 
				for (int i = x * (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE; i < (x * (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE + (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE); i++) {
					std::string addr;
					//std::string hash_str;
					std::stringstream ss;

					ss << (const char*)&mnemonic[SIZE_MNEMONIC_FRAME * i];
					for (int ii = 0; ii < NUM_ALL_CHILDS; ii++) {
						uint8_t* hash = (uint8_t*)&hash160[(i * NUM_ALL_CHILDS + ii) * 20];
						if (ii >= (NUM_ALL_CHILDS - (2 * NUM_CHILDS)))
						{
							char address[42 + 1];
							segwit_addr_encode(address, "bc", 0, (const uint8_t*)hash, 20);
							addr = std::string(address);
							encodeAddressBase32((const uint8_t*)hash, addr);
						}
						else
						{
							encodeAddressBase58((const uint8_t*)hash, addr);
						}
						ss << "," << addr;
					}
					ss << '\n';
					///#pragma omp critical (SaveChilds)
					//				{
					out << ss.str();
					//				}
				}
			}
			else
			{
				printf("\n!!!ERROR create file %s!!!\n", FILE_PATH_RESULT);
			}
			out.close();
		}
	}
	void addFoundMnemonicInFile(std::string mnemonic, const char* address) {
		std::ofstream out;
		out.open(FILE_PATH_FOUND_ADDRESSES, std::ios::app);
		if (out.is_open())
		{
			std::time_t result = std::time(nullptr);
			out << mnemonic << "," << (const char*)address << "," << std::asctime(std::localtime(&result));
		}
		else
		{
			printf("\n!!!ERROR open file %s!!!\n", FILE_PATH_FOUND_ADDRESSES);
		}
		out.close();
	}

	void addInFileTest(std::string& mnemonic, std::string& hash160, std::string& hash160_in_table, std::string& addr, std::string& addr_in_table) {
		std::ofstream out;
		out.open(FILE_PATH_FOUND_BYTES, std::ios::app);
		if (out.is_open())
		{
			const std::time_t now = std::time(nullptr);
			out << mnemonic << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << "," << std::asctime(std::localtime(&now));
		}
		else
		{
			printf("\n!!!ERROR open file %s!!!\n", FILE_PATH_FOUND_BYTES);
		}
		out.close();
	}

	int checkResult(retStruct* ret) {
		if (ret->found_legacy == 1)
		{
			std::string mnemonic_str = (const char*)ret->mnemonic_legacy_found;
			std::string addr;

			tools::encodeAddressBase58((const uint8_t*)ret->hash160_legacy_found, addr);
			tools::addFoundMnemonicInFile(mnemonic_str, addr.c_str());
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
			std::cout << "!!!FOUND LEGACY: " << mnemonic_str << ", " << addr << std::endl;
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";

		}
		if (ret->found_segwit == 1)
		{
			std::string mnemonic_str = (const char*)ret->mnemonic_segwit_found;
			std::string addr;
			tools::encodeAddressBase32((const uint8_t*)ret->hash160_segwit_found, addr);
			tools::addFoundMnemonicInFile(mnemonic_str, addr.c_str());
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
			std::cout << "!!!FOUND SEGWIT: " << mnemonic_str << ", " << addr << std::endl;
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";

		}
		if (ret->found_legacy_bytes == 2)
		{
			std::string hash160 = tools::bytesToHexString((const uint8_t*)ret->hash160_legacy_bytes_found, 20);
			uint32_t hash_reverse[5];
			tools::reverseHashUint32(ret->hash160_legacy_bytes_from_table, hash_reverse);
			std::string hash160_in_table = tools::bytesToHexString((const uint8_t*)hash_reverse, 20);
			std::string mnemonic_str = (const char*)ret->mnemonic_legacy_bytes_found;
			std::string addr;
			std::string addr_in_table;

			tools::encodeAddressBase58(hash160, addr);
			tools::encodeAddressBase58(hash160_in_table, addr_in_table);
			std::cout << "\n!!!FOUND LEGACY BYTES: " << mnemonic_str << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << " \n";
			tools::addInFileTest(mnemonic_str, hash160, hash160_in_table, addr, addr_in_table);
		}
		if (ret->found_segwit_bytes == 2)
		{
			std::string hash160 = tools::bytesToHexString((const uint8_t*)ret->hash160_segwit_bytes_found, 20);
			uint32_t hash_reverse[5];
			tools::reverseHashUint32(ret->hash160_segwit_bytes_from_table, hash_reverse);
			std::string hash160_in_table = tools::bytesToHexString((const uint8_t*)hash_reverse, 20);
			std::string mnemonic_str = (const char*)ret->mnemonic_segwit_bytes_found;
			std::string addr;
			std::string addr_in_table;

			tools::encodeAddressBase32(hash160, addr);
			tools::encodeAddressBase32(hash160_in_table, addr_in_table);
			std::cout << "\n!!!FOUND SEGWIT BYTES: " << mnemonic_str << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << " \n";
			tools::addInFileTest(mnemonic_str, hash160, hash160_in_table, addr, addr_in_table);
		}
		return 0;
	}

}
