/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V1.2.0
  * @date		16-April-2023
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

	static uint32_t calcCurrPath(uint32_t* path)
	{
		uint32_t curr_path = 0;
		for (int num = 0; num < 10; num++)
		{
			if (path[num] != 0)
			{
				curr_path = num;
				path[num] = 0;
				return curr_path;
			}
		}
		return curr_path;
	}

	void saveResult(char* mnemonic, uint8_t* hash160, size_t num_wallets, size_t num_all_childs, size_t num_childs, uint32_t path_generate[10]) {
		std::ofstream out;
		for (int x = 0; x < NUM_PACKETS_SAVE_IN_FILE; x++) {
			static bool start_string = false;
			out.open(FILE_PATH_RESULT, std::ios::app);
			if (out.is_open())
			{
				#pragma omp parallel for 
				for (int i = x * (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE; i < (x * (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE + (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE); i++) {
					std::string addr;
					//std::string hash_str;
					std::stringstream ss;

					ss << (const char*)&mnemonic[SIZE_MNEMONIC_FRAME * i];
					uint32_t curr_path = 66;
					uint32_t path[10];
					for (int num = 0; num < 10; num++) path[num] = path_generate[num];

					for (int ii = 0; ii < num_all_childs; ii++) {
						uint8_t* hash = (uint8_t*)&hash160[(i * num_all_childs + ii) * 20];
						if(ii % num_childs == 0)
							curr_path = calcCurrPath(path);
						if (curr_path == 8 || curr_path == 9)
						{
							char address[42 + 1];
							segwit_addr_encode(address, "bc", 0, (const uint8_t*)hash, 20);
							addr = std::string(address);
							encodeAddressBase32((const uint8_t*)hash, addr);
						}
						else if (curr_path == 6 || curr_path == 7)
						{
							encodeAddressBIP49((const uint8_t*)hash, addr);
						}
						else
						{
							encodeAddressBase58((const uint8_t*)hash, addr);
						}
						ss << "," << addr;
					}
					ss << '\n';
					#pragma omp critical (SaveChilds)
									{
					out << ss.str();
									}
				}
			}
			else
			{
				printf("\n!!!ERROR create file %s!!!\n", FILE_PATH_RESULT);
			}
			out.close();
		}
	}
	void addFoundMnemonicInFile(std::string path, std::string mnemonic, std::string address) {
		std::ofstream out;
		std::string pth = path + ":";
		out.open(FILE_PATH_FOUND_ADDRESSES, std::ios::app);
		if (out.is_open())
		{
			std::time_t result = std::time(nullptr);
			out << mnemonic << ",address path " << pth << "," << address << "," << std::asctime(std::localtime(&result));
		}
		else
		{
			printf("\n!!!ERROR open file %s!!!\n", FILE_PATH_FOUND_ADDRESSES);
		}
		out.close();
	}

	void addInFileTest(std::string& path, std::string& mnemonic, std::string& hash160, std::string& hash160_in_table, std::string& addr, std::string& addr_in_table) {
		std::ofstream out;
		std::string pth = path + ":";
		out.open(FILE_PATH_FOUND_BYTES, std::ios::app);
		if (out.is_open())
		{
			const std::time_t now = std::time(nullptr);
			out << mnemonic << ",address path " << pth << "," << addr << "," << "address in table:," << addr_in_table << ",hash160 path " << pth << "," << hash160 << "hash160 in table:," << hash160_in_table << "," << std::asctime(std::localtime(&now));
		}
		else
		{
			printf("\n!!!ERROR open file %s!!!\n", FILE_PATH_FOUND_BYTES);
		}
		out.close();
	}

	std::string getPath(uint32_t path, uint32_t child)
	{
		std::stringstream ss;
		std::string pth = ""; 
		if (path == 0) ss << "m/0/" << child;
		if (path == 1) ss << "m/1/" << child;
		if (path == 2) ss << "m/0/0/" << child;
		if (path == 3) ss << "m/0/1/" << child;
		if (path == 4) ss << "m/44'/0'/0'/0/" << child;
		if (path == 5) ss << "m/44'/0'/0'/1/" << child;
		if (path == 6) ss << "m/49'/0'/0'/0/" << child;
		if (path == 7) ss << "m/49'/0'/0'/1/" << child;
		if (path == 8) ss << "m/84'/0'/0'/0/" << child;
		if (path == 9) ss << "m/84'/0'/0'/1/" << child;
		return ss.str();
	}




	int checkResult(retStruct* ret) {
		if (ret->f[0].found == 1)
		{
			std::string mnemonic_str = (const char*)ret->f[0].mnemonic;
			std::string addr;
			std::string path = getPath(ret->f[0].path, ret->f[0].child);
			tools::encodeAddressBase58((const uint8_t*)ret->f[0].hash160, addr);
			tools::addFoundMnemonicInFile(path, mnemonic_str, addr.c_str());
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
			std::cout << "!!!FOUND ADDRESS ("<< path <<"): " << mnemonic_str << ", " << addr << std::endl;
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";

		}
		if (ret->f[1].found == 1)
		{
			std::string mnemonic_str = (const char*)ret->f[1].mnemonic;
			std::string addr;
			std::string path = getPath(ret->f[1].path, ret->f[1].child);
			tools::encodeAddressBIP49((const uint8_t*)ret->f[1].hash160, addr);
			tools::addFoundMnemonicInFile(path, mnemonic_str, addr.c_str());
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
			std::cout << "!!!FOUND ADDRESS (" << path << "): " << mnemonic_str << ", " << addr << std::endl;
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";

		}
		if (ret->f[2].found == 1)
		{
			std::string mnemonic_str = (const char*)ret->f[2].mnemonic;
			std::string addr;
			std::string path = getPath(ret->f[2].path, ret->f[2].child);
			tools::encodeAddressBase32((const uint8_t*)ret->f[2].hash160, addr);
			tools::addFoundMnemonicInFile(path, mnemonic_str, addr.c_str());
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
			std::cout << "!!!FOUND ADDRESS (" << path << "): " << mnemonic_str << ", " << addr << std::endl;
			std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";

		}
		if (ret->f[0].found_bytes == 2)
		{
			int num_bytes = 0;
			uint32_t hash_reverse[5];
			tools::reverseHashUint32(ret->f[0].hash160_bytes_from_table, hash_reverse);
			for (int i = 0; i < 20; i++)
			{
				if (*(uint8_t*)((uint8_t*)ret->f[0].hash160_bytes + i) != *(uint8_t*)((uint8_t*)hash_reverse + i)) break;
				num_bytes++;
			}

			std::string hash160 = tools::bytesToHexString((const uint8_t*)ret->f[0].hash160_bytes, 20);
			std::string hash160_in_table = tools::bytesToHexString((const uint8_t*)hash_reverse, 20);
			std::string mnemonic_str = (const char*)ret->f[0].mnemonic_bytes;
			std::string addr;
			std::string addr_in_table;
			std::string path = getPath(ret->f[0].path, ret->f[0].child);
			tools::encodeAddressBase58((const uint8_t*)ret->f[0].hash160_bytes, addr);
			tools::encodeAddressBase58((const uint8_t*)hash_reverse, addr_in_table);
			std::cout << "\n!!!FOUND IN ADDRESS(HASH160) (" << path << ") EQUAL " << num_bytes << " BYTES: " << mnemonic_str << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << " \n";
			tools::addInFileTest(path, mnemonic_str, hash160, hash160_in_table, addr, addr_in_table);
		}

		if (ret->f[1].found_bytes == 2)
		{
			int num_bytes = 0;
			uint32_t hash_reverse[5];
			tools::reverseHashUint32(ret->f[1].hash160_bytes_from_table, hash_reverse);
			for (int i = 0; i < 20; i++)
			{
				if (*(uint8_t*)((uint8_t*)ret->f[1].hash160_bytes + i) != *(uint8_t*)((uint8_t*)hash_reverse + i)) break;
				num_bytes++;
			}
			std::string hash160 = tools::bytesToHexString((const uint8_t*)ret->f[1].hash160_bytes, 20);
			std::string hash160_in_table = tools::bytesToHexString((const uint8_t*)hash_reverse, 20);
			std::string mnemonic_str = (const char*)ret->f[1].mnemonic_bytes;;
			std::string addr;
			std::string addr_in_table;
			std::string path = getPath(ret->f[1].path, ret->f[1].child);
			tools::encodeAddressBIP49((const uint8_t*)ret->f[1].hash160_bytes, addr);
			tools::encodeAddressBIP49((const uint8_t*)hash_reverse, addr_in_table);
			std::cout << "\n!!!FOUND IN ADDRESS(HASH160) (" << path << ") EQUAL " << num_bytes << " BYTES: " << mnemonic_str << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << " \n";
			tools::addInFileTest(path, mnemonic_str, hash160, hash160_in_table, addr, addr_in_table);
		}

		if (ret->f[2].found_bytes == 2)
		{
			int num_bytes = 0;
			uint32_t hash_reverse[5];
			tools::reverseHashUint32(ret->f[2].hash160_bytes_from_table, hash_reverse);
			for (int i = 0; i < 20; i++)
			{
				if (*(uint8_t*)((uint8_t*)ret->f[2].hash160_bytes + i) != *(uint8_t*)((uint8_t*)hash_reverse + i)) break;
				num_bytes++;
			}
			std::string hash160 = tools::bytesToHexString((const uint8_t*)ret->f[2].hash160_bytes, 20);
			std::string hash160_in_table = tools::bytesToHexString((const uint8_t*)hash_reverse, 20);
			std::string mnemonic_str = (const char*)ret->f[2].mnemonic_bytes;;
			std::string addr;
			std::string addr_in_table;
			std::string path = getPath(ret->f[2].path, ret->f[2].child);
			tools::encodeAddressBase32((const uint8_t*)ret->f[2].hash160_bytes, addr);
			tools::encodeAddressBase32((const uint8_t*)hash_reverse, addr_in_table);
			std::cout << "\n!!!FOUND IN ADDRESS(HASH160) (" << path << ") EQUAL " << num_bytes << " BYTES: " << mnemonic_str << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << " \n";
			tools::addInFileTest(path, mnemonic_str, hash160, hash160_in_table, addr, addr_in_table);
		}
		return 0;
	}

}
