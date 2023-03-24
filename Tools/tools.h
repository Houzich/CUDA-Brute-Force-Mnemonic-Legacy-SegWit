/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V1.0.0
  * @date		20-March-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */
#pragma once
#include <vector>
#include <string>
#include "../BruteForceMnemonic/stdafx.h"
namespace tools {

	void Generate_Random_LongWords_Byffer(uint64_t* buff, size_t len);
	int push_to_memory(uint8_t* addr_buff, std::vector<std::string>& lines, int max_len);
	int get_all_tables(tableStruct* tables, std::string path, std::string prefix);
	void Clear_Files(void);
	void Save_Result(char* mnemonic, uint8_t* hash160, size_t num_wallets);
	void Add_Found_Seed_In_File(std::string seed, const char* address);
	void Add_Hash_In_File_Test(std::string& seed_hexstr, std::string& hash160, std::string& hash160_in_table, int num_child, std::string& addr, std::string& addr_in_table, int out_bytes_equally);
	int Print_Save_Ret(retStruct* ret);
}