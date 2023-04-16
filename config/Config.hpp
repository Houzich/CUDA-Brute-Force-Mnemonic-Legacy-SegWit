/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V1.2.0
  * @date		16-April-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */
#pragma once
#include <string>



struct ConfigClass
{
public:
	std::string folder_tables_legacy = "";
	std::string folder_tables_segwit = "";
	std::string folder_tables_native_segwit = "";

	uint64_t num_child_addresses = 0;

	std::string path_m0_x = "";
	std::string path_m1_x = "";
	std::string path_m0_0_x = "";
	std::string path_m0_1_x = "";
	std::string path_m44h_0h_0h_0_x = "";
	std::string path_m44h_0h_0h_1_x = "";
	std::string path_m49h_0h_0h_0_x = "";
	std::string path_m49h_0h_0h_1_x = "";
	std::string path_m84h_0h_0h_0_x = "";
	std::string path_m84h_0h_0h_1_x = "";

	uint32_t generate_path[10] = { 0 };
	uint32_t num_paths = 0;

	uint64_t cuda_grid = 0;
	uint64_t cuda_block = 0;
public:
	ConfigClass()
	{
	}
	~ConfigClass()
	{
	}
};


int parse_config(ConfigClass* config, std::string path);

