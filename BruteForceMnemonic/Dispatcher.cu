/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V1.2.0
  * @date		16-April-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */
#include <stdafx.h>

#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>
#include <string>
#include <memory>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <omp.h>



#include "Dispatcher.h"
#include "GPU.h"
#include "KernelStride.hpp"
#include "Helper.h"


#include "cuda_runtime.h"
#include "device_launch_parameters.h"


#include "../Tools/tools.h"
#include "../Tools/utils.h"
#include "../config/Config.hpp"
#include "../Tools/segwit_addr.h"






int Generate_Mnemonic(void)
{
	cudaError_t cudaStatus = cudaSuccess;

	ConfigClass Config;
	try {
		parse_config(&Config, "config.cfg");
	}
	catch (...) {
		for (;;)
			std::this_thread::sleep_for(std::chrono::seconds(30));
	}

	devicesInfo();
	// Choose which GPU to run on, change this on a multi-GPU system.
	uint32_t num_device = 0;
#ifndef TEST_MODE
	std::cout << "\n\nEnter number of device: ";
	std::cin >> num_device;
#endif //TEST_MODE
	cudaStatus = cudaSetDevice(num_device);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");
		return -1;
	}

	size_t num_wallets_gpu = Config.cuda_grid * Config.cuda_block;
	if (num_wallets_gpu < NUM_PACKETS_SAVE_IN_FILE)
	{
		std::cerr << "Error num_wallets_gpu < NUM_PACKETS_SAVE_IN_FILE!" << std::endl;
		return -1;
	}
	//18,446,744,073,709,551,615
	size_t number_of_addresses = 0;
	size_t count_save_data_in_file = 0;
	int num_bytes = 0;
	int err;
	std::cout << "\nNUM WALLETS IN PACKET GPU: " << tools::formatWithCommas(num_wallets_gpu) << std::endl << std::endl;
#ifndef TEST_MODE
	std::cout << "Max value: 18,000,000,000,000,000,000 (18000000000000000000)" << std::endl;
	std::cout << "Enter number of generate mnemonic: ";
	std::cin >> number_of_addresses;
	number_of_addresses = (((number_of_addresses - 1) / (num_wallets_gpu)+1) * (num_wallets_gpu));

	std::cout << "Enter num rounds save data in file: ";
	std::cin >> count_save_data_in_file;

	std::cout << "Enter num bytes for check 6...8: ";
	std::cin >> num_bytes;
	if (num_bytes != 0)
		if ((num_bytes < 6) || (num_bytes > 8)) {
			std::cout << "Error num bytes. Won't be used!" << std::endl;
			num_bytes = 0;
		}


#else
	//number_of_addresses = 18 000 000 000 000 000 000;
	number_of_addresses = ((((num_wallets_gpu * 1) - 1) / (num_wallets_gpu)+1) * (num_wallets_gpu));
	//bip44_test_str = "";
	num_bytes = 5;
	count_save_data_in_file = 2;
#endif //TEST_MODE

	data_class* Data = new data_class();
	stride_class* Stride = new stride_class(Data);
	std::cout << "READ TABLES! WAIT..." << std::endl;
	tools::clearFiles();
	if((Config.generate_path[0] != 0) || (Config.generate_path[1] != 0) || (Config.generate_path[2] != 0) || (Config.generate_path[3] != 0) || (Config.generate_path[4] != 0)
		|| (Config.generate_path[5] != 0))
	{
		std::cout << "READ TABLES LEGACY(BIP32, BIP44)..." << std::endl;
	err = tools::readAllTables(Data->host.tables_legacy, Config.folder_tables_legacy, "");
	if (err == -1) {
		std::cout << "Error readAllTables legacy!" << std::endl;
		goto Error;
	}
	}
	if ((Config.generate_path[6] != 0) || (Config.generate_path[7] != 0))
	{
		std::cout << "READ TABLES SEGWIT(BIP49)..." << std::endl;
		err = tools::readAllTables(Data->host.tables_segwit, Config.folder_tables_segwit, "");
		if (err == -1) {
			std::cout << "Error readAllTables segwit!" << std::endl;
			goto Error;
		}
	}
	if ((Config.generate_path[8] != 0) || (Config.generate_path[9] != 0))
	{
		std::cout << "READ TABLES NATIVE SEGWIT(BIP84)..." << std::endl;
		err = tools::readAllTables(Data->host.tables_native_segwit, Config.folder_tables_native_segwit, "");
		if (err == -1) {
			std::cout << "Error readAllTables native segwit!" << std::endl;
			goto Error;
		}
	}
	std::cout << std::endl << std::endl;

	if (Data->malloc(Config.cuda_grid, Config.cuda_block, Config.num_paths, Config.num_child_addresses, count_save_data_in_file == 0 ? false : true) != 0) {
		std::cout << "Error Data->malloc()!" << std::endl;
		goto Error;
	}

	if (Stride->init() != 0) {
		printf("Error INIT!!\n");
		goto Error;
	}

	Data->host.freeTableBuffers();

	std::cout << "START GENERATE ADDRESSES!" << std::endl;
	std::cout << "PATH: " << std::endl;
	if (Config.generate_path[0] != 0) std::cout << "m/0/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[1] != 0) std::cout << "m/1/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[2] != 0) std::cout << "m/0/0/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[3] != 0) std::cout << "m/0/1/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[4] != 0) std::cout << "m/44'/0'/0'/0/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[5] != 0) std::cout << "m/44'/0'/0'/1/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[6] != 0) std::cout << "m/49'/0'/0'/0/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[7] != 0) std::cout << "m/49'/0'/0'/1/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[8] != 0) std::cout << "m/84'/0'/0'/0/0.." << (Config.num_child_addresses - 1) << std::endl;
	if (Config.generate_path[9] != 0) std::cout << "m/84'/0'/0'/1/0.." << (Config.num_child_addresses - 1) << std::endl;
	std::cout << "\nGENERATE " << tools::formatWithCommas(number_of_addresses) << " MNEMONICS. " << tools::formatWithCommas(number_of_addresses * Data->num_all_childs) << " ADDRESSES. MNEMONICS IN ROUNDS " << tools::formatWithCommas(Data->wallets_in_round_gpu) << ". WAIT...\n\n";

	tools::generateRandomUint64Buffer(Data->host.entropy, Data->size_entropy_buf / (sizeof(uint64_t)));

	if (cudaMemcpyToSymbol(dev_num_bytes_find, &num_bytes, 4, 0, cudaMemcpyHostToDevice) != cudaSuccess)
	{
		fprintf(stderr, "cudaMemcpyToSymbol to num_bytes_find failed!");
		goto Error;
	}
	if (cudaMemcpyToSymbol(dev_generate_path, &Config.generate_path, sizeof(Config.generate_path), 0, cudaMemcpyHostToDevice) != cudaSuccess)
	{
		fprintf(stderr, "cudaMemcpyToSymbol to dev_generate_path failed!");
		goto Error;
	}
	if (cudaMemcpyToSymbol(dev_num_child, &Config.num_child_addresses, 4, 0, cudaMemcpyHostToDevice) != cudaSuccess)
	{
		fprintf(stderr, "cudaMemcpyToSymbol to dev_num_child failed!");
		goto Error;
	}
	if (cudaMemcpyToSymbol(dev_num_paths, &Config.num_paths, 4, 0, cudaMemcpyHostToDevice) != cudaSuccess)
	{
		fprintf(stderr, "cudaMemcpyToSymbol to dev_num_paths failed!");
		goto Error;
	}
	static int start_save = 0;
	for (uint64_t step = 0; step < number_of_addresses / (Data->wallets_in_round_gpu); step++)
	{
		tools::start_time();

		if (start_save < count_save_data_in_file) {
			if (Stride->start_for_save(Config.cuda_grid, Config.cuda_block) != 0) {
				printf("Error START!!\n");
				goto Error;
			}
		}
		else
		{
			if (Stride->start(Config.cuda_grid, Config.cuda_block) != 0) {
				printf("Error START!!\n");
				goto Error;
			}
		}


		tools::generateRandomUint64Buffer(Data->host.entropy, Data->size_entropy_buf / (sizeof(uint64_t)));
		if (start_save < count_save_data_in_file) {
			if (Stride->end_for_save() != 0) {
				printf("Error END!!\n");
				goto Error;
			}
		}
		else
		{
			if (Stride->end() != 0) {
				printf("Error END!!\n");
				goto Error;
			}
		}

		if (start_save < count_save_data_in_file) {
			start_save++;
			tools::saveResult((char*)Data->host.mnemonic, (uint8_t*)Data->host.hash160, Data->wallets_in_round_gpu, Data->num_all_childs, Data->num_childs, Config.generate_path);
		}

		tools::checkResult(Data->host.ret);

		float delay;
		tools::stop_time_and_calc(&delay);
		std::cout << "\rSPEED: " << std::setw(8) << std::fixed << tools::formatWithCommas((float)Data->wallets_in_round_gpu / (delay / 1000.0f)) << " MNEMONICS/SECOND AND "
			<< tools::formatWithCommas(((float)Data->wallets_in_round_gpu * Data->num_all_childs) / (delay / 1000.0f)) << " ADDRESSES/SECOND, ROUND: " << step;

	}
	std::cout << "\n\nEND!" << std::endl;

	// cudaDeviceReset must be called before exiting in order for profiling and
	// tracing tools such as Nsight and Visual Profiler to show complete traces.
	cudaStatus = cudaDeviceReset();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaDeviceReset failed!");
		return -1;
	}

	return 0;
Error:
	std::cout << "\n\nERROR!" << std::endl;
	// cudaDeviceReset must be called before exiting in order for profiling and
	// tracing tools such as Nsight and Visual Profiler to show complete traces.
	cudaStatus = cudaDeviceReset();
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaDeviceReset failed!");
		return -1;
	}

	return -1;
}







