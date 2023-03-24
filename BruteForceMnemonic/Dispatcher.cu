/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V1.0.0
  * @date		20-March-2023
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



uint64_t number_of_addresses_generate = 0;
int num_bytes = 0;




int Generate_Mnemonic_And_Hash(void)
{
	cudaError_t cudaStatus = cudaSuccess;

	ConfigClass config;
	parse_gonfig(&config, "config.cfg");

	devicesInfo();
	// Choose which GPU to run on, change this on a multi-GPU system.
	uint32_t num_device = 0;
#ifndef GENERATE_INFINITY
	std::cout << "\n\nEnter number of device: ";
	std::cin >> num_device;
#endif //GENERATE_INFINITY
	cudaStatus = cudaSetDevice(num_device);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaSetDevice failed!  Do you have a CUDA-capable GPU installed?");
		return -1;
	}

	size_t num_wallets_gpu = config.cuda_grid * config.cuda_block;

	tools::Clear_Files();
	//18,446,744,073,709,551,615
	uint64_t number_of_addresses = 0;
	int count_save_data_in_file = 0;

	std::cout << "\nNUM WALLETS IN PACKET GPU: " << tools::formatWithCommas(num_wallets_gpu) << std::endl << std::endl;
#ifndef GENERATE_INFINITY
	std::cout << "Max value: 18,000,000,000,000,000,000 (18000000000000000000)" << std::endl;
	std::cout << "Enter number of seeds: ";
	std::cin >> number_of_addresses;
	number_of_addresses = (((number_of_addresses - 1) / (num_wallets_gpu)+1) * (num_wallets_gpu));

	std::cout << "Enter num cycles save data in file: ";
	std::cin >> count_save_data_in_file;

	std::cout << "!!!FOR TEST!!! Enter num bytes for check 5...8: ";
	std::cin >> num_bytes;
	if (num_bytes != 0)
		if ((num_bytes < 5) || (num_bytes > 8)) {
			std::cout << "Error num bytes. Won't be used!" << std::endl;
			num_bytes = 0;
		}


#else
	//number_of_addresses = 18 000 000 000 000 000 000;
	number_of_addresses = ((((num_wallets_gpu * 10) - 1) / (num_wallets_gpu)+1) * (num_wallets_gpu));
	//bip44_test_str = "";
	num_bytes = 0;
	count_save_data_in_file = 0;
#endif //GENERATE_INFINITY

	data_class* Board = new data_class();
	stride_class* Stride = new stride_class(Board);

#ifdef GENERATE_SEGWIT
	int err = tools::get_all_tables(Board->host.tables_segwit, config.folder_database_segwit, config.prefix_database_segwit);
	if (err == -1) {
		std::cout << "Error get_all_tables segwit!" << std::endl;
		goto Error;
	}
#elif defined (GENERATE_LEGACY_AND_SEGWIT)
	int err = tools::get_all_tables(Board->host.tables_legacy, config.folder_database_legacy, config.prefix_database_legacy);
	if (err == -1) {
		std::cout << "Error get_all_tables legacy!" << std::endl;
		goto Error;
	}
	err = tools::get_all_tables(Board->host.tables_segwit, config.folder_database_segwit, config.prefix_database_segwit);
	if (err == -1) {
		std::cout << "Error get_all_tables segwit!" << std::endl;
		goto Error;
	}
#endif //GENERATE_BIP32


	if (Board->Malloc(config.cuda_grid, config.cuda_block, count_save_data_in_file == 0 ? false : true) != 0) {
		std::cout << "Error Board->Malloc()!" << std::endl;
		goto Error;
	}

	if (Stride->init() != 0) {
		printf("Error INIT!!\n");
		goto Error;
	}

	Board->host.free_table_buffers();

	std::cout << "START GENERATE ADDRESSES!" << std::endl;
	std::cout << "\nGENERATE " << tools::formatWithCommas(number_of_addresses) << " SEDDS. " << tools::formatWithCommas(number_of_addresses * NUM_ALL_CHILDS) << " CHILD ADDRESSES. PACKET " << tools::formatWithCommas(Board->num_wallets_gpu) << ". WAIT...\n\n";

	tools::Generate_Random_LongWords_Byffer(Board->host.entropy, Board->size_entropy_buf / (sizeof(uint64_t)));


	//for (uint64_t i = 0; i < 256; i++)
	//{
	//	if (cudaMemcpyToSymbol(bip84_tables[i], Board->host.table[i], Board->host.table_size[i], 0, cudaMemcpyHostToDevice) != cudaSuccess)
	//	{
	//		fprintf(stderr, "cudaMemcpyToSymbol to tables[256] failed! i = %d", i);
	//		goto Error;
	//	}
	//}

	//std::cout << "tables_pionts size: " << sizeof(host_buffers_class::tables_points) << std::endl;

	//if (cudaMemcpyToSymbol(bip84_table_size, Board->host.table_size, sizeof(host_buffers_class::table_size), 0, cudaMemcpyHostToDevice) != cudaSuccess)
	//{
	//	fprintf(stderr, "cudaMemcpyToSymbol to table_size[256] failed!");
	//	goto Error;
	//}




	if (cudaMemcpyToSymbol(num_bytes_find, &num_bytes, 4, 0, cudaMemcpyHostToDevice) != cudaSuccess)
	{
		fprintf(stderr, "cudaMemcpyToSymbol to num_bytes_find failed!");
		goto Error;
	}


	static int start_save = 0;
	for (uint64_t step = 0; step < number_of_addresses / (Board->num_wallets_gpu); step++)
	{
		tools::start_time();

		number_of_addresses_generate = (step + 1) * (Board->num_wallets_gpu);
		if (start_save < count_save_data_in_file) {
			if (Stride->start_for_save(config.cuda_grid, config.cuda_block) != 0) {
				printf("Error START!!\n");
				goto Error;
			}
		}
		else
		{
			if (Stride->start(config.cuda_grid, config.cuda_block) != 0) {
				printf("Error START!!\n");
				goto Error;
			}
		}


		tools::Generate_Random_LongWords_Byffer(Board->host.entropy, Board->size_entropy_buf / (sizeof(uint64_t)));
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
			tools::Save_Result((char*)Board->host.mnemonic, (uint8_t*)Board->host.hash160, Board->num_wallets_gpu);
		}

		tools::Print_Save_Ret(Board->host.ret);

		float delay;
		tools::stop_time_and_calc(&delay);
		std::cout << "\rSPEED: " << std::setw(8) << std::fixed << tools::formatWithCommas((float)Board->num_wallets_gpu / (delay / 1000.0f)) << " SEEDS AND "
			<< tools::formatWithCommas(((float)Board->num_wallets_gpu * NUM_ALL_CHILDS) / (delay / 1000.0f)) << " ADDRESSES PER SECOND, ROUND: " << step;

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







