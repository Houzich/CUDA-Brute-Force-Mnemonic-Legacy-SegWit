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
#include <stdint.h>
#include <string>
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

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include "stdafx.h"
#include "../Tools/utils.h"


class host_buffers_class
{
public:
	tableStruct tables_legacy[256] = { NULL };
	tableStruct tables_segwit[256] = { NULL };
	tableStruct tables_native_segwit[256] = { NULL };

	uint64_t* entropy = NULL;
	uint8_t* mnemonic = NULL;
	uint32_t* hash160 = NULL;

	retStruct* ret = NULL;

	uint64_t memory_size = 0;
public:
	host_buffers_class()
	{
	}

	int alignedMalloc(void** point, uint64_t size, uint64_t* all_ram_memory_size, std::string buff_name) {
		*point = _aligned_malloc(size, 4096);
		if (NULL == *point) { fprintf(stderr, "_aligned_malloc (%s) failed! Size: %s", buff_name.c_str(), tools::formatWithCommas(size).data()); return 1; }
		*all_ram_memory_size += size;
		//std::cout << "MALLOC RAM MEMORY SIZE (" << buff_name << "): " << std::to_string((float)size / (1024.0f * 1024.0f)) << " MB\n";
		return 0;
	}
	int mallocHost(void** point, uint64_t size, uint64_t* all_ram_memory_size, std::string buff_name) {
		if (cudaMallocHost((void**)point, size) != cudaSuccess) {
			fprintf(stderr, "cudaMallocHost (%s) failed! Size: %s", buff_name.c_str(), tools::formatWithCommas(size).data()); return -1;
		}
		*all_ram_memory_size += size;
		//std::cout << "MALLOC RAM MEMORY SIZE (" << buff_name << "): " << std::to_string((float)size / (1024.0f * 1024.0f)) << " MB\n";
		return 0;
	}
	int malloc(size_t size_entropy_buf, size_t size_mnemonic_buf, size_t size_hash160_buf)
	{
		memory_size = 0;
		if (mallocHost((void**)&entropy, size_entropy_buf, &memory_size, "entropy") != 0) return -1;
		if (alignedMalloc((void**)&mnemonic, size_mnemonic_buf, &memory_size, "mnemonic") != 0) return -1;
		if (alignedMalloc((void**)&hash160, size_hash160_buf, &memory_size, "hash160") != 0) return -1;
		if (mallocHost((void**)&ret, sizeof(retStruct), &memory_size, "ret") != 0) return -1;
		std::cout << "MALLOC ALL RAM MEMORY SIZE (HOST): " << std::to_string((float)memory_size / (1024.0f * 1024.0f)) << " MB\n";
		return 0;
	}
	void freeTableBuffers(void) {
		for (int x = 0; x < 256; x++) {
			if (tables_legacy[x].table != NULL)
			{
				free(tables_legacy[x].table);
				tables_legacy[x].table = NULL;
			}			
		}
		for (int x = 0; x < 256; x++) {
			if (tables_segwit[x].table != NULL)
			{
				free(tables_segwit[x].table);
				tables_segwit[x].table = NULL;
			}
		}
		for (int x = 0; x < 256; x++) {
			if (tables_native_segwit[x].table != NULL)
			{
				free(tables_native_segwit[x].table);
				tables_native_segwit[x].table = NULL;
			}
		}	
	}

	~host_buffers_class()
	{
		freeTableBuffers();
		cudaFreeHost(entropy);
		cudaFreeHost(ret);
		//for CPU
		_aligned_free(hash160);
		_aligned_free(mnemonic);

	}

};

class device_buffers_class
{
public:
	tableStruct tables_legacy[256] = { NULL };
	tableStruct* dev_tables_legacy;

	tableStruct tables_segwit[256] = { NULL };
	tableStruct* dev_tables_segwit;

	tableStruct tables_native_segwit[256] = { NULL };
	tableStruct* dev_tables_native_segwit;

	uint64_t* entropy = NULL;
	uint8_t* mnemonic = NULL;
	uint32_t* hash160 = NULL;
	retStruct* ret = NULL;


	uint64_t memory_size = 0;
public:
	device_buffers_class()
	{
	}
	int cudaMallocDevice(uint8_t** point, uint64_t size, uint64_t* all_gpu_memory_size, std::string buff_name) {
		//cudaError_t cudaStatus = cudaSuccess;
		if (cudaMalloc(point, size) != cudaSuccess) {
			fprintf(stderr, "cudaMalloc (%s) failed! Size: %s", buff_name.c_str(), tools::formatWithCommas(size).data()); return -1;
		}
		*all_gpu_memory_size += size;
		//std::cout << "MALLOC GPU MEMORY SIZE (" << buff_name << "): " << std::to_string((float)size / (1024.0f * 1024.0f)) << " MB\n";
		return 0;
	}
	int malloc(size_t size_entropy_buf, size_t size_mnemonic_buf, size_t size_hash160_bip44_buf, size_t num_wallet)
	{
		memory_size = 0;	
		if (cudaMallocDevice((uint8_t**)&entropy, size_entropy_buf, &memory_size, "entropy") != 0) return -1;
		if (cudaMallocDevice((uint8_t**)&mnemonic, size_mnemonic_buf, &memory_size, "mnemonic") != 0) return -1;
		if (cudaMallocDevice((uint8_t**)&hash160, size_hash160_bip44_buf, &memory_size, "hash160") != 0) return -1;
		if (cudaMallocDevice((uint8_t**)&dev_tables_legacy, sizeof(tableStruct) * 256, &memory_size, "dev_tables_legacy") != 0) return -1;
		if (cudaMallocDevice((uint8_t**)&dev_tables_segwit, sizeof(tableStruct) * 256, &memory_size, "dev_tables_segwit") != 0) return -1;
		if (cudaMallocDevice((uint8_t**)&dev_tables_native_segwit, sizeof(tableStruct) * 256, &memory_size, "dev_tables_native_segwit") != 0) return -1;
		if (cudaMallocDevice((uint8_t**)&ret, sizeof(retStruct), &memory_size, "ret") != 0) return -1;
		std::cout << "MALLOC ALL MEMORY SIZE (GPU): " << std::to_string((float)(memory_size) / (1024.0f * 1024.0f)) << " MB\n";
		return 0;
	}

	void freeTableBuffers(void) {
		for (int x = 0; x < 256; x++) {
			if (tables_legacy[x].table != NULL)
				cudaFree((void *)tables_legacy[x].table);
		}
		cudaFree(dev_tables_legacy);
		for (int x = 0; x < 256; x++) {
			if (dev_tables_segwit[x].table != NULL)
				cudaFree((void*)dev_tables_segwit[x].table);
		}
		cudaFree(dev_tables_segwit);
		for (int x = 0; x < 256; x++) {
			if (dev_tables_native_segwit[x].table != NULL)
				cudaFree((void*)dev_tables_native_segwit[x].table);
		}
		cudaFree(dev_tables_native_segwit);
	}

	~device_buffers_class()
	{
		freeTableBuffers();
		cudaFree(entropy);
		cudaFree(mnemonic);
		cudaFree(hash160);
		cudaFree(ret);
	}
};


class data_class
{
public:
	device_buffers_class dev;
	host_buffers_class host;

	cudaStream_t stream1 = NULL;
	size_t size_entropy_buf = 0;
	size_t size_mnemonic_buf = 0;
	size_t size_hash160_buf = 0;
	size_t wallets_in_round_gpu = 0;
	size_t num_paths = 0;
	size_t num_childs = 0;
	size_t num_all_childs = 0;
public:
	data_class()
	{

	}

	int malloc(size_t cuda_grid, size_t cuda_block, size_t num_paths, size_t num_childs, bool alloc_buff_for_save)
	{
		this->num_paths = num_paths;
		this->num_childs = num_childs;
		this->num_all_childs = num_paths * num_childs;

		size_t num_wallet = cuda_grid * cuda_block;
		size_t size_entropy_buf = sizeof(uint64_t) * 2;
		size_t size_mnemonic_buf = SIZE_MNEMONIC_FRAME * num_wallet;
		size_t size_hash160_buf = 20 * num_wallet * this->num_all_childs;
		if (!alloc_buff_for_save)
		{
			size_mnemonic_buf = 0;
			size_hash160_buf = 0;
		}


		if (cudaStreamCreate(&stream1) != cudaSuccess) { fprintf(stderr, "cudaStreamCreate failed!  stream1"); return -1; }
		if (dev.malloc(size_entropy_buf, size_mnemonic_buf, size_hash160_buf, num_wallet) != 0) return -1;
		if (host.malloc(size_entropy_buf, size_mnemonic_buf, size_hash160_buf) != 0) return -1;
		this->size_entropy_buf = size_entropy_buf;
		this->size_mnemonic_buf = size_mnemonic_buf;
		this->size_hash160_buf = size_hash160_buf;
		this->wallets_in_round_gpu = num_wallet;
		return 0;
	}
	~data_class()
	{
		cudaStreamDestroy(stream1);
	}
};

cudaError_t deviceSynchronize(std::string name_kernel);
void devicesInfo(void);

