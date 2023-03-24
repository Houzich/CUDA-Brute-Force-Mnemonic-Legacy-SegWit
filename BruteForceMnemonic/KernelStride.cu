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
#include <stdio.h>
#include <stdint.h>


#include "KernelStride.hpp"
#include "Helper.h"
#include <GPU.h>
#include "../Tools/utils.h"


int stride_class::bruteforce_mnemonic(uint64_t grid, uint64_t block) {
	gl_bruteforce_mnemonic << <(uint32_t)grid, (uint32_t)block, 0, dt->stream1 >> > (dt->dev.entropy, dt->dev.dev_tables_legacy, dt->dev.dev_tables_segwit, dt->dev.ret);
	//______________________________________________________________________________________________________________
	//gl_test_1 << <(uint32_t)grid, (uint32_t)block, 0, dt->stream1 >> > (
	//	dt->dev.entropy,
	//	dt->dev.mnemonic_buff,
	//	dt->dev.ipad_buff,
	//	dt->dev.opad_buff,
	//	dt->dev.seed_buff
	//	);
	//if (DeviceSynchronize("gl_test_1") != cudaSuccess) return -1;
	//for (int x = 1; x < 2048; x++)
	//gl_test_2 << <(uint32_t)grid, (uint32_t)block, 0, dt->stream1 >> > (
	//	dt->dev.ipad_buff,
	//	dt->dev.opad_buff,
	//	dt->dev.seed_buff
	//	);
	//if (DeviceSynchronize("gl_test_2") != cudaSuccess) return -1;
	//gl_test_3 << <(uint32_t)grid, (uint32_t)block, 0, dt->stream1 >> > (
	//	dt->dev.dev_tables_legacy,
	//	dt->dev.dev_tables_segwit,
	//	dt->dev.mnemonic_buff,
	//	dt->dev.ipad_buff,
	//	dt->dev.opad_buff,
	//	dt->dev.seed_buff,
	//	dt->dev.ret
	//	);
	//if (DeviceSynchronize("gl_test_3") != cudaSuccess) return -1;
	//______________________________________________________________________________________________________________
	return 0;
}

int stride_class::bruteforce_mnemonic_for_save(uint64_t grid, uint64_t block) {
	gl_bruteforce_mnemonic_for_save << <(uint32_t)grid, (uint32_t)block, 0, dt->stream1 >> > (dt->dev.entropy, dt->dev.dev_tables_legacy, dt->dev.dev_tables_segwit, dt->dev.ret, dt->dev.mnemonic, dt->dev.hash160);
	return 0;
}

int stride_class::memsetGlobalMnemonic()
{
	//if (DeviceSynchronize("cudaMemcpy table") != cudaSuccess) return -1;
	if (cudaMemcpyAsync(dt->dev.entropy, dt->host.entropy, dt->size_entropy_buf, cudaMemcpyHostToDevice, dt->stream1) != cudaSuccess) { fprintf(stderr, "cudaMemcpyAsync to Board->dev.entropy failed!"); return -1; }
	if (cudaMemsetAsync(dt->dev.ret, 0, sizeof(retStruct), dt->stream1) != cudaSuccess) { fprintf(stderr, "cudaMemset Board->dev.ret failed!"); return -1; }
	//______________________________________________________________________________________________________________
	//if (cudaMemsetAsync(dt->dev.mnemonic_buff, 0, dt->num_wallets_gpu * SIZE_MNEMONIC_FRAME, dt->stream1) != cudaSuccess) { fprintf(stderr, "cudaMemset Board->dev.mnemonic_buff failed!"); return -1; }
	//if (cudaMemsetAsync(dt->dev.seed_buff, 0, dt->num_wallets_gpu * 64, dt->stream1) != cudaSuccess) { fprintf(stderr, "cudaMemset Board->dev.seed_buff failed!"); return -1; }
	//______________________________________________________________________________________________________________
	return 0;
}

int stride_class::memsetGlobalMnemonicSave()
{
	if (cudaMemcpyAsync(dt->dev.entropy, dt->host.entropy, dt->size_entropy_buf, cudaMemcpyHostToDevice, dt->stream1) != cudaSuccess) { fprintf(stderr, "cudaMemcpyAsync to Board->dev.entropy failed!"); return -1; }
	if (cudaMemsetAsync(dt->dev.ret, 0, sizeof(retStruct), dt->stream1) != cudaSuccess) { fprintf(stderr, "cudaMemset Board->dev.ret failed!"); return -1; }
	return 0;
}

int stride_class::init()
{
	size_t memory_size = 0;
	for (int i = 0; i < 256; i++)
	{
		std::string name = "Table " + tools::byteToHexString(i);
		if (dt->dev.cudaMallocDevice((uint8_t**)&dt->dev.tables_legacy[i].table, dt->host.tables_legacy[i].size, &memory_size, name.c_str()) != 0)
		{
			std::cout << "Error cudaMallocDevice(), Board->dev.table_legacy[i]! i = " << i << std::endl;
			return -1;
		}
		dt->dev.tables_legacy[i].size = dt->host.tables_legacy[i].size;
		dt->dev.memory_size += dt->host.tables_legacy[i].size;
	}
	std::cout << "MALLOC MEMORY SIZE (TABLES LEGACY GPU): " << std::to_string((float)memory_size / (1024.0f * 1024.0f)) << " MB\n";
	memory_size = 0;
	for (int i = 0; i < 256; i++)
	{
		std::string name = "Table " + tools::byteToHexString(i);
		if (dt->dev.cudaMallocDevice((uint8_t**)&dt->dev.tables_segwit[i].table, dt->host.tables_segwit[i].size, &memory_size, name.c_str()) != 0)
		{
			std::cout << "Error cudaMallocDevice(), Board->dev.table_segwit[i]! i = " << i << std::endl;
			return -1;
		}
		dt->dev.tables_segwit[i].size = dt->host.tables_segwit[i].size;
		dt->dev.memory_size += dt->host.tables_segwit[i].size;
	}
	std::cout << "MALLOC MEMORY SIZE (TABLES SEGWIT GPU): " << std::to_string((float)memory_size / (1024.0f * 1024.0f)) << " MB\n";


	std::cout << "INIT GPU ... \n";
	for (int i = 0; i < 256; i++)
	{
		if (cudaMemcpy((void*)dt->dev.tables_legacy[i].table, dt->host.tables_legacy[i].table, dt->host.tables_legacy[i].size, cudaMemcpyHostToDevice) != cudaSuccess)
		{
			std::cout << "cudaMemcpy to Board->dev.table_legacy[i] failed! i = " << i << std::endl;
			return -1;
		}
		const size_t percentDone = (i * 100 / 256) / 2;
		std::cout << "  " << percentDone << "%\r";
	}
	if (cudaMemcpy(dt->dev.dev_tables_legacy, dt->dev.tables_legacy, 256 * sizeof(tableStruct), cudaMemcpyHostToDevice) != cudaSuccess) { fprintf(stderr, "cudaMemcpyAsync to Board->dev.table_legacy failed!"); return -1; }

	for (int i = 0; i < 256; i++)
	{
		if (cudaMemcpy((void*)dt->dev.tables_segwit[i].table, dt->host.tables_segwit[i].table, dt->host.tables_segwit[i].size, cudaMemcpyHostToDevice) != cudaSuccess)
		{
			std::cout << "cudaMemcpy to Board->dev.table_segwit[i] failed! i = " << i << std::endl;
			return -1;
		}
		const size_t percentDone = 50 + (i * 100 / 256) / 2;
		std::cout << "  " << percentDone << "%\r";
	}
	if (cudaMemcpy(dt->dev.dev_tables_segwit, dt->dev.tables_segwit, 256 * sizeof(tableStruct), cudaMemcpyHostToDevice) != cudaSuccess) { fprintf(stderr, "cudaMemcpyAsync to Board->dev.table_segwit failed!"); return -1; }
	if (deviceSynchronize("init") != cudaSuccess) return -1;
	return 0;
}

int stride_class::start_for_save(uint64_t grid, uint64_t block)
{
	if (memsetGlobalMnemonicSave() != 0) return -1;
	if (bruteforce_mnemonic_for_save(grid, block) != 0) return -1;

	return 0;
}

int stride_class::start(uint64_t grid, uint64_t block)
{
	if (memsetGlobalMnemonic() != 0) return -1;
	if (bruteforce_mnemonic(grid, block) != 0) return -1;

	return 0;
}

int stride_class::end()
{
	cudaError_t cudaStatus = cudaSuccess;
	if (deviceSynchronize("end") != cudaSuccess) return -1; //????
	cudaStatus = cudaMemcpy(dt->host.ret, dt->dev.ret, sizeof(retStruct), cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy ret failed!");
		return -1;
	}

	return 0;
}

int stride_class::end_for_save()
{
	cudaError_t cudaStatus = cudaSuccess;


	if (deviceSynchronize("end_for_save") != cudaSuccess) return -1; //????
	cudaStatus = cudaMemcpy(dt->host.mnemonic, dt->dev.mnemonic, dt->size_mnemonic_buf, cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy mnemonic failed!");
		return -1;
	}
	cudaStatus = cudaMemcpy(dt->host.hash160, dt->dev.hash160, dt->size_hash160_bip44_buf, cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy hash160 failed!");
		return -1;
	}
	cudaStatus = cudaMemcpy(dt->host.ret, dt->dev.ret, sizeof(retStruct), cudaMemcpyDeviceToHost);
	if (cudaStatus != cudaSuccess) {
		fprintf(stderr, "cudaMemcpy ret failed!");
		return -1;
	}

	return 0;
}