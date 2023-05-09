#pragma once
#include <cstddef>
//compute_86, sm_86

/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V2.0.0
  * @date		28-April-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */


//#define _CRT_SECURE_NO_WARNINGS
//#define TEST_MODE

#define NUM_WORDS_MNEMONIC					(12)
#define SIZE_MNEMONIC_FRAME					(128 * 2)
#define SIZE_HASH160_FRAME					(20)
#define NUM_ENTROPY_FRAME					(111)
#define SIZE_ENTROPY_FRAME					(sizeof(uint64_t) * 2 * NUM_ENTROPY_FRAME)
#define SIZE32_MNEMONIC_FRAME				(128 / 4)
#define SIZE32_HASH160_FRAME			    (20 / 4)
#define SIZE64_MNEMONIC_FRAME				(128 / 8)


#define NUM_PACKETS_SAVE_IN_FILE 8
#define FILE_PATH_RESULT "Save_Addresses.csv"
#define FILE_PATH_FOUND_ADDRESSES "Found_Addresses.csv"
#define FILE_PATH_FOUND_BYTES "Found_Bytes.csv"


struct tableStruct {
	unsigned int* table = NULL;
	unsigned int size = 0;
};

#define MAX_FOUND_ADDRESSES 5

#pragma pack(push, 1)
struct foundInfoStruct {
	unsigned int mnemonic[SIZE32_MNEMONIC_FRAME];
	unsigned int hash160[SIZE32_HASH160_FRAME];
	unsigned int path;
	unsigned int child;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct foundBytesInfoStruct {
	unsigned int mnemonic[SIZE32_MNEMONIC_FRAME];
	unsigned int hash160[SIZE32_HASH160_FRAME];
	unsigned int hash160_from_table[SIZE32_HASH160_FRAME];
	unsigned int path;
	unsigned int child;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct foundStruct {
	foundInfoStruct found_info[MAX_FOUND_ADDRESSES];
	foundBytesInfoStruct found_bytes_info[MAX_FOUND_ADDRESSES];
	unsigned int count_found;
	unsigned int count_found_bytes;
};
#pragma pack(pop)


#pragma pack(push, 1)
struct retStruct {
	foundStruct f[3];
};
#pragma pack(pop)