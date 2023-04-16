#pragma once
//compute_86, sm_86

/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V1.2.0
  * @date		16-April-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */


//#define _CRT_SECURE_NO_WARNINGS
//#define TEST_MODE


#define SIZE_MNEMONIC_FRAME					(128ULL)
#define SIZE_HASH160_FRAME					(20ULL)
#define SIZE32_MNEMONIC_FRAME				(128ULL / 4ULL)
#define SIZE32_HASH160_FRAME			    (20ULL / 4ULL)
#define SIZE64_MNEMONIC_FRAME				(128ULL / 8ULL)

//#define USE_REVERSE_64
#define USE_REVERSE_32

#define NUM_PACKETS_SAVE_IN_FILE 8
#define FILE_PATH_RESULT "Save_Addresses.csv"
#define FILE_PATH_FOUND_ADDRESSES "Found_Addresses.csv"
#define FILE_PATH_FOUND_BYTES "Found_Bytes.csv"




/* Four of six logical functions used in SHA-384 and SHA-512: */
#define REVERSE32_FOR_HASH(w,x)	{ \
	uint32_t tmp = (w); \
	tmp = (tmp >> 16) | (tmp << 16); \
	(x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
}
#define REVERSE64_FOR_HASH(w,x)	{ \
	uint64_t tmp = (w); \
	tmp = (tmp >> 32) | (tmp << 32); \
	tmp = ((tmp & 0xff00ff00ff00ff00UL) >> 8) | \
	      ((tmp & 0x00ff00ff00ff00ffUL) << 8); \
	(x) = ((tmp & 0xffff0000ffff0000UL) >> 16) | \
	      ((tmp & 0x0000ffff0000ffffUL) << 16); \
}

struct tableStruct {
	unsigned int* table;
	unsigned int size;
};
#pragma pack(push, 1)
struct foundStruct {
	unsigned int mnemonic[SIZE32_MNEMONIC_FRAME];
	unsigned int mnemonic_bytes[SIZE32_MNEMONIC_FRAME];
	unsigned int hash160[SIZE32_HASH160_FRAME];
	unsigned int hash160_bytes[SIZE32_HASH160_FRAME];
	unsigned int hash160_bytes_from_table[SIZE32_HASH160_FRAME];
	unsigned int found;
	unsigned int found_bytes;
	unsigned int path;
	unsigned int child;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct retStruct {
	foundStruct f[3];
};
#pragma pack(pop)