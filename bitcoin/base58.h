
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include <attributes.h>
#include <span.h>

#include <string>
#include <vector>

/**
 * Encode a byte span as a base58-encoded string
 */
std::string EncodeBase58(Span<const unsigned char> input);

/**
 * Decode a base58-encoded string (str) into a byte vector (vchRet).
 * return true if decoding is successful.
 */
[[nodiscard]] bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret_len);

/**
 * Encode a byte span into a base58-encoded string, including checksum
 */
std::string EncodeBase58Check(Span<const unsigned char> input);

/**
 * Decode a base58-encoded string (str) that includes a checksum into a byte
 * vector (vchRet), return true if decoding is successful
 */
[[nodiscard]] bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret_len);


int EncodeHashBIP49(const uint8_t* hash160, std::string& addr);

#endif // BITCOIN_BASE58_H
