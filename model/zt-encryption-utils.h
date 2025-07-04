// zt-encryption-utils.h
#ifndef ZT_ENCRYPTION_UTILS_H
#define ZT_ENCRYPTION_UTILS_H

#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/config.h> 

namespace ns3 {

std::string EncryptPayload(const std::string& data, const CryptoPP::byte* key, std::string& ivOut);
std::string DecryptPayload(const std::string& cipher, const CryptoPP::byte* key);

CryptoPP::SecByteBlock HexDecodeKey(const std::string& hex);
std::vector<CryptoPP::byte> HexToBytes(const std::string& hex);

} // namespace ns3

#endif // ZT_ENCRYPTION_UTILS_H

