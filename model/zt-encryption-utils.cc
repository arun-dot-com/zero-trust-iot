// zt-encryption-utils.cc

#include "ns3/zt-encryption-utils.h"
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

namespace ns3 {

using namespace CryptoPP;

std::string EncryptPayload(const std::string& data, const byte* key, std::string& ivOut) {
  AutoSeededRandomPool prng;
  byte iv[AES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));
  ivOut.assign((char*)iv, AES::BLOCKSIZE);

  std::string cipher;
  CBC_Mode<AES>::Encryption enc;
  enc.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

  StringSource(data, true,
    new StreamTransformationFilter(enc,
      new StringSink(cipher)
    )
  );

  return ivOut + cipher;  // prepend IV to ciphertext
}

std::string DecryptPayload(const std::string& cipher, const byte* key) {
  std::string iv = cipher.substr(0, AES::BLOCKSIZE);
  std::string actualCipher = cipher.substr(AES::BLOCKSIZE);

  std::string recovered;
  CBC_Mode<AES>::Decryption dec;
  dec.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, (const byte*)iv.data());

  StringSource(actualCipher, true,
    new StreamTransformationFilter(dec,
      new StringSink(recovered)
    )
  );

  return recovered;
}

// decode session key from hex to raw bytes
SecByteBlock HexDecodeKey(const std::string& hex) {
  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  StringSource(hex, true,
    new HexDecoder(new ArraySink(key, key.size())));
  return key;
}
std::vector<CryptoPP::byte> HexToBytes(const std::string& hex) {
  std::string decoded;
  CryptoPP::StringSource(hex, true,
    new CryptoPP::HexDecoder(
      new CryptoPP::StringSink(decoded)
    )
  );

  return std::vector<CryptoPP::byte>(decoded.begin(), decoded.end());
}

} // namespace ns3

