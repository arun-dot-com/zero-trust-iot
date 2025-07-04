#ifndef ZT_CERTIFICATE_H
#define ZT_CERTIFICATE_H

#include <string>
#include <ctime>
#include <unordered_set>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>

class CertificateAuthority {
public:
  CertificateAuthority();
  std::string SignIdentity(uint32_t nodeId, const std::string& role, time_t expiry);
  CryptoPP::RSA::PublicKey GetPublicKey() const;

private:
  CryptoPP::RSA::PrivateKey privateKey;
  CryptoPP::RSA::PublicKey publicKey;
};

class ZtPolicyEngineWithCert {
public:
  void SetCaPublicKey(CryptoPP::RSA::PublicKey pub);
  void Revoke(uint32_t nodeId);
  bool Authorize(uint32_t nodeId, const std::string& role, const std::string& certStr);

private:
  CryptoPP::RSA::PublicKey caPublicKey;
  std::unordered_set<uint32_t> revoke;
};

#endif // ZT_CERTIFICATE_H

