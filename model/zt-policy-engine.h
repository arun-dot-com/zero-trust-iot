// === zt-policy-engine.h ===
#ifndef ZT_POLICY_ENGINE_H
#define ZT_POLICY_ENGINE_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <ns3/object.h>
#include <cryptopp/rsa.h>

using namespace CryptoPP;

namespace ns3 {

class ZtPolicyEngine : public Object {
public:
  static TypeId GetTypeId();
  void AddAuthorized(uint32_t nodeId, const std::string& role);
  bool Authorize(uint32_t nodeId, const std::string& role);
  void SetCaPublicKey(RSA::PublicKey pub);
  void Revoke(uint32_t nodeId);
  bool AuthorizeWithCert(uint32_t nodeId, const std::string& role, const std::string& certStr);

private:
  std::unordered_map<uint32_t, std::string> authTable;
  std::unordered_set<uint32_t> revoke;
  RSA::PublicKey caPublicKey;
};

} // namespace ns3

#endif // ZT_POLICY_ENGINE_H

