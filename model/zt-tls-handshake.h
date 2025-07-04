// zt-tls-handshake.h

#ifndef ZT_TLS_HANDSHAKE_H
#define ZT_TLS_HANDSHAKE_H

#include "ns3/object.h"
#include "ns3/node.h"
#include <map>
#include <string>
#include <functional>

namespace ns3 {

class ZtTlsHandshake : public Object {
public:
  static TypeId GetTypeId();
  ZtTlsHandshake();

  // Start a simulated TLS handshake, storing shared session keys for both nodes
  void StartHandshake(Ptr<Node> client, Ptr<Node> server, uint32_t clientId, uint32_t serverId);

  // Returns whether a session exists for a given peer
  bool HasSession(uint32_t peerId) const;

  // Get the encoded (hex) session key for a peer
  std::string GetSessionKey(uint32_t peerId) const;

  // Optionally inject external logging function
  void SetExternalLogger(std::function<void(std::string)> logger);

  // Optionally set a Zero Trust policy validator
  void SetPolicyValidator(std::function<bool(uint32_t, std::string)> validator);

private:
  void Log(const std::string& msg) const;

  std::map<uint32_t, std::string> m_sessionKeys;
  std::function<void(std::string)> m_logger;
  std::function<bool(uint32_t, std::string)> m_policyValidator;
};

} // namespace ns3

#endif // ZT_TLS_HANDSHAKE_H

