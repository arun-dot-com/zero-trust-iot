// zt-tls-handshake.cc

#include "zt-tls-handshake.h"
#include "ns3/log.h"
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h> 

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("ZtTlsHandshake");

TypeId ZtTlsHandshake::GetTypeId() {
  static TypeId tid = TypeId("ns3::ZtTlsHandshake")
    .SetParent<Object>()
    .SetGroupName("ZeroTrust")
    .AddConstructor<ZtTlsHandshake>();
  return tid;
}

ZtTlsHandshake::ZtTlsHandshake() {
  NS_LOG_FUNCTION(this);
}

void ZtTlsHandshake::StartHandshake(Ptr<Node> client, Ptr<Node> server, uint32_t clientId, uint32_t serverId) {
  NS_LOG_FUNCTION(this << client << server);

  if (m_policyValidator && !m_policyValidator(clientId, "client")) {
    Log("[ZT-HANDSHAKE] Client not authorized by policy");
    return;
  }

  if (m_policyValidator && !m_policyValidator(serverId, "server")) {
    Log("[ZT-HANDSHAKE] Server not authorized by policy");
    return;
  }

  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
  prng.GenerateBlock(key, sizeof(key));

  std::string encoded;
  CryptoPP::StringSource ss(key, sizeof(key), true,
    new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded)));

  m_sessionKeys[serverId] = encoded;
  m_sessionKeys[clientId] = encoded;

  Log("[ZT-HANDSHAKE] Session established between Client " + std::to_string(clientId) +
      " and Server " + std::to_string(serverId) + " | Key: " + encoded);
}

bool ZtTlsHandshake::HasSession(uint32_t peerId) const {
  return m_sessionKeys.find(peerId) != m_sessionKeys.end();
}

std::string ZtTlsHandshake::GetSessionKey(uint32_t peerId) const {
  auto it = m_sessionKeys.find(peerId);
  return (it != m_sessionKeys.end()) ? it->second : "";
}

void ZtTlsHandshake::SetExternalLogger(std::function<void(std::string)> logger) {
  m_logger = logger;
}

void ZtTlsHandshake::SetPolicyValidator(std::function<bool(uint32_t, std::string)> validator) {
  m_policyValidator = validator;
}

void ZtTlsHandshake::Log(const std::string& msg) const {
  if (m_logger) {
    m_logger(msg);
  } else {
    NS_LOG_INFO(msg);
  }
}

} // namespace ns3

