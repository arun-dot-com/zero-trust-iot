// === zt-policy-engine.cc ===
#include "zt-policy-engine.h"
#include <ns3/log.h>
#include <sstream>
#include <ctime>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("ZtPolicyEngine");

/**
 * \brief Get the TypeId for ZtPolicyEngine.
 * \return The TypeId object for this class.
 */
TypeId ZtPolicyEngine::GetTypeId() {
  static TypeId tid = TypeId("ZtPolicyEngine")
    .SetParent<Object>()
    .SetGroupName("ZeroTrust")
    .AddConstructor<ZtPolicyEngine>();
  return tid;
}

/**
 * \brief Add an authorized node and its assigned role.
 * \param nodeId The ID of the node.
 * \param role The assigned role for the node (e.g., "sensor", "gateway").
 */
void ZtPolicyEngine::AddAuthorized(uint32_t nodeId, const std::string& role) {
  authTable[nodeId] = role;
}

/**
 * \brief Check if a node is authorized based on its ID and expected role.
 * \param nodeId The ID of the node requesting access.
 * \param role The expected role the node must have.
 * \return True if the node is authorized and role matches, false otherwise.
 */
bool ZtPolicyEngine::Authorize(uint32_t nodeId, const std::string& role) {
  return authTable.find(nodeId) != authTable.end() && authTable[nodeId] == role;
}

/**
 * \brief Set the public key of the Certificate Authority used for signature verification.
 * \param pub The RSA public key of the CA.
 */
void ZtPolicyEngine::SetCaPublicKey(RSA::PublicKey pub) {
  caPublicKey = pub;
}

/**
 * \brief Revoke a node by adding its ID to the revocation list.
 * \param nodeId The ID of the node to be revoked.
 */
void ZtPolicyEngine::Revoke(uint32_t nodeId) {
  revoke.insert(nodeId);
}

/**
 * \brief Authorize a node using certificate validation.
 *
 * This function checks:
 * - Whether the node is revoked.
 * - If the certificate has a valid signature.
 * - If the ID and role match the expected values.
 * - Whether the certificate has expired.
 *
 * \param nodeId The ID of the node requesting access.
 * \param role The expected role for the node.
 * \param certStr The full certificate string including signature.
 * \return True if all certificate checks pass and the node is authorized, false otherwise.
 */
bool ZtPolicyEngine::AuthorizeWithCert(uint32_t nodeId, const std::string& role, const std::string& certStr) {
  if (revoke.find(nodeId) != revoke.end()) {
    NS_LOG_UNCOND("ZT-CERT: Node " << nodeId << " is revoked");
    return false;
  }

  std::string content, sig;
  size_t sigPos = certStr.find("|SIG:");
  if (sigPos == std::string::npos) return false;
  content = certStr.substr(0, sigPos);
  sig = certStr.substr(sigPos + 5);

  std::string decodedSig;
  CryptoPP::StringSource(sig, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decodedSig)));

  CryptoPP::RSASS<CryptoPP::PSSR, CryptoPP::SHA1>::Verifier verifier(caPublicKey);
  bool valid = false;
  CryptoPP::StringSource(decodedSig + content, true,
    new CryptoPP::SignatureVerificationFilter(verifier,
      new CryptoPP::ArraySink((byte*)&valid, sizeof(valid)),
      CryptoPP::SignatureVerificationFilter::PUT_RESULT | CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN));

  if (!valid) {
    NS_LOG_UNCOND("ZT-CERT: Signature invalid");
    return false;
  }

  std::istringstream ss(content);
  std::string token;
  uint32_t idParsed = 0;
  std::string roleParsed;
  time_t expiry = 0;

  while (std::getline(ss, token, '|')) {
    if (token.find("ID:") == 0)
      idParsed = std::stoul(token.substr(3));
    else if (token.find("ROLE:") == 0)
      roleParsed = token.substr(5);
    else if (token.find("EXP:") == 0)
      expiry = std::stol(token.substr(4));
  }

  if (idParsed != nodeId || roleParsed != role) {
    NS_LOG_UNCOND("ZT-CERT: Identity mismatch");
    return false;
  }

  if (std::time(nullptr) > expiry) {
    NS_LOG_UNCOND("ZT-CERT: Certificate expired");
    return false;
  }

  return true;
}

} // namespace ns3

