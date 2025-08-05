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

/**
 * \ingroup zerotrust
 * \brief Implements policy enforcement for Zero Trust security in NS-3 simulations.
 *
 * The ZtPolicyEngine class is responsible for enforcing identity-based access control,
 * managing certificate validation, revocations, and dynamic role-based authorization.
 */
class ZtPolicyEngine : public Object {
public:
  /**
   * \brief Get the TypeId for ZtPolicyEngine.
   * \return TypeId object used for NS-3 runtime type identification.
   */
  static TypeId GetTypeId();

  /**
   * \brief Add a node to the authorized list with a specified role.
   * \param nodeId The node ID to authorize.
   * \param role The role assigned to the node (e.g., "sensor", "gateway").
   */
  void AddAuthorized(uint32_t nodeId, const std::string& role);

  /**
   * \brief Check if a node is authorized for a given role.
   * \param nodeId The ID of the requesting node.
   * \param role The required role for access.
   * \return True if authorized, false otherwise.
   */
  bool Authorize(uint32_t nodeId, const std::string& role);

  /**
   * \brief Set the Certificate Authority's public key for verifying digital signatures.
   * \param pub The RSA public key of the CA.
   */
  void SetCaPublicKey(RSA::PublicKey pub);

  /**
   * \brief Add a node ID to the revocation list.
   * \param nodeId The ID of the node to revoke.
   */
  void Revoke(uint32_t nodeId);

  /**
   * \brief Perform certificate-based authorization for a node.
   *
   * This checks:
   * - If the node is revoked
   * - If the certificate signature is valid
   * - If the certificate identity matches the request
   * - If the certificate is not expired
   *
   * \param nodeId The ID of the requesting node.
   * \param role The required role for access.
   * \param certStr The certificate string (including fields and base64-encoded signature).
   * \return True if certificate is valid and authorized, false otherwise.
   */
  bool AuthorizeWithCert(uint32_t nodeId, const std::string& role, const std::string& certStr);

private:
  std::unordered_map<uint32_t, std::string> authTable; ///< Maps node ID to assigned role
  std::unordered_set<uint32_t> revoke;                 ///< List of revoked node IDs
  RSA::PublicKey caPublicKey;                          ///< Public key for certificate signature verification
};

} // namespace ns3

#endif // ZT_POLICY_ENGINE_H

