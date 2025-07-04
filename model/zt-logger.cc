#include "zt-logger.h"
#include <ns3/core-module.h>
#include <sstream>
#include <iomanip>
#include <ctime>

using namespace ns3;

bool ZtLogger::timestampsEnabled = true;

void ZtLogger::EnableTimestamps(bool enable) {
  timestampsEnabled = enable;
}

void ZtLogger::Log(const std::string &tag, const std::string &message) {
  std::ostringstream output;

  if (timestampsEnabled) {
    std::time_t now = std::time(nullptr);
    std::tm *lt = std::localtime(&now);
    output << "[" << std::put_time(lt, "%H:%M:%S") << "] ";
  }

  output << "[" << tag << "] " << message;
  NS_LOG_UNCOND(output.str());
}

// === Certificate Logs ===
void ZtLogger::LogCertIssued(uint32_t nodeId, const std::string &role, time_t expiry) {
  std::ostringstream msg;
  msg << "Issued certificate to Node " << nodeId << " | Role: " << role
      << " | Expiry: " << expiry;
  Log("ZT-CERT", msg.str());
}

void ZtLogger::LogCertValidationResult(uint32_t nodeId, bool valid) {
  Log("ZT-CERT", "Validation for Node " + std::to_string(nodeId) +
      (valid ? ": VALID" : ": INVALID"));
}

void ZtLogger::LogCertRevoked(uint32_t nodeId) {
  Log("ZT-CERT", "Node " + std::to_string(nodeId) + " certificate revoked");
}

void ZtLogger::LogCertRejected(const std::string &reason) {
  Log("ZT-CERT", "Certificate rejected: " + reason);
}

// === Encryption Logs ===
void ZtLogger::LogEncryption(const std::string &payload, const std::string &ivHex) {
  Log("ZT-ENC", "Payload encrypted | IV: " + ivHex + " | Data: " + payload);
}

void ZtLogger::LogDecryption(const std::string &payload) {
  Log("ZT-DEC", "Decrypted Payload: " + payload);
}

void ZtLogger::LogDecryptionFailure() {
  Log("ZT-DEC", "Decryption failed: Invalid session or corrupt data");
}

