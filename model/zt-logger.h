#ifndef ZT_LOGGER_H
#define ZT_LOGGER_H

#include <string>
#include <ctime>
#include <cstdint>

class ZtLogger {
public:
  static void EnableTimestamps(bool enable);

  // General
  static void Log(const std::string &tag, const std::string &message);

  // Certificate Events
  static void LogCertIssued(uint32_t nodeId, const std::string &role, time_t expiry);
  static void LogCertValidationResult(uint32_t nodeId, bool valid);
  static void LogCertRevoked(uint32_t nodeId);
  static void LogCertRejected(const std::string &reason);

  // Encryption Events
  static void LogEncryption(const std::string &payload, const std::string &ivHex);
  static void LogDecryption(const std::string &payload);
  static void LogDecryptionFailure();

private:
  static bool timestampsEnabled;
};

#endif // ZT_LOGGER_H

