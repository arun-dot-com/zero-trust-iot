/**
 * @file mitm-mitigation.cc
 * @brief NS-3 simulation demonstrating Zero Trust principles using secure communication and policy enforcement.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/zt-certificate.h"
#include "ns3/zt-policy-engine.h"
#include "ns3/zt-encryption-utils.h"
#include "ns3/zt-logger.h"
#include "ns3/zt-tls-handshake.h"

using namespace ns3;

// ==== Globals ====

/// TLS handshake manager for establishing secure sessions
Ptr<ZtTlsHandshake> handshake;

/// Policy engine for authorization based on identity and roles
Ptr<ZtPolicyEngine> policyEngine;

/// Certificate authority for signing identity certificates
CertificateAuthority ca;

/// UDP communication port used by gateway
uint16_t port = 9000;

/**
 * @brief Receives an encrypted packet at the gateway and performs decryption and validation.
 * @param socket The receiving socket on the gateway node.
 */
void ReceiveAtGateway(Ptr<Socket> socket)
{
  Ptr<Packet> packet = socket->Recv();
  uint32_t size = packet->GetSize();
  std::vector<uint8_t> buffer(size);
  packet->CopyData(buffer.data(), size);
  std::string encrypted(buffer.begin(), buffer.end());

  uint32_t selfId = 1;
  if (!handshake->HasSession(selfId)) {
    ZtLogger::Log("GATEWAY", "Rejected packet: no valid session with sender.");
    return;
  }

  std::string sessionKeyHex = handshake->GetSessionKey(selfId);
  std::string decrypted;
  try {
    decrypted = ns3::DecryptPayload(encrypted, ns3::HexDecodeKey(sessionKeyHex).BytePtr());
  } catch (...) {
    ZtLogger::Log("GATEWAY", "Decryption failed: corrupted or spoofed packet.");
    return;
  }

  if (decrypted.find("temperature") != std::string::npos) {
    ZtLogger::Log("GATEWAY", "Valid encrypted payload received from Sensor.");
    ZtLogger::Log("GATEWAY", "Valid encrypted payload received from Sensor: " + decrypted);
  } else {
    ZtLogger::Log("GATEWAY", "Rejected packet: payload failed validation.");
  }
}

/**
 * @brief Simulates a sensor device sending an encrypted payload to the gateway after policy and handshake validation.
 * @param socket The socket used to send the encrypted message.
 * @param gatewayAddr The address of the gateway node.
 * @param nodeId The ID of the sensor node.
 */
void SendFromSensor(Ptr<Socket> socket, Address gatewayAddr, uint32_t nodeId)
{
  std::string cert = ca.SignIdentity(nodeId, "IoTDevice", std::time(nullptr) + 300);
  ZtLogger::LogCertIssued(nodeId, "IoTDevice", std::time(nullptr) + 300);

  if (!policyEngine->AuthorizeWithCert(nodeId, "IoTDevice", cert)) {
    ZtLogger::LogCertRejected("Sensor not authorized");
    return;
  }

  handshake->StartHandshake(socket->GetNode(), NodeList::GetNode(1), nodeId, 1);

  if (!handshake->HasSession(1)) {
    ZtLogger::Log("TLS", "Handshake failed with gateway");
    return;
  }

  std::string sessionKeyHex = handshake->GetSessionKey(1);
  std::string ivOut;
  std::string payload = "temperature=26.3";
  std::string encrypted = ns3::EncryptPayload(payload, ns3::HexDecodeKey(sessionKeyHex).BytePtr(), ivOut);

  ZtLogger::LogEncryption("[payload hidden]", ivOut);

  socket->Connect(InetSocketAddress(InetSocketAddress::ConvertFrom(gatewayAddr).GetIpv4(), port));
  socket->Send(reinterpret_cast<const uint8_t *>(encrypted.c_str()), encrypted.size(), 0);
}

/**
 * @brief Simulates an attacker sending a spoofed plaintext message to the gateway without encryption.
 * @param socket The attacker's socket used to send the spoofed message.
 * @param gatewayAddr The address of the gateway.
 */
void AttackerSpoof(Ptr<Socket> socket, Address gatewayAddr)
{
  std::string fakeData = "temperature=99.9";
  socket->Connect(InetSocketAddress(InetSocketAddress::ConvertFrom(gatewayAddr).GetIpv4(), port));
  socket->Send(reinterpret_cast<const uint8_t *>(fakeData.c_str()), fakeData.size(), 0);

  ZtLogger::Log("ATTACKER", "Sent spoofed plaintext");
}

/**
 * @brief Main entry point for the simulation. Sets up network topology, installs security components, and executes events.
 * 
 * Topology: Sensor <-> Gateway <-> Attacker  
 * Demonstrates: Certificate signing, Zero Trust policy enforcement, secure TLS handshake, encrypted communication, and spoofing attempt.
 */
int main(int argc, char *argv[])
{
  NodeContainer nodes;
  nodes.Create(3);
  Names::Add("sensor", nodes.Get(0));
  Names::Add("gateway", nodes.Get(1));
  Names::Add("attacker", nodes.Get(2));

  InternetStackHelper stack;
  stack.Install(nodes);

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));
  p2p.Install(nodes.Get(0), nodes.Get(1));
  p2p.Install(nodes.Get(2), nodes.Get(1));

  Ipv4AddressHelper ip;
  ip.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces1 = ip.Assign(p2p.Install(nodes.Get(0), nodes.Get(1)));

  ip.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces2 = ip.Assign(p2p.Install(nodes.Get(2), nodes.Get(1)));

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // Setup Zero Trust components
  policyEngine = CreateObject<ZtPolicyEngine>();
  policyEngine->AddAuthorized(0, "client");
  policyEngine->AddAuthorized(1, "server");
  policyEngine->SetCaPublicKey(ca.GetPublicKey());

  handshake = CreateObject<ZtTlsHandshake>();
  handshake->SetPolicyValidator([](uint32_t nodeId, std::string role) {
    return policyEngine->Authorize(nodeId, role);
  });

  ZtLogger::EnableTimestamps(true);

  // Gateway listener
  Ptr<Socket> recvSocket = Socket::CreateSocket(nodes.Get(1), TypeId::LookupByName("ns3::UdpSocketFactory"));
  recvSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), port));
  recvSocket->SetRecvCallback(MakeCallback(&ReceiveAtGateway));

  // Legitimate sensor send
  Ptr<Socket> sensorSock = Socket::CreateSocket(nodes.Get(0), TypeId::LookupByName("ns3::UdpSocketFactory"));
  Simulator::Schedule(Seconds(1.0), &SendFromSensor, sensorSock, InetSocketAddress(interfaces1.GetAddress(1), port), 0);

  // Attacker spoof
  Ptr<Socket> attackerSock = Socket::CreateSocket(nodes.Get(2), TypeId::LookupByName("ns3::UdpSocketFactory"));
  Simulator::Schedule(Seconds(1.5), &AttackerSpoof, attackerSock, InetSocketAddress(interfaces2.GetAddress(1), port));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}

