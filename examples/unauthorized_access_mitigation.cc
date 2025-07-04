// unauthorized_access_mitigated.cc (secured with Zero Trust Library)

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/zero-trust-iot-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UnauthorizedAccessMitigated");

class SecureSensorApp : public Application {
public:
  void Setup(Address peer, uint32_t nodeId, std::string role, std::string payload,
             Ptr<ZtPolicyEngine> policy, CertificateAuthority* ca, Ptr<ZtTlsHandshake> handshake) {
    m_peer = peer;
    m_nodeId = nodeId;
    m_role = role;
    m_payload = payload;
    m_policy = policy;
    m_ca = ca;
    m_handshake = handshake;
  }

private:
  virtual void StartApplication() {
    m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_socket->Connect(m_peer);

    time_t expiry = std::time(nullptr) + 60;
    std::string cert = m_ca->SignIdentity(m_nodeId, m_role, expiry);
    ZtLogger::LogCertIssued(m_nodeId, m_role, expiry);
    Ptr<Packet> certPkt = Create<Packet>((uint8_t*)cert.c_str(), cert.size());
    m_socket->Send(certPkt);

    m_handshake->StartHandshake(GetNode(), GetNode(), m_nodeId, 1);
    Simulator::Schedule(Seconds(2.0), &SecureSensorApp::SendEncrypted, this);
  }

  void SendEncrypted() {
    if (!m_handshake->HasSession(m_nodeId)) {
      ZtLogger::Log("ZT", "Sensor node has no session key – skipping encryption");
      return;
    }
    std::string sessionKey = m_handshake->GetSessionKey(m_nodeId);
    std::vector<byte> rawKey = HexToBytes(sessionKey);
    std::string iv;
    std::string encrypted = EncryptPayload(m_payload, rawKey.data(), iv);
    ZtLogger::LogEncryption(m_payload, iv);
    Ptr<Packet> pkt = Create<Packet>((uint8_t*)encrypted.c_str(), encrypted.size());
    m_socket->Send(pkt);
  }

  virtual void StopApplication() {
    if (m_socket) m_socket->Close();
  }

  Ptr<Socket> m_socket;
  Address m_peer;
  uint32_t m_nodeId;
  std::string m_role, m_payload;
  Ptr<ZtPolicyEngine> m_policy;
  CertificateAuthority* m_ca;
  Ptr<ZtTlsHandshake> m_handshake;
};

class SecureSink : public Application {
public:
  void Setup(Address listen, Ptr<ZtPolicyEngine> policy, Ptr<ZtTlsHandshake> handshake) {
    m_local = listen;
    m_policy = policy;
    m_handshake = handshake;
  }

private:
  virtual void StartApplication() {
    m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_socket->Bind(m_local);
    m_socket->Listen();
    m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                MakeCallback(&SecureSink::HandleAccept, this));
  }

  void HandleAccept(Ptr<Socket> s, const Address&) {
    s->SetRecvCallback(MakeCallback(&SecureSink::HandleRead, this));
  }

  void HandleRead(Ptr<Socket> socket) {
    while (Ptr<Packet> pkt = socket->Recv()) {
      uint32_t size = pkt->GetSize();
      std::vector<uint8_t> buffer(size);
      pkt->CopyData(buffer.data(), size);
      std::string data(reinterpret_cast<char*>(buffer.data()), size);

      if (data.find("ID:") == 0) {
        try {
          uint32_t nodeId = std::stoi(data.substr(3, data.find("|ROLE:") - 3));
          std::string role = data.substr(data.find("|ROLE:") + 6, data.find("|EXP:") - data.find("|ROLE:") - 6);

          bool valid = m_policy->AuthorizeWithCert(nodeId, role, data);
          ZtLogger::LogCertValidationResult(nodeId, valid);
          m_authorized[nodeId] = valid;

          if (valid) {
            m_handshake->StartHandshake(GetNode(), GetNode(), nodeId, 1);
          }
        } catch (...) {
          ZtLogger::Log("ZT", "Malformed certificate – ignored");
        }
        continue;
      }

      bool validPacket = false;
      for (const auto& entry : m_authorized) {
        if (entry.second && m_handshake->HasSession(entry.first)) {
          try {
            std::string sessionKey = m_handshake->GetSessionKey(entry.first);
            std::vector<byte> rawKey = HexToBytes(sessionKey);
            std::string decrypted = DecryptPayload(data, rawKey.data());
            ZtLogger::LogDecryption(decrypted);
            validPacket = true;
            break;
          } catch (...) {
            ZtLogger::LogDecryptionFailure();
            //validPacket = true;
            break;
          }
        }
      }
     ZtLogger::Log("DEBUG", "Reached packet validation block");

      if (!validPacket) {
        ZtLogger::Log("ZT", "Unauthorized data attempt - dropped");
      }
    }
  }

  virtual void StopApplication() {
    if (m_socket) m_socket->Close();
  }

  Ptr<Socket> m_socket;
  Address m_local;
  Ptr<ZtPolicyEngine> m_policy;
  Ptr<ZtTlsHandshake> m_handshake;
  std::map<uint32_t, bool> m_authorized;
};

class AttackerApp : public Application {
public:
  void Setup(Address peer, std::string payload) {
    m_peer = peer;
    m_payload = payload;
  }

private:
  virtual void StartApplication() {
    m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_socket->Connect(m_peer);
    Simulator::Schedule(Seconds(3.0), &AttackerApp::SendFake, this);
  }

  void SendFake() {
    ZtLogger::Log("ATTACKER", "Sending unauthorized payload");
    Ptr<Packet> pkt = Create<Packet>((uint8_t*)m_payload.c_str(), m_payload.size());
    m_socket->Send(pkt);
  }

  virtual void StopApplication() {
    if (m_socket) m_socket->Close();
  }

  Ptr<Socket> m_socket;
  Address m_peer;
  std::string m_payload;
};

int main(int argc, char* argv[]) {
  ZtLogger::EnableTimestamps(true);

  NodeContainer nodes;
  nodes.Create(3); // 0: sensor, 1: sink, 2: attacker

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));
  NetDeviceContainer d1 = p2p.Install(nodes.Get(0), nodes.Get(1));
  NetDeviceContainer d2 = p2p.Install(nodes.Get(2), nodes.Get(1));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper ip;
  ip.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iface1 = ip.Assign(d1);
  ip.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer iface2 = ip.Assign(d2);

  // Zero Trust setup
  Ptr<ZtPolicyEngine> policy = CreateObject<ZtPolicyEngine>();
  CertificateAuthority ca;
  Ptr<ZtTlsHandshake> handshake = CreateObject<ZtTlsHandshake>();
  policy->SetCaPublicKey(ca.GetPublicKey());
  policy->AddAuthorized(0, "sensor");

  // Sink
  Ptr<SecureSink> sink = CreateObject<SecureSink>();
  sink->Setup(InetSocketAddress(Ipv4Address::GetAny(), 9090), policy, handshake);
  nodes.Get(1)->AddApplication(sink);
  sink->SetStartTime(Seconds(0.0));
  sink->SetStopTime(Seconds(20.0));

  // Legitimate Sensor
  Ptr<SecureSensorApp> sensor = CreateObject<SecureSensorApp>();
  sensor->Setup(InetSocketAddress(iface1.GetAddress(1), 9090), 0, "sensor", "TEMP:25.5", policy, &ca, handshake);
  nodes.Get(0)->AddApplication(sensor);
  sensor->SetStartTime(Seconds(1.0));
  sensor->SetStopTime(Seconds(5.0));

  // Attacker
  Ptr<AttackerApp> attacker = CreateObject<AttackerApp>();
  attacker->Setup(InetSocketAddress(iface2.GetAddress(1), 9090), "ERASE:ALL");
  nodes.Get(2)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(2.5));
  attacker->SetStopTime(Seconds(6.0));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
