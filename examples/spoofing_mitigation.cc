// spoofing_mitigated.cc (secure version with Zero Trust Library)

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/zero-trust-iot-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SpoofingMitigated");

class SecureSensorApp : public Application {
public:
  void Setup(Address peerAddr, uint32_t nodeId, std::string role, std::string sensorData,
             Ptr<ZtPolicyEngine> policy, CertificateAuthority* ca, Ptr<ZtTlsHandshake> handshake) {
    peer = peerAddr;
    nid = nodeId;
    this->role = role;
    this->sensorData = sensorData;
    this->zt = policy;
    this->ca = ca;
    this->handshake = handshake;
  }

private:
  virtual void StartApplication() {
    socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    socket->Connect(peer);

    handshake->StartHandshake(GetNode(), GetNode(), nid, 1);
    time_t expiry = std::time(nullptr) + 60;
    std::string cert = ca->SignIdentity(nid, role, expiry);
    ZtLogger::LogCertIssued(nid, role, expiry);
    Ptr<Packet> certPkt = Create<Packet>((uint8_t*)cert.c_str(), cert.size());
    socket->Send(certPkt);

    Simulator::Schedule(Seconds(2.0), &SecureSensorApp::SendEncrypted, this);
  }

  void SendEncrypted() {
    std::string sessionHexKey = handshake->GetSessionKey(nid);
    std::vector<byte> rawKey = HexToBytes(sessionHexKey);
    std::string iv;
    std::string encrypted = EncryptPayload(sensorData, rawKey.data(), iv);
    ZtLogger::LogEncryption(sensorData, iv);
    Ptr<Packet> pkt = Create<Packet>((uint8_t*)encrypted.c_str(), encrypted.size());
    socket->Send(pkt);
  }

  virtual void StopApplication() {
    if (socket) socket->Close();
  }

  Ptr<Socket> socket;
  Address peer;
  uint32_t nid;
  std::string role, sensorData;
  Ptr<ZtPolicyEngine> zt;
  CertificateAuthority* ca;
  Ptr<ZtTlsHandshake> handshake;
};

class SecureSinkApp : public Application {
public:
  void Setup(Address listen, Ptr<ZtPolicyEngine> policy, Ptr<ZtTlsHandshake> handshake) {
    local = listen;
    zt = policy;
    this->handshake = handshake;
  }

private:
  virtual void StartApplication() {
    socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    socket->Bind(local);
    socket->Listen();
    socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                              MakeCallback(&SecureSinkApp::HandleAccept, this));
  }

  void HandleAccept(Ptr<Socket> s, const Address&) {
    s->SetRecvCallback(MakeCallback(&SecureSinkApp::HandleRead, this));
  }

  void HandleRead(Ptr<Socket> s) {
    while (Ptr<Packet> pkt = s->Recv()) {
      uint32_t size = pkt->GetSize();
      uint8_t* buffer = new uint8_t[size];
      pkt->CopyData(buffer, size);
      std::string data(reinterpret_cast<char*>(buffer), size);
      delete[] buffer;

      if (data.find("ID:") == 0) {
        size_t idPos = data.find("ID:");
        size_t rolePos = data.find("|ROLE:");
        size_t expPos = data.find("|EXP:");
        uint32_t nodeId = std::stoul(data.substr(idPos + 3, rolePos - idPos - 3));
        std::string role = data.substr(rolePos + 6, expPos - rolePos - 6);

        bool valid = zt->AuthorizeWithCert(nodeId, role, data);
        ZtLogger::LogCertValidationResult(nodeId, valid);
        authorized[nodeId] = valid;

        handshake->StartHandshake(GetNode(), GetNode(), nodeId, 1);
        return;
      }

      uint32_t peerId = 0; // Example: extract from socket later
      if (authorized[peerId]) {
        try {
          std::string sessionHexKey = handshake->GetSessionKey(1);
          std::vector<byte> rawKey = HexToBytes(sessionHexKey);
          std::string decrypted = DecryptPayload(data, rawKey.data());
          ZtLogger::LogDecryption(decrypted);
        } catch (...) {
          ZtLogger::LogDecryptionFailure();
        }
      } else {
        ZtLogger::Log("ZT", "Unauthorized data attempt");
      }
    }
  }

  virtual void StopApplication() {
    if (socket) socket->Close();
  }

  Ptr<Socket> socket;
  Address local;
  Ptr<ZtPolicyEngine> zt;
  Ptr<ZtTlsHandshake> handshake;
  std::map<uint32_t, bool> authorized;
};
class SimpleTcpApp : public Application {
public:
  void Setup(Address address, std::string payload) {
    m_peer = address;
    m_payload = payload;
  }

private:
  virtual void StartApplication() {
    m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_socket->Connect(m_peer);
    Simulator::Schedule(Seconds(2.0), &SimpleTcpApp::SendData, this);
  }

  void SendData() {
    Ptr<Packet> pkt = Create<Packet>((uint8_t*)m_payload.c_str(), m_payload.size());
    m_socket->Send(pkt);
  }

  virtual void StopApplication() {
    if (m_socket) {
      m_socket->Close();
    }
  }

  Ptr<Socket> m_socket;
  Address m_peer;
  std::string m_payload;
};

int main(int argc, char* argv[]) {
  ZtLogger::EnableTimestamps(true);

  NodeContainer nodes;
  nodes.Create(3); // 0: sensor, 1: gateway, 2: attacker

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("2Mbps"));
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

  // Zero Trust Setup
  Ptr<ZtPolicyEngine> policy = CreateObject<ZtPolicyEngine>();
  CertificateAuthority ca;
  Ptr<ZtTlsHandshake> handshake = CreateObject<ZtTlsHandshake>();
  policy->SetCaPublicKey(ca.GetPublicKey());
  policy->AddAuthorized(0, "temp-sensor");

  // Sink
  Ptr<SecureSinkApp> sink = CreateObject<SecureSinkApp>();
  sink->Setup(InetSocketAddress(Ipv4Address::GetAny(), 8080), policy, handshake);
  nodes.Get(1)->AddApplication(sink);
  sink->SetStartTime(Seconds(0.0));
  sink->SetStopTime(Seconds(20.0));

  // Legitimate Sensor
  Ptr<SecureSensorApp> sensor = CreateObject<SecureSensorApp>();
  sensor->Setup(InetSocketAddress(iface1.GetAddress(1), 8080), 0, "temp-sensor", "TEMP:22.5", policy, &ca, handshake);
  nodes.Get(0)->AddApplication(sensor);
  sensor->SetStartTime(Seconds(1.0));
  sensor->SetStopTime(Seconds(10.0));

  // Attacker (no cert, garbage data)
  Ptr<SimpleTcpApp> attacker = CreateObject<SimpleTcpApp>();
  attacker->Setup(InetSocketAddress(iface2.GetAddress(1), 8080), "MALICIOUS#@garbage$");
  nodes.Get(2)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(3.0));
  attacker->SetStopTime(Seconds(10.0));

  
  Simulator::Run();
  Simulator::Destroy();
  return 0;
}

