// unauthorized_access_attack.cc (realistic simulation: no Zero Trust)

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UnauthorizedAccessAttack");

class SimpleTcpApp : public Application {
public:
  void Setup(Address peerAddr, std::string message) {
    m_peer = peerAddr;
    m_message = message;
  }

private:
  virtual void StartApplication() {
    m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_socket->Connect(m_peer);
    Simulator::Schedule(Seconds(2.0), &SimpleTcpApp::SendData, this);
  }

  void SendData() {
    Ptr<Packet> packet = Create<Packet>((uint8_t*)m_message.c_str(), m_message.size());
    m_socket->Send(packet);
  }

  virtual void StopApplication() {
    if (m_socket) m_socket->Close();
  }

  Ptr<Socket> m_socket;
  Address m_peer;
  std::string m_message;
};

class BasicSink : public Application {
private:
  virtual void StartApplication() {
    m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9090));
    m_socket->Listen();
    m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                                MakeCallback(&BasicSink::HandleAccept, this));
  }

  void HandleAccept(Ptr<Socket> s, const Address&) {
    s->SetRecvCallback(MakeCallback(&BasicSink::HandleRead, this));
  }

  void HandleRead(Ptr<Socket> socket) {
    while (Ptr<Packet> packet = socket->Recv()) {
      Address from;
      socket->GetPeerName(from);

      uint32_t size = packet->GetSize();
      uint8_t* buffer = new uint8_t[size];
      packet->CopyData(buffer, size);
      std::string data(reinterpret_cast<char*>(buffer), size);
      delete[] buffer;

      std::ostringstream log;
      log << "[RECEIVED from " << InetSocketAddress::ConvertFrom(from).GetIpv4() << "] Payload: " << data;
      NS_LOG_UNCOND(log.str());
    }
  }

  virtual void StopApplication() {
    if (m_socket) m_socket->Close();
  }

  Ptr<Socket> m_socket;
};

int main(int argc, char* argv[]) {
  NodeContainer nodes;
  nodes.Create(3); // 0: sensor, 1: sink, 2: attacker

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));
  NetDeviceContainer d1 = p2p.Install(nodes.Get(0), nodes.Get(1));
  NetDeviceContainer d2 = p2p.Install(nodes.Get(2), nodes.Get(1));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iface1 = address.Assign(d1);
  address.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer iface2 = address.Assign(d2);

  // Sink
  Ptr<BasicSink> sink = CreateObject<BasicSink>();
  nodes.Get(1)->AddApplication(sink);
  sink->SetStartTime(Seconds(0.0));
  sink->SetStopTime(Seconds(20.0));

  // Legitimate Sensor
  Ptr<SimpleTcpApp> sensor = CreateObject<SimpleTcpApp>();
  sensor->Setup(InetSocketAddress(iface1.GetAddress(1), 9090), "TEMP:25.0");
  nodes.Get(0)->AddApplication(sensor);
  sensor->SetStartTime(Seconds(1.0));
  sensor->SetStopTime(Seconds(5.0));

  // Unauthorized Attacker
  Ptr<SimpleTcpApp> attacker = CreateObject<SimpleTcpApp>();
  attacker->Setup(InetSocketAddress(iface2.GetAddress(1), 9090), "DELETE ALL DATA");
  nodes.Get(2)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(3.0));
  attacker->SetStopTime(Seconds(7.0));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}

