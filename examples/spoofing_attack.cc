// spoofing_attack.cc (insecure version)

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SpoofingAttack");

// Simple TCP App to send spoofed or valid data
class SimpleTcpApp : public Application {
public:
  void Setup(Address addr, std::string message) {
    peer = addr;
    data = message;
  }

private:
  virtual void StartApplication() {
    socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    socket->Connect(peer);
    Simulator::Schedule(Seconds(1.0), &SimpleTcpApp::Send, this);
  }

  void Send() {
    Ptr<Packet> packet = Create<Packet>((uint8_t*)data.c_str(), data.size());
    socket->Send(packet);
  }

  virtual void StopApplication() {
    if (socket) socket->Close();
  }

  Ptr<Socket> socket;
  Address peer;
  std::string data;
};

class TcpReceiver : public Application {
public:
  void Setup(Address listen) {
    local = listen;
  }

private:
  virtual void StartApplication() {
    socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    socket->Bind(local);
    socket->Listen();
    socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                              MakeCallback(&TcpReceiver::HandleAccept, this));
  }

  void HandleAccept(Ptr<Socket> s, const Address &) {
    s->SetRecvCallback(MakeCallback(&TcpReceiver::HandleRead, this));
  }

  void HandleRead(Ptr<Socket> s) {
    while (Ptr<Packet> packet = s->Recv()) {
      uint32_t len = packet->GetSize();
      uint8_t *buffer = new uint8_t[len];
      packet->CopyData(buffer, len);
      std::string received((char*)buffer, len);
      delete[] buffer;
      NS_LOG_UNCOND("[Gateway] Received: " << received);
    }
  }

  virtual void StopApplication() {
    if (socket) socket->Close();
  }

  Ptr<Socket> socket;
  Address local;
};

int main(int argc, char *argv[]) {
  NodeContainer nodes;
  nodes.Create(3); // [0]=sensor, [1]=gateway, [2]=spoofed attacker

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));

  NetDeviceContainer d1 = p2p.Install(nodes.Get(0), nodes.Get(1));
  NetDeviceContainer d2 = p2p.Install(nodes.Get(2), nodes.Get(1));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper ip;
  ip.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer iface1 = ip.Assign(d1);
  ip.SetBase("10.0.1.0", "255.255.255.0");
  Ipv4InterfaceContainer iface2 = ip.Assign(d2);

  // Legitimate sensor node
  Ptr<SimpleTcpApp> sensorApp = CreateObject<SimpleTcpApp>();
  sensorApp->Setup(InetSocketAddress(iface1.GetAddress(1), 8080), "TEMP:25.0");
  nodes.Get(0)->AddApplication(sensorApp);
  sensorApp->SetStartTime(Seconds(0.5));
  sensorApp->SetStopTime(Seconds(10.0));

  // Attacker sends garbage
  Ptr<SimpleTcpApp> spoofedApp = CreateObject<SimpleTcpApp>();
  spoofedApp->Setup(InetSocketAddress(iface2.GetAddress(1), 8080), "@$%!@garbageDATA#");
  nodes.Get(2)->AddApplication(spoofedApp);
  spoofedApp->SetStartTime(Seconds(1.5));
  spoofedApp->SetStopTime(Seconds(10.0));

  // Gateway receiver
  Ptr<TcpReceiver> recvApp = CreateObject<TcpReceiver>();
  recvApp->Setup(InetSocketAddress(Ipv4Address::GetAny(), 8080));
  nodes.Get(1)->AddApplication(recvApp);
  recvApp->SetStartTime(Seconds(0.0));
  recvApp->SetStopTime(Seconds(15.0));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}

