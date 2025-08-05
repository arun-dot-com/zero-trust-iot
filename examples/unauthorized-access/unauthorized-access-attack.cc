/**
 * @file unauthorized-access-attack.cc
 * @brief Simulates unauthorized access in an NS-3 IoT setup without Zero Trust enforcement.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UnauthorizedAccessAttack");

/**
 * @class SimpleTcpApp
 * @brief Simulates a simple TCP client application that sends a message to a given peer.
 */
class SimpleTcpApp : public Application {
public:
  /**
   * @brief Sets up the application with peer address and payload.
   * @param peerAddr The destination address.
   * @param message The data to send.
   */
  void Setup(Address peerAddr, std::string message);

private:
  virtual void StartApplication();   ///< Called at application start.
  virtual void StopApplication();    ///< Called at application stop.

  /**
   * @brief Sends the configured payload to the peer.
   */
  void SendData();

  Ptr<Socket> m_socket;      ///< TCP socket used by the app.
  Address m_peer;            ///< Destination address.
  std::string m_message;     ///< Payload to send.
};

void SimpleTcpApp::Setup(Address peerAddr, std::string message) {
  m_peer = peerAddr;
  m_message = message;
}

void SimpleTcpApp::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_socket->Connect(m_peer);
  Simulator::Schedule(Seconds(2.0), &SimpleTcpApp::SendData, this);
}

void SimpleTcpApp::SendData() {
  Ptr<Packet> packet = Create<Packet>((uint8_t*)m_message.c_str(), m_message.size());
  m_socket->Send(packet);
}

void SimpleTcpApp::StopApplication() {
  if (m_socket) m_socket->Close();
}

/**
 * @class BasicSink
 * @brief A simple TCP server that logs incoming messages.
 */
class BasicSink : public Application {
private:
  virtual void StartApplication();  ///< Called at application start.
  virtual void StopApplication();   ///< Called at application stop.

  /**
   * @brief Handles incoming connections.
   * @param socket Pointer to the socket.
   * @param address Remote address.
   */
  void HandleAccept(Ptr<Socket> socket, const Address& address);

  /**
   * @brief Reads data from connected clients and logs the content.
   * @param socket Socket to read from.
   */
  void HandleRead(Ptr<Socket> socket);

  Ptr<Socket> m_socket; ///< Server socket.
};

void BasicSink::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9090));
  m_socket->Listen();
  m_socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                              MakeCallback(&BasicSink::HandleAccept, this));
}

void BasicSink::HandleAccept(Ptr<Socket> s, const Address&) {
  s->SetRecvCallback(MakeCallback(&BasicSink::HandleRead, this));
}

void BasicSink::HandleRead(Ptr<Socket> socket) {
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

void BasicSink::StopApplication() {
  if (m_socket) m_socket->Close();
}

/**
 * @brief Main function to simulate a TCP-based unauthorized access attack scenario.
 * 
 * - Node 0: legitimate sensor
 * - Node 1: sink
 * - Node 2: unauthorized attacker
 */
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

  // Sink application
  Ptr<BasicSink> sink = CreateObject<BasicSink>();
  nodes.Get(1)->AddApplication(sink);
  sink->SetStartTime(Seconds(0.0));
  sink->SetStopTime(Seconds(20.0));

  // Legitimate sensor application
  Ptr<SimpleTcpApp> sensor = CreateObject<SimpleTcpApp>();
  sensor->Setup(InetSocketAddress(iface1.GetAddress(1), 9090), "TEMP:25.0");
  nodes.Get(0)->AddApplication(sensor);
  sensor->SetStartTime(Seconds(1.0));
  sensor->SetStopTime(Seconds(5.0));

  // Unauthorized attacker application
  Ptr<SimpleTcpApp> attacker = CreateObject<SimpleTcpApp>();
  attacker->Setup(InetSocketAddress(iface2.GetAddress(1), 9090), "DELETE ALL DATA");
  nodes.Get(2)->AddApplication(attacker);
  attacker->SetStartTime(Seconds(3.0));
  attacker->SetStopTime(Seconds(7.0));

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}

