/**
 * @file spoofing-attack.cc
 * @brief Demonstrates a spoofing attack scenario in an NS-3 TCP-based IoT setup.
 *
 * This simulation consists of a legitimate sensor node and a spoofed attacker,
 * both sending data to a gateway over TCP. The gateway receives and logs the data.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SpoofingAttack");

/**
 * @class SimpleTcpApp
 * @brief A simple TCP-based application to send data to a remote peer.
 *
 * This application is used by both the legitimate sensor and the spoofed attacker
 * to transmit a message to the gateway node.
 */
class SimpleTcpApp : public Application {
public:
  /**
   * @brief Set up the TCP app with destination address and message.
   * @param addr The destination Address to connect to.
   * @param message The message payload to send.
   */
  void Setup(Address addr, std::string message);

private:
  /**
   * @brief Called when the application starts. Connects the socket and schedules Send().
   */
  virtual void StartApplication();

  /**
   * @brief Sends the message to the peer via TCP.
   */
  void Send();

  /**
   * @brief Called when the application stops. Closes the socket.
   */
  virtual void StopApplication();

  Ptr<Socket> socket;      ///< TCP socket used to send data.
  Address peer;            ///< Destination address to send data to.
  std::string data;        ///< Message payload.
};

void SimpleTcpApp::Setup(Address addr, std::string message) {
  peer = addr;
  data = message;
}

void SimpleTcpApp::StartApplication() {
  socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  socket->Connect(peer);
  Simulator::Schedule(Seconds(1.0), &SimpleTcpApp::Send, this);
}

void SimpleTcpApp::Send() {
  Ptr<Packet> packet = Create<Packet>((uint8_t*)data.c_str(), data.size());
  socket->Send(packet);
}

void SimpleTcpApp::StopApplication() {
  if (socket) socket->Close();
}

/**
 * @class TcpReceiver
 * @brief A simple TCP server application that receives and logs incoming messages.
 *
 * Acts as the gateway receiving messages from both legitimate and spoofed sources.
 */
class TcpReceiver : public Application {
public:
  /**
   * @brief Sets the address on which the receiver should listen.
   * @param listen The address to bind and listen on.
   */
  void Setup(Address listen);

private:
  /**
   * @brief Called when the application starts. Binds and listens on the socket.
   */
  virtual void StartApplication();

  /**
   * @brief Accepts a new incoming connection.
   * @param s The accepted socket.
   * @param address The remote address (not used).
   */
  void HandleAccept(Ptr<Socket> s, const Address &address);

  /**
   * @brief Reads incoming data and logs it.
   * @param s The socket from which to receive data.
   */
  void HandleRead(Ptr<Socket> s);

  /**
   * @brief Called when the application stops. Closes the socket.
   */
  virtual void StopApplication();

  Ptr<Socket> socket;  ///< TCP server socket.
  Address local;       ///< Address to listen on.
};

void TcpReceiver::Setup(Address listen) {
  local = listen;
}

void TcpReceiver::StartApplication() {
  socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
  socket->Bind(local);
  socket->Listen();
  socket->SetAcceptCallback(MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
                            MakeCallback(&TcpReceiver::HandleAccept, this));
}

void TcpReceiver::HandleAccept(Ptr<Socket> s, const Address &) {
  s->SetRecvCallback(MakeCallback(&TcpReceiver::HandleRead, this));
}

void TcpReceiver::HandleRead(Ptr<Socket> s) {
  while (Ptr<Packet> packet = s->Recv()) {
    uint32_t len = packet->GetSize();
    uint8_t *buffer = new uint8_t[len];
    packet->CopyData(buffer, len);
    std::string received((char*)buffer, len);
    delete[] buffer;
    NS_LOG_UNCOND("[Gateway] Received: " << received);
  }
}

void TcpReceiver::StopApplication() {
  if (socket) socket->Close();
}

/**
 * @brief Main function to run the spoofing attack simulation.
 *
 * This sets up three nodes: a legitimate sensor, a spoofed attacker,
 * and a gateway. Both sensor and attacker send TCP messages to the gateway.
 */
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

