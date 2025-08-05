/**
 * @file mitm-attack.cc
 * @brief NS-3 simulation of a Man-in-the-Middle (MitM) attack on UDP communication.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("MitMAttackUDP");

uint16_t mitmPort = 8080;
uint16_t gatewayPort = 9090;
Ipv4Address g_gatewayAddress;

/**
 * @brief Sends a UDP message from the sensor node to the MITM node.
 * @param socket The socket used for transmission.
 * @param mitmAddr The address of the MITM node.
 * @param message The message string to send.
 */
void SendFromSensor(Ptr<Socket> socket, Address mitmAddr, std::string message) {
  socket->Connect(mitmAddr);
  Ptr<Packet> pkt = Create<Packet>((uint8_t*)message.c_str(), message.size());
  socket->Send(pkt);
  NS_LOG_UNCOND("[SENSOR] Sent: " << message);
}

/**
 * @brief Receives packets at the gateway node.
 * @param socket The receiving socket.
 */
void ReceiveAtGateway(Ptr<Socket> socket) {
  Ptr<Packet> pkt = socket->Recv();
  uint32_t size = pkt->GetSize();
  std::vector<uint8_t> buffer(size);
  pkt->CopyData(buffer.data(), size);
  std::string msg(buffer.begin(), buffer.end());
  NS_LOG_UNCOND("[GATEWAY] Received: " << msg);
}

/**
 * @brief MITM node intercepts and modifies packets before forwarding them to the gateway.
 * @param socket The receiving socket on the MITM node.
 */
void MitmReceiveAndForward(Ptr<Socket> socket) {
  Ptr<Packet> pkt = socket->Recv();
  uint32_t size = pkt->GetSize();
  std::vector<uint8_t> buffer(size);
  pkt->CopyData(buffer.data(), size);
  std::string msg(buffer.begin(), buffer.end());

  std::string tampered = "TAMPERED: " + msg;
  NS_LOG_UNCOND("[MITM] Intercepted and modified: " << tampered);

  Ptr<Socket> forwardSocket = Socket::CreateSocket(socket->GetNode(), UdpSocketFactory::GetTypeId());
  forwardSocket->Connect(InetSocketAddress(g_gatewayAddress, gatewayPort));
  Ptr<Packet> fwdPkt = Create<Packet>((uint8_t*)tampered.c_str(), tampered.size());
  forwardSocket->Send(fwdPkt);
}

/**
 * @brief Main function to set up the NS-3 simulation.
 * 
 * Creates three nodes (sensor, MITM, gateway), connects them with point-to-point links,
 * installs the internet stack, sets up sockets and callbacks, and runs the simulation.
 */
int main(int argc, char *argv[]) {
  LogComponentEnable("MitMAttackUDP", LOG_LEVEL_INFO);

  NodeContainer nodes;
  nodes.Create(3); // 0: Sensor, 1: Gateway, 2: MITM

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));

  NetDeviceContainer d1 = p2p.Install(nodes.Get(0), nodes.Get(2)); // Sensor-MITM
  NetDeviceContainer d2 = p2p.Install(nodes.Get(2), nodes.Get(1)); // MITM-Gateway

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper ip;
  ip.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i1 = ip.Assign(d1);
  ip.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer i2 = ip.Assign(d2);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  // Gateway socket
  Ptr<Socket> gatewaySock = Socket::CreateSocket(nodes.Get(1), UdpSocketFactory::GetTypeId());
  gatewaySock->Bind(InetSocketAddress(Ipv4Address::GetAny(), gatewayPort));
  gatewaySock->SetRecvCallback(MakeCallback(&ReceiveAtGateway));

  // MITM socket
  Ptr<Socket> mitmSock = Socket::CreateSocket(nodes.Get(2), UdpSocketFactory::GetTypeId());
  mitmSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), mitmPort));
  mitmSock->SetRecvCallback(MakeCallback(&MitmReceiveAndForward));

  // Sensor socket
  Ptr<Socket> sensorSock = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());
  Simulator::Schedule(Seconds(2.0), &SendFromSensor, sensorSock, InetSocketAddress(i1.GetAddress(1), mitmPort), "TEMP:45.2");
  g_gatewayAddress = i2.GetAddress(1);  // Set the global gateway address

  Simulator::Run();
  Simulator::Destroy();
  return 0;
}

