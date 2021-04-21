import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;

import java.sql.Timestamp;
import java.util.ArrayList;

public class MultimediaSession extends Session {
 private ArrayList<String> listPort1 = new ArrayList<>();
 private ArrayList<String> listPort2 = new ArrayList<>();
 private ArrayList<Boolean>listIsTCP = new ArrayList<>();
 private ArrayList<Boolean>listIsUDP = new ArrayList<>();
 
 public MultimediaSession() {
 }
 
 public MultimediaSession(String ip1, String port1, String ip2, String port2) {
  super(ip1, port1, ip2, port2);
  this.listPort1.add(port1);
  this.listPort2.add(port2);
 }
 
 public MultimediaSession(Session s){
  this.ip1=s.getIp1();
  this.ip2=s.getIp2();
  this.listPort1.add(s.getPort1());
  this.listPort2.add(s.getPort2());
  
 }
 
 //Is it safe?? we have to sort out every packet in sessions
// public void appendSession(Session s){
//
//  this.port1.add(s.getPort1());
//  this.port2.add(s.getPort2());
//  this.ipV4Packets.addAll(s.getIpV4Packets());
//  this.packetTimestamps.addAll(s.getPacketTimestamps());
//  int listSize = s.getPacketTimestamps().size();
//  for (int i = 0; i <listSize; i++){
//   this.timeouts.add(s.getTimeout());
//   this.listIsTCP.add(s.isTCP());
//   this.listIsUDP.add(s.isUDP());
//  }
 
 public void appendPacket(IpV4Packet ipV4Packet, Timestamp arrivalTime, String port1, String port2) {
  ipV4Packets.add(ipV4Packet);
  packetTimestamps.add(arrivalTime);
  listIsUDP.add(isUDPPacket(ipV4Packet));
  listIsTCP.add(isTCPPacket(ipV4Packet));
  listPort1.add(port1);
  listPort2.add(port2);
  setPredefinedTimeout(ipV4Packet,port1,port2);
  
 }
 
 protected double setPredefinedTimeout(IpV4Packet packet, String port1, String port2) {
  double newTimeout = choosePredefinedTimeout(packet,port1,port2);
  
  //We are taking the max timeout for Multimedia sessions
  if(newTimeout>this.timeout){
   timeout = newTimeout;
   return newTimeout;
  }
  
  return timeout;
 }
 
 @Override
 public void appendPacket(IpV4Packet ipV4Packet, Timestamp arrivalTime) {
  ipV4Packets.add(ipV4Packet);
  packetTimestamps.add(arrivalTime);
  listIsUDP.add(isUDPPacket(ipV4Packet));
  listIsTCP.add(isTCPPacket(ipV4Packet));
  
  int size = listPort1.size()-1;
  String port1 = listPort1.get(size);
  String port2 = listPort2.get(size);
  listPort2.add(port1);
  setPredefinedTimeout(ipV4Packet,port1,port2);
 }

// TODO override methods for discord and may be rename Multimedia
 
 public boolean has (MultimediaSession session){
  String ip1 = session.getIp1();
  String ip2 = session.getIp2();
  
  if (this.ip1.equals(ip1) && this.ip2.equals(ip2))
   return true;
  if (this.ip1.equals(ip2) && this.ip2.equals(ip1))
   return true;
  
  return false;
  
 }
 
 //This should probably not be overridden
// @Override
// public double getSessionDuration() {
//  return super.getSessionDuration();
// }
 
 @Override
 public Timestamp getStartTime() {
 
  //TCP handshake consists of 3 packets: SYN, SYN+ACK and ACK
  //TCP session start time = time of the 3d packet (ACK)
  //if there is was no TCP handshake, then we will take timestamp of the first packet as default.
  Timestamp defaultTimestamp = packetTimestamps.get(0);
  
  int size = ipV4Packets.size();
 
  //First we need a sessions with TCP packets only
  Session tcpSession = getSessionWithTCPOnly();
  
  if (tcpSession!=null){
   //Find start time in the tcpSession
   Timestamp timestamp = tcpSession.getStartTime();
   return timestamp;
  }
  
  return defaultTimestamp;
 }
 
 private Session getSessionWithTCPOnly() {
  
  int size = listIsTCP.size();
  Session tcpSession = new Session(this.ip1, this.listPort1.get(0), this.ip2, this.listPort2.get(0));
  boolean noTCP = true;
  for (int i = 0; i < size; i++) {
   if (listIsTCP.get(i)) {
    tcpSession.appendPacket(ipV4Packets.get(i), packetTimestamps.get(i));
    noTCP=false;
   }
  }
  
  if (noTCP) return null;
  
  return tcpSession;
 }
 
 @Override
 public Timestamp getEndTime() {
  
  int size = ipV4Packets.size();
  //If there is no TCP FIN, we will take time of the last packet
  Timestamp defaultTimestamp = packetTimestamps.get(size-1);
  
  
  //First we need a sessions with TCP packets only
  Session tcpSession = getSessionWithTCPOnly();
  if (tcpSession!=null){
   //Find start time in the tcpSession
   Timestamp timestamp = tcpSession.getEndTime();
   return timestamp;
  }
 
  return defaultTimestamp;
 }
 
 @Override
 public boolean has(String ip1, String port1, String ip2, String port2) {
  
  if (this.ip1.equals(ip1) && this.ip2.equals(ip2)) {
   return true;
  }
  
  if (this.ip1 .equals(ip2) && this.ip2.equals(ip1)){
   return true;
  }
  
  return false;
 }
 
 @Override
 public boolean checkIsFinished() {
  
  Session tcpSession = getSessionWithTCPOnly();
  
  if (tcpSession!=null);
 
  int len = ipV4Packets.size();
  //If we don't find FIN in 10 last packets then there is likely no FIN
  int breakAfter = (len - 1) - 10;
  for (int i = len-1 ; i>=0; i--) {
   //TCP session ends with FIN
   IpV4Packet ipPkt1 = ipV4Packets.get(i);
   try {
    TcpPacket tcpPkt1 = TcpPacket.newPacket(ipPkt1.getPayload().getRawData(), 0, ipPkt1.getPayload().length());
    if (tcpPkt1.getHeader().getFin()) {
     return true;
    }
   } catch (IllegalRawDataException e) {
    e.printStackTrace();
   }
   if (i == breakAfter){
    break;
   }
  }
  return false;
 }
}
