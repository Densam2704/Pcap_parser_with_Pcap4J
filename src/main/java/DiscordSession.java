import org.pcap4j.packet.IpV4Packet;

import java.sql.Timestamp;
import java.util.ArrayList;

public class DiscordSession extends Session {
 private ArrayList<String> listPort1 = new ArrayList<>();
 private ArrayList<String> listPort2 = new ArrayList<>();
 private ArrayList<Boolean>listIsTCP = new ArrayList<>();
 private ArrayList<Boolean>listIsUDP = new ArrayList<>();
 private ArrayList<Double>timeouts = new ArrayList<>();
 
 public DiscordSession() {
 }
 
 public DiscordSession(String ip1, String port1, String ip2, String port2) {
  super(ip1, port1, ip2, port2);
  this.listPort1.add(port1);
  this.listPort2.add(port2);
 }
 
 public DiscordSession(Session s){
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
  listIsUDP.add(checkIsUDP(ipV4Packet));
  listIsTCP.add(checkIsTCP(ipV4Packet));
  listPort1.add(port1);
  listPort2.add(port2);
  timeouts.add(chooseTimeout(ipV4Packet,port1,port2));
 }
 
 
 @Override
 public double getSessionDuration() {
  return super.getSessionDuration();
 }
 
 @Override
 public Timestamp getStartTime() {
  return super.getStartTime();
 }
 
 @Override
 public Timestamp getEndTime() {
  return super.getEndTime();
 }
 
 @Override
 public boolean isInTheSession(String ip1, String port1, String ip2, String port2) {
  return super.isInTheSession(ip1, port1, ip2, port2);
 }
}
