import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.util.ArrayList;

public class Session implements Constants {
  protected String ip1;
  protected String ip2;
  
  private String port1;
  private String port2;
  
  protected ArrayList<IpV4Packet> ipV4Packets = new ArrayList<IpV4Packet>();
  protected ArrayList<Timestamp> packetTimestamps = new ArrayList<Timestamp>();
  protected double timeout = -1;
  
  private boolean isTCP = false;
  private boolean isUDP = false;
  
  //Set timeout value for  session
//      if port is well-known value then timeout is short
//      else timeout is long or medium depending on TCP/UDP port
  protected double choosePredefinedTimeout(IpV4Packet packet, String port1, String port2) {
	double timeout = 0;
	//default timeouts for non-port-specific sessions
	if (isTCPPacket(packet))
	  //for tcp
	  timeout = TIMEOUT_LONG;
	if (isUDPPacket(packet))
	  //for udp and icmp
	  timeout = TIMEOUT_MEDIUM;
	
	//Short timeouts for port-specific sessions
	//if ip1 in our network then check ip2:port2
	if ((ipToHex(ip1) & TESTBED_MASK) == (TESTBED_HEX_SUBNET & TESTBED_MASK)) {
	  int intPort2 = Integer.parseInt(port2);
	  // if it's common port
	  if (intPort2 >= 0 && intPort2 <= 49151) {
		timeout = TIMEOUT_SHORT;
	  }
	} else {
	  //if ip2 in our network then check ip1:port
	  if ((ipToHex(ip2) & TESTBED_MASK) == (TESTBED_HEX_SUBNET & TESTBED_MASK)) {
		
		int intPort1 = Integer.parseInt(port1);
		// if it's common port
		if (intPort1 > 0 && intPort1 < 49151) {
		  timeout = TIMEOUT_SHORT;
		}
	  }
	}
	return timeout;
	
  }
  
  //Convert string ip to int hex value. See more:
  //https://stackoverflow.com/questions/4209760/validate-an-ip-address-with-mask
  public int ipToHex(String ip) {
	Inet4Address inet4Address = null;
	try {
	  inet4Address = (Inet4Address) Inet4Address.getByName(ip);
	  
	  byte[] bytes = inet4Address.getAddress();
	  
	  int hex = ((bytes[0] & 0xFF) << 24) |
			  ((bytes[1] & 0xFF) << 16) |
			  ((bytes[2] & 0xFF) << 8) |
			  ((bytes[3] & 0xFF) << 0);
	  return hex;
	} catch (UnknownHostException e) {
	  e.printStackTrace();
	}
	return 0;
  }
  
  public boolean checkIsTelegram() {
	
	if ((TELEGRAM_HEX_SUBNET & TELEGRAM_MASK) == (ipToHex(ip1) & TELEGRAM_MASK)) {
	  return true;
	  
	}
      return (TELEGRAM_HEX_SUBNET & TELEGRAM_MASK) == (ipToHex(ip2) & TELEGRAM_MASK);
  }
  
  public boolean checkIsDiscord() {
	
	if ((DISCORD_HEX_SUBNET & DISCORD_MASK) == (ipToHex(ip1) & DISCORD_MASK)) {
	  return true;
	}
      return (DISCORD_HEX_SUBNET & DISCORD_MASK) == (ipToHex(ip2) & DISCORD_MASK);
  }
  
  public boolean checkIsTelegram(String ip1, String ip2) {
	
	if ((TELEGRAM_HEX_SUBNET & TELEGRAM_MASK) == (ipToHex(ip1) & TELEGRAM_MASK)) {
	  return true;
	  
	}
      return (TELEGRAM_HEX_SUBNET & TELEGRAM_MASK) == (ipToHex(ip2) & TELEGRAM_MASK);
  }
  
  public boolean checkIsDiscord(String ip1, String ip2) {
	
	if ((DISCORD_HEX_SUBNET & DISCORD_MASK) == (ipToHex(ip1) & DISCORD_MASK)) {
	  return true;
	}
      return (DISCORD_HEX_SUBNET & DISCORD_MASK) == (ipToHex(ip2) & DISCORD_MASK);
  }
  
  //Checks if last added packet in session is added later than timeout
  public boolean checkIsTooLong(Timestamp currPktTimestamp) {
	
	int sessionSize = packetTimestamps.size();
	Timestamp lastTmstmpInSession = packetTimestamps.get(sessionSize - 1);

//        System.out.printf("currPktTimestamp = %s\n",currPktTimestamp.toString());
//        System.out.printf("lastTmstmpInSession = %s\n",lastTmstmpInSession.toString());
	Double difference = getTimeDelta(currPktTimestamp, lastTmstmpInSession);
//        System.out.printf("Session lasts = %.6f\n",difference);
	if (timeout < 0)
	  choosePredefinedTimeout(ipV4Packets.get(sessionSize - 1), port1, port2);
      return difference > timeout;
  }
  
  //Look for FIN tcp. Returns true if FIN is found.
  public boolean checkIsFinished() {
	if (!isTCP)
	  return false;
	
	int len = ipV4Packets.size();
	//If we don't find FIN in 10 last packets then there is likely no FIN
	int breakAfter = (len - 1) - 10;
	for (int i = len - 1; i >= 0; i--) {
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
	  if (i == breakAfter) {
		break;
	  }
	}
	return false;
  }
  
  //Get Time difference (a.k.a. delta) between 2 timestamps
  public Double getTimeDelta(Timestamp time1, Timestamp time2) {
	double time_delta = 0;
	
	//If both timestamps are not null
	if (time1 != null && time2 != null) {
	  
	  int deltaInMs = (int) Math.abs(time2.getTime() - time1.getTime());
	  //If delta in seconds is > 0 then we should count seconds together with nano seconds
	  if (deltaInMs / 1000 != 0) {
		time_delta = deltaInMs / 1000;
	  }
	  //If not, then we can simply count delta in nano seconds
	  int time2Nanos = time2.getNanos();
	  time_delta += (double) Math.abs(time1.getNanos() - time2Nanos) / 1000000000;
	  
	  
	}
	return time_delta;
	
  }
  
  public double getSessionDuration() {
	double dur = 0;
	
	Timestamp start = this.getStartTime();
	Timestamp end = this.getEndTime();
	
	if (start != null && end != null) {
	  dur = getTimeDelta(start, end);
	}
	return dur;
  }
  
  //get timestamp of start (TCP handshake)
  public Timestamp getStartTime() {
	//if there is no handshake, then we will take timestamp of the first packet
	Timestamp timestamp = packetTimestamps.get(0);
	
	if (!isTCP)
	  return timestamp;
	
	int len = ipV4Packets.size() - 2;
	for (int i = 0; i < len; i++) {
	  //TCP handshake consists of 3 packets: SYN, SYN+ACK and ACK
	  //TCP session start time = time of the 3d packet (ACK)
	  IpV4Packet ipPkt1 = ipV4Packets.get(i);
	  TcpPacket tcpPkt1 = null;
	  try {
		tcpPkt1 = TcpPacket.newPacket(ipPkt1.getPayload().getRawData(), 0, ipPkt1.getPayload().length());
		//SYN
		if (tcpPkt1.getHeader().getSyn()) {
		  
		  IpV4Packet ipPkt2 = ipV4Packets.get(i + 1);
		  TcpPacket tcpPkt2 = TcpPacket.newPacket(ipPkt2.getPayload().getRawData(),
				  0, ipPkt2.getPayload().length());
		  //SYN + ACK
		  if (tcpPkt2.getHeader().getSyn() && tcpPkt2.getHeader().getAck()) {
			
			IpV4Packet ipPkt3 = ipV4Packets.get(i + 2);
			TcpPacket tcpPkt3 = TcpPacket.newPacket(ipPkt3.getPayload().getRawData(),
					0, ipPkt3.getPayload().length());
			//ACK
			if (tcpPkt3.getHeader().getAck()) {
			  //return timestamp of handshake
			  return timestamp = packetTimestamps.get(i + 2);
			}
		  }
		}
	  } catch (IllegalRawDataException e) {
		e.printStackTrace();
	  }
	  
	}
	
	
	return timestamp;
  }
  
  //get timestamp of end (TCP FIN)
  public Timestamp getEndTime() {
	//If there is no FIN, we will take time of the last packet
	Timestamp timestamp = packetTimestamps.get(packetTimestamps.size() - 1);
	if (!isTCP)
	  return timestamp;
	int len = ipV4Packets.size();
	for (int i = len - 1; i >= 0; i--) {
	  //TCP session ends with FIN
	  IpV4Packet ipPkt1 = ipV4Packets.get(i);
	  try {
		TcpPacket tcpPkt1 = TcpPacket.newPacket(ipPkt1.getPayload().getRawData(), 0, ipPkt1.getPayload().length());
		if (tcpPkt1.getHeader().getFin()) {
		  return timestamp = packetTimestamps.get(i);
		}
	  } catch (IllegalRawDataException e) {
		e.printStackTrace();
	  }
	}
	
	return timestamp;
  }
  
  //Check if the ip1:port1 ip2:port2 belong to the Session
  public boolean has(String ip1, String port1, String ip2, String port2) {
	if (this.ip1.equals(ip1) && this.port1.equals(port1) && this.ip2.equals(ip2) && this.port2.equals(port2))
	  return true;
      return this.ip1.equals(ip2) && this.port1.equals(port2) && this.ip2.equals(ip1) && this.port2.equals(port1);
  }
  
  //Check if the ip1:port1 ip2:port2 belong to the Session
  public boolean has(Session s) {
	
	String ip1 = s.getIp1();
	String ip2 = s.getIp2();
	String port1 = s.getPort1();
	String port2 = s.getPort2();
	
	if (this.ip1.equals(ip1) && this.port1.equals(port1) && this.ip2.equals(ip2) && this.port2.equals(port2))
	  return true;
      return this.ip1.equals(ip2) && this.port1.equals(port2) && this.ip2.equals(ip1) && this.port2.equals(port1);
  }
  
  //Adds packet to the session
  public void appendPacket(IpV4Packet ipV4Packet, Timestamp arrivalTime) {
	ipV4Packets.add(ipV4Packet);
	packetTimestamps.add(arrivalTime);
	if (isFirstPacketInSession()) {
	  isTCP = isTCPPacket(ipV4Packet);
	  isUDP = isUDPPacket(ipV4Packet);
	  timeout = choosePredefinedTimeout(ipV4Packet, port1, port2);
	}
	
  }
  
  //
  private boolean isFirstPacketInSession() {
      return ipV4Packets.size() == 1;
  }
  
  protected boolean isTCPPacket(IpV4Packet packet) {
      return packet.getHeader().getProtocol().toString().equals(TCP_STRING);
  }
  
  protected boolean isUDPPacket(IpV4Packet packet) {
	if (packet.getHeader().getProtocol().toString().equals(UDP_STRING)) {
	  return true;
	}
	//ICMPv4 contains UDP, so we count it as UDP
      return packet.getHeader().getProtocol().toString().equals(ICMPv4_STRING);
  }
  
  
  // Constructors
  
  public Session() {
  }
  
  
  public Session(String ip1, String port1, String ip2, String port2) {
	
	this.ip1 = ip1;
	this.port1 = port1;
	this.ip2 = ip2;
	this.port2 = port2;
	
  }
  
  //Getters and Setters
  
  public boolean isTCP() {
	return isTCP;
  }
  
  public boolean isUDP() {
	return isUDP;
  }
  
  public double getTimeout() {
	return timeout;
  }
  
  public String getIp1() {
	return ip1;
  }
  
  public void setIp1(String ip1) {
	this.ip1 = ip1;
  }
  
  public String getPort1() {
	return port1;
  }
  
  public void setPort1(String port1) {
	this.port1 = port1;
  }
  
  public String getIp2() {
	return ip2;
  }
  
  public void setIp2(String ip2) {
	this.ip2 = ip2;
  }
  
  public String getPort2() {
	return port2;
  }
  
  public void setPort2(String port2) {
	this.port2 = port2;
  }
  
  public ArrayList<IpV4Packet> getIpV4Packets() {
	return ipV4Packets;
  }
  
  public ArrayList<Timestamp> getPacketTimestamps() {
	return packetTimestamps;
  }
  
}
