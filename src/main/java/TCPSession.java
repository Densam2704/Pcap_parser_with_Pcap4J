import org.pcap4j.packet.IpV4Packet;

import java.sql.Timestamp;
import java.util.ArrayList;

public class TCPSession {
    private String ip1;
    private String port1;
    private String ip2;
    private String port2;
    ArrayList<IpV4Packet>ipV4Packets = new ArrayList<IpV4Packet>();
    ArrayList<Timestamp>packetTimestamps = new ArrayList<Timestamp>();
    ArrayList <Long>numberInPcap = new ArrayList<>();

    //Check if the ip1:port1 ip2:port2 belong to the TCPSession
    public boolean isInTheSession(String ip1, String port1, String ip2, String port2){
        if (this.ip1.equals(ip1) && this.port1.equals(port1) && this.ip2.equals(ip2) && this.port2.equals(port2))
            return true;
        if (this.ip1.equals(ip2) && this.port1.equals(port2) && this.ip2.equals(ip1) && this.port2.equals(port1))
            return true;

        return false;
    }

    //Adds packet to the session
    public void appendPacket(IpV4Packet ipV4Packet, Timestamp arrivalTime, long packetNum){
            ipV4Packets.add(ipV4Packet);
            packetTimestamps.add(arrivalTime);
            numberInPcap.add(packetNum);
    }


    // Constructors

    public TCPSession() {
    }

    public TCPSession(String ip1, String port1, String ip2, String port2) {
        this.ip1 = ip1;
        this.port1 = port1;
        this.ip2 = ip2;
        this.port2 = port2;
    }

    //Getters and Setters

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

    public ArrayList<Long> getNumberInPcap() {
        return numberInPcap;
    }
}
