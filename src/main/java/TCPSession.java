import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.sql.Timestamp;
import java.util.ArrayList;

public class TCPSession {
    private String ip1;
    private String port1;
    private String ip2;
    private String port2;
    ArrayList<IpV4Packet>ipV4Packets = new ArrayList<IpV4Packet>();
    ArrayList<Timestamp>packetTimestamps = new ArrayList<Timestamp>();
    ArrayList <Long> packetNums = new ArrayList<>();

    //Get Time delta between 2 timestamps
    public static Double getTimeDelta(Timestamp currFrameTime, Timestamp previousFrameTime) {
        double time_delta = 0;

        //If previous frame didn't have time delta
        if (previousFrameTime != null) {

            int deltaInMs = (int) Math.abs(previousFrameTime.getTime() - currFrameTime.getTime());
            //If delta in seconds is > 0 then we should count seconds together with nano seconds
            if (deltaInMs / 1000 != 0) {
                time_delta = deltaInMs / 1000;
            }
            //If not, then we can simply count delta in nano seconds
            int prevNanos = previousFrameTime.getNanos();
            time_delta += (double) Math.abs(currFrameTime.getNanos() - prevNanos) / 1000000000;


        }
        return time_delta;

    }

    public double getSessionDuration(){
        double dur=0;

        Timestamp start = this.getSessionStartTime();
        Timestamp end = this.getSessionEndTime();

        if ( start!= null && end!=null){
            dur=getTimeDelta(start,end);
        }
        return dur;
    }

    //get timestamp of start (TCP handshake)
    public Timestamp getSessionStartTime() {
        Timestamp timestamp=null;

        int len = ipV4Packets.size()-2;
        for (int i = 0 ; i<len; i++){
            //TCP handshake consists of 3 packets: SYN, SYN+ACK and ACK
            //TCP session start time = time of the 3d packet (ACK)
            IpV4Packet ipPkt1 = ipV4Packets.get(i);
            TcpPacket tcpPkt1 = null;
            try {
                tcpPkt1 = TcpPacket.newPacket(ipPkt1.getPayload().getRawData(),0,ipPkt1.getPayload().length());
                //SYN
                if (tcpPkt1.getHeader().getSyn()){

                    IpV4Packet ipPkt2 = ipV4Packets.get(i+1);
                    TcpPacket tcpPkt2 = TcpPacket.newPacket(ipPkt2.getPayload().getRawData(),
                            0,ipPkt2.getPayload().length());
                    //SYN + ACK
                    if (tcpPkt2.getHeader().getSyn() && tcpPkt2.getHeader().getAck()){

                        IpV4Packet ipPkt3 = ipV4Packets.get(i+2);
                        TcpPacket tcpPkt3 = TcpPacket.newPacket(ipPkt3.getPayload().getRawData(),
                                0,ipPkt3.getPayload().length());
                        //ACK
                        if(tcpPkt3.getHeader().getAck()){
                            return timestamp=packetTimestamps.get(i+2);
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
    public Timestamp getSessionEndTime(){
        Timestamp timestamp=null;

        int len = ipV4Packets.size();
        for (int i = 0 ; i<len; i++) {
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
            packetNums.add(packetNum);
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

    public ArrayList<Long> getPacketNums() {
        return packetNums;
    }
}
