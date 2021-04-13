import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.sql.Timestamp;
import java.util.ArrayList;

public class SimpleSession {
    private String ip1;
    private String ip2;
    private String port1;
    private String port2;
    private boolean isFinished=false;
    private double dur = 0;
    private ArrayList<Double>interPacketTimes=new ArrayList<>();
    private ArrayList<Integer>packetLengths = new ArrayList<>();

    public boolean belongsToSession(String ip1, String port1, String ip2, String port2){
        if (this.ip1.equals(ip1) && this.port1.equals(port1) && this.ip2.equals(ip2) && this.port2.equals(port2))
            return true;
        if (this.ip1.equals(ip2) && this.port1.equals(port2) && this.ip2.equals(ip1) && this.port2.equals(port1))
            return true;

        return false;
    }

    //Adds packet to the session
    public void appendToSession(){
    }
}
