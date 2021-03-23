import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.RadiotapDataTsft;
import org.pcap4j.packet.RadiotapPacket;

import java.math.BigInteger;
import java.util.ArrayList;

public class PcapManager {
    //File path + file name
    private String fullFileName;
    //Pcap Handle for working with pcap file
    private PcapHandle ph;
    // Access Point or Station
    private String trafficSource;

    public PcapManager(String fullFileName, PcapHandle ph, String trafficSource) {
        this.fullFileName = fullFileName;
        this.ph = ph;
        this.trafficSource = trafficSource;
    }

//    public PcapManager(String fullFileName, String trafficSource) {
//        this.fullFileName = fullFileName;
//        this.trafficSource = trafficSource;
//    }

    public PcapManager() {
    }

    public String getFullFileName() {
        return fullFileName;
    }

    public void setFullFileName(String fullFileName) {
        this.fullFileName = fullFileName;
    }

    public PcapHandle getPh() {
        return ph;
    }

    public void setPh(PcapHandle ph) {
        this.ph = ph;
    }

    public String getTrafficSource() {
        return trafficSource;
    }

    public void setTrafficSource(String trafficSource) {
        this.trafficSource = trafficSource;
    }

    public ArrayList<Packet> getPacketArrayList(boolean ShowEachPacket) throws NotOpenException {
        ArrayList<Packet> packets = new ArrayList<>();

        int packetNumber = 0;
        Packet packet = null;
        while ((packet = ph.getNextPacket()) != null) {
            if (ShowEachPacket) {
                System.out.println("Packet "+packetNumber);
                System.out.println("Time:\n"+ph.getTimestamp());
                System.out.println(packet.toString());
            }
            packets.add(packet);
            packetNumber++;

        }
        System.out.println(packetNumber + " packets have been read from " + fullFileName);
        return packets;
    }
    public BigInteger getArrivalTime(Packet packet){
        BigInteger arrivalTime= new BigInteger("0");
        if (trafficSource.equals(ConstantsIface.STATION)){


        }
        if (trafficSource.equals(ConstantsIface.ACCESS_POINT)){
            RadiotapPacket rtPacket = packet.get(RadiotapPacket.class);
            if(rtPacket != null){
                RadiotapPacket.RadiotapHeader rtHeader = rtPacket.getHeader();

                if(rtHeader!=null){
                    ArrayList<RadiotapPacket.RadiotapData> rtDataFields = rtHeader.getDataFields();
                    for (RadiotapPacket.RadiotapData field: rtDataFields){
                        //Here we are looking for a TSFT field from Radiotap
                        if (!field.toString().equals(null) &&  field.getClass().equals(RadiotapDataTsft.class)){
                            return arrivalTime=((RadiotapDataTsft) field).getMacTimestamp();
                            //System.out.println(((RadiotapDataTsft) field).getMacTimestamp());
                           // System.out.println(" Field " +field.toString());
                        }
                    }
                }

            }
        }
        return arrivalTime;
    }
}
