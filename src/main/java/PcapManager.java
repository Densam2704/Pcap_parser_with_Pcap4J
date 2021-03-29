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
    // Access Point or Station
    private String trafficSource;

    public PcapManager(String fullFileName, String trafficSource) {
        this.fullFileName = fullFileName;
        this.trafficSource = trafficSource;
    }

    public PcapManager() {
    }

    public String getFullFileName() {
        return fullFileName;
    }

    public void setFullFileName(String fullFileName) {
        this.fullFileName = fullFileName;
    }

    public String getTrafficSource() {
        return trafficSource;
    }

    public void setTrafficSource(String trafficSource) {
        this.trafficSource = trafficSource;
    }

    public long getArrivalTime(PcapHandle ph){
        long arrivalTime= 0;
        if (trafficSource.equals(ConstantsIface.STATION)){
            arrivalTime =  ph.getTimestamp().getTime();

        }
        return arrivalTime;
    }
        public BigInteger getTSFT (Packet packet){

            BigInteger arrivalTime= new BigInteger("0");
            //We have to check that traffic is collected in Monitor mode, which was used only in AP traffic
        if (trafficSource.equals(ConstantsIface.ACCESS_POINT)&&packet!=null){
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
