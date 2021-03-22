import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.RadiotapDataTsft;
import org.pcap4j.packet.RadiotapPacket;

import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        String filename = "decrypted.pcap" ;
        String filepath = "C:\\Study\\Magister\\Diploma\\Data";
        String pcapFile =
                new StringBuilder()
                .append(filepath)
                .append("\\")
                .append(filename)
                .toString();

        PcapHandle ph = Pcaps.openOffline(pcapFile);

        ArrayList<Packet> packetList = new ArrayList<>();
        int packetNumber = 0;
        Packet packet= null;
        
        while ((packet = ph.getNextPacket())!= null && packetNumber < 3){
            packetList.add(packet);
            packetNumber++;
            System.out.println("Packet "+packetNumber);
            RadiotapPacket rtPacket = packet.get(RadiotapPacket.class);
            if(rtPacket != null){
                RadiotapPacket.RadiotapHeader rtHeader = rtPacket.getHeader();

                if(rtHeader!=null){
                    ArrayList<RadiotapPacket.RadiotapData> rtDataFields = rtHeader.getDataFields();
                    for (RadiotapPacket.RadiotapData field: rtDataFields){
                        if (!field.toString().equals(null) &&  field.getClass().equals(RadiotapDataTsft.class)){
                            //System.out.println(((RadiotapDataTsft) field).getMacTimestamp());
                            System.out.println(" Field " +field.toString());
                        }
                    }
                }

            }

        }
        System.out.println(packetNumber+
                " packets have been read from "+
                pcapFile);
//        StringBuilder stringBuilder = new StringBuilder(1000);
//        stringBuilder.append(ph.getNextPacket().toString())
//                .append(System.getProperty("line.separator"))
//                .append(ph.getNextPacket().toString());
//
//        ph.close();

        //System.out.println(stringBuilder.toString());

    }
    public boolean findTCPPacket( PcapHandle pcapHandle){
       // pcapHandle.
        return true;
    }
}
