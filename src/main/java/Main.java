
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

        String staFilename = "sta.pcap";
        String staFilepath = "C:\\Study\\Magister\\Diploma\\Data";
        String staPcapFile =
                new StringBuilder()
                        .append(staFilepath)
                        .append("\\")
                        .append(staFilename)
                        .toString();


        //String apFileName = "sta.pcap";
        //String apFileName = "packet6754.pcap";
        //String apFileName = "decrypted2.pcap" ;
        //String apFileName = "tcp_only.pcap";
        //String apFileName = "notDecrypted.pcap" ;
        String apFileName = "exported2.pcap" ;
        String apFilePath = "C:\\Study\\Magister\\Diploma\\Data";
        String apPcapFile =
                new StringBuilder()
                .append(apFilePath)
                .append("\\")
                .append(apFileName)
                .toString();

        //readStaPcap(staPcapFile);
        readApPcap(apPcapFile);


// This part is to be rewritten or replaced with PcapManager class.
//        if(true)return;
//
//        //String apFileName = "sta.pcap";
//        //String apFileName = "packet6754.pcap";
//        //String apFileName = "decrypted2.pcap" ;
//        String apFileName = "tcp_only.pcap";
//        //String apFileName = "notDecrypted.pcap" ;
//        String apFilePath = "C:\\Study\\Magister\\Diploma\\Data";
//        String apPcapFile =
//                new StringBuilder()
//                .append(apFilePath)
//                .append("\\")
//                .append(apFileName)
//                .toString();
//
//        PcapHandle ap_ph = Pcaps.openOffline(apPcapFile);
//
//        ArrayList<Packet> packetList = new ArrayList<>();
//        int packetNumber = 0;
//        Packet packet= null;
//        while ((packet = ap_ph.getNextPacket())!= null ){
//            packetList.add(packet);
//            packetNumber++;
//            System.out.println("Packet "+packetNumber);
//
//
//            byte[] rawData = packet.getRawData();
//
////            int lengthRawData = rawData.length;
////            ArrayList<Byte> editedRawData = new ArrayList<Byte>();
////            if (lengthRawData > 0){
////                for (int i = 0; i < lengthRawData; i++){
////                    //If there is a IPv4 byte sequence
////                    if (rawData[i]==0x00 && rawData[i+1]==0x45
////                            && rawData[i+2]==0x00){
//////                        for (int j = i+1; j < lengthRawData; j++){
//////                            editedRawData.add(rawData[j]);
//////                        }
////                        for (int j = 0; j < lengthRawData - i - 1)
////                        System.out.println(" IP packet found");
////                        break;
////                    }
////                }
////            }
////            for( int i = 0 ; i < editedRawData.size(); i++){
////
////            }
////            IpV4Packet ipV4Packet = IpV4Packet.newPacket(editedRawData.toArray(byte[]))
//
//
//            System.out.println(packet.toString());
//
//                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
//                if (ipPacket != null){
//                    System.out.println("IPPACKET " + ipPacket.toString());
//                    TcpPacket tcpPacket= ipPacket.get(TcpPacket.class);
//                    if(tcpPacket != null && tcpPacket.getPayload() != null)
//                    {
//                        System.out.println(tcpPacket.toString());
//                    }
//                }
//            if (packetNumber==3){break;}
//
////          // Procedure of getting TSFT
////            RadiotapPacket rtPacket = packet.get(RadiotapPacket.class);
////            if(rtPacket != null){
////                RadiotapPacket.RadiotapHeader rtHeader = rtPacket.getHeader();
////
////                if(rtHeader!=null){
////                    ArrayList<RadiotapPacket.RadiotapData> rtDataFields = rtHeader.getDataFields();
////                    for (RadiotapPacket.RadiotapData field: rtDataFields){
////                        //Here we are looking for a TSFT field from Radiotap
////                        if (!field.toString().equals(null) &&  field.getClass().equals(RadiotapDataTsft.class)){
////                            //System.out.println(((RadiotapDataTsft) field).getMacTimestamp());
////                            System.out.println(" Field " +field.toString());
////                        }
////                    }
////                }
////
////            }
//
//        }
//        System.out.println(packetNumber + " packets have been read from " + apPcapFile);
//        //String builder from example
////        StringBuilder stringBuilder = new StringBuilder(1000);
////        stringBuilder.append(ap_ph.getNextPacket().toString())
////                .append(System.getProperty("line.separator"))
////                .append(ap_ph.getNextPacket().toString());
////
////        ap_ph.close();
//
//        //System.out.println(stringBuilder.toString());

    }

    private static void readStaPcap(String staPcapFile) throws PcapNativeException, NotOpenException {
        PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);
        PcapManager staPcapManager = new PcapManager(staPcapFile,ConstantsIface.STATION);

        //ArrayList<Packet> packets = new ArrayList<>();

        int packetNumber = 0;
        Packet packet = null;
        while ((packet = staPh.getNextPacket()) != null) {
            //packets.add(packet);
            packetNumber++;
            System.out.println("Packet "+packetNumber);
            System.out.println("Time:\n"+staPcapManager.getArrivalTime(staPh));
            //System.out.println(packet.toString());

        }
        System.out.println(packetNumber + " packets have been read from " + staPcapFile);
        staPh.close();
    }

    private static void readApPcap (String apPcapFile) throws NotOpenException, PcapNativeException {
        PcapHandle apPh = Pcaps.openOffline(apPcapFile, PcapHandle.TimestampPrecision.NANO);
        PcapManager apPcapManager = new PcapManager(apPcapFile,ConstantsIface.ACCESS_POINT);

        //ArrayList<Packet> packets = new ArrayList<>();

        int packetNumber = 0;
        Packet packet = null;
        while ((packet = apPh.getNextPacket()) != null) {
            //packets.add(packet);
            packetNumber++;
            System.out.println("Packet "+packetNumber);
            System.out.println("TSFT:\n"+apPcapManager.getTSFT(packet));
            System.out.println(packet.toString());

        }
        System.out.println(packetNumber + " packets have been read from " + apPcapFile);
        apPh.close();

    }

}
