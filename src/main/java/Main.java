
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

        String sta_filename = "sta.pcap";
        String sta_filepath = "C:\\Study\\Magister\\Diploma\\Data";
        String sta_pcapFile =
                new StringBuilder()
                        .append(sta_filepath)
                        .append("\\")
                        .append(sta_filename)
                        .toString();
        PcapHandle sta_ph = Pcaps.openOffline(sta_pcapFile, PcapHandle.TimestampPrecision.NANO);
        PcapManager staPcapManager = new PcapManager(sta_pcapFile,sta_ph,ConstantsIface.STATION);
        ArrayList<Packet>packets=staPcapManager.getPacketArrayList(true);





// This part is to be rewritten or replaced with PcapManager class.
//        if(true)return;
//
//        //String filename = "sta.pcap";
//        //String filename = "packet6754.pcap";
//        //String filename = "decrypted2.pcap" ;
//        String filename = "tcp_only.pcap";
//        //String filename = "notDecrypted.pcap" ;
//        String filepath = "C:\\Study\\Magister\\Diploma\\Data";
//        String pcapFile =
//                new StringBuilder()
//                .append(filepath)
//                .append("\\")
//                .append(filename)
//                .toString();
//
//        PcapHandle ap_ph = Pcaps.openOffline(pcapFile);
//
//        ArrayList<Packet> packetList = new ArrayList<>();
//        int packetNumber = 0;
//        Packet packet= null;
//        while ((packet = ap_ph.getNextPacket())!= null ){
//            packetList.add(packet);
//            packetNumber++;
//            System.out.println("Packet "+packetNumber);
//
//            //Попытка удалить ненужную последовательность байт
//            //Скорее всего лажа, потому что не будет части байтов. И в конце нарушится контрольная сумма кадров.
//            //Плюс еще и недописано.
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
//        System.out.println(packetNumber + " packets have been read from " + pcapFile);
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

}
