
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.Dot11FrameType;

import java.io.EOFException;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.text.Format;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.TimeoutException;

public class Main {

    public static void main(String[] args) throws PcapNativeException, NotOpenException, EOFException, TimeoutException {

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
        String apFileName = "ap.pcap" ;
        //String apFileName = "exported2.pcap" ;
        String apFilePath = "C:\\Study\\Magister\\Diploma\\Data";
        String apPcapFile =
                new StringBuilder()
                .append(apFilePath)
                .append("\\")
                .append(apFileName)
                .toString();

        //readStaPcap(staPcapFile);
        //readApPcap(apPcapFile);
        //find_1(staPcapFile);
        find_2(apPcapFile);


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
    //1 time delta from previous captured frame. (packets from Station)
    private static void  find_1 (String staPcapFile) throws PcapNativeException, NotOpenException {

        PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);

        int packetNumber = 0;
        Packet packet = null;
        Timestamp previousCapturedFrameTime=null;
        //Timestamp previousDisplayedFrameTime=null;
        while ((packet = staPh.getNextPacket()) != null) {
            packetNumber++;
            boolean isFromStation=false;
            try {
                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                if(ipV4Packet.getHeader().getSrcAddr().equals(InetAddress.getByName("192.0.2.12")))
                    isFromStation=true;
            }
            catch (Exception e){

            }
            //If packet is from STA with IP 192.0.2.12
            if (isFromStation){
                double time_delta=getTimeDelta(staPh,previousCapturedFrameTime);
                System.out.println(String.format(packetNumber+ " \nTime from previous captured frame = %.9f",time_delta));
                //TODO export time_delta to somewhere
            }
            previousCapturedFrameTime=staPh.getTimestamp();
        }
        staPh.close();
        System.out.println(packetNumber + " packets have been read from " + staPcapFile);

    }
    //packet time delta from Station to Access Point (AP side)
    private static void find_2 (String apPcapFile)throws PcapNativeException, NotOpenException {
        PcapHandle apPh = Pcaps.openOffline(apPcapFile, PcapHandle.TimestampPrecision.NANO);

        int packetNumber = 0;
        int filteredPackets=0;
        Packet packet = null;
        //TODO make MACs as constants, or MACs as variables from function
        //AP MAC
        String MAC0="00c0ca98dfdf";//00:c0:ca:98:df:df
        //Sta1
        String MAC1 = "803049236661";//80:30:49:23:66:61
        //Sta2
        String MAC2 = "049226344fff";//04:92:26:34:4f:ff

        Timestamp previousCapturedFrameTime = null;

        while ((packet=apPh.getNextPacket()) != null) {
            //packets.add(packet);
            packetNumber++;

            RadiotapPacket radiotapPacket = packet.get(RadiotapPacket.class);
            try {
                if(radiotapPacket!=null){
//                    System.out.println("Получен radiotap");
//                    System.out.println(radiotapPacket.toString());
                    byte[] payload = radiotapPacket.getPayload().getRawData();

                    //This gives a little bit more packets than wireshark (for ap.pcap 6308 instead of 6295)
                    //Don't know why this happens
                    short wlanAddrLen=6;
                    //Source address position in payload
                    short wlanSaPos=10;

                    //There is a case when source address is a 4th address in a WLAN frame
                    if (payload[0]==0x08 && payload[1]==0x42){
                        wlanSaPos=16;
                    }

                    byte[]byteWlanSa = new byte [wlanAddrLen];
                    System.arraycopy(payload,wlanSaPos,byteWlanSa,0,wlanAddrLen);
                    String wlanSa = byteArrayToHex(byteWlanSa);
//
                    if (wlanSa.equals(MAC1)||wlanSa.equals(MAC2)){
                        System.out.println("THIS IS OUR FRAME");
                        filteredPackets++;
                        double time_delta=getTimeDelta(apPh,previousCapturedFrameTime);
                        System.out.println(String.format(packetNumber+ " \nTime from previous captured frame = %.9f",time_delta));

                        System.out.println("wlan source address: " + wlanSa);
                        System.out.println("payload: "+ byteArrayToHex(payload));
                        //TODO export time_delta to somewhere
                    }
                    else
                    {
//                        System.out.println(packetNumber);
//                        System.out.println("wlan source address: " + wlanSa);
//                        System.out.println("payload: "+ byteArrayToHex(payload));
                    }

                }

            }
            catch (Exception e){

            }
            previousCapturedFrameTime=apPh.getTimestamp();

        }
        System.out.println(filteredPackets + " packets were captured from our stations " + apPcapFile);
        System.out.println(packetNumber + " packets have been read from " + apPcapFile);
        apPh.close();
    }
    //find_3_1
    private static void readStaPcap(String staPcapFile) throws PcapNativeException, NotOpenException {
        PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);
       // PcapManager staPcapManager = new PcapManager(staPcapFile,ConstantsIface.STATION);

        //ArrayList<Packet> packets = new ArrayList<>();

        int packetNumber = 0;
        Packet packet = null;
        while ((packet = staPh.getNextPacket()) != null) {
            //packets.add(packet);
            packetNumber++;
            System.out.println("Packet "+packetNumber);
           // System.out.println("Time:\n"+staPcapManager.getArrivalTime(staPh));
            //System.out.println(packet.toString());

        }
        System.out.println(packetNumber + " packets have been read from " + staPcapFile);
        staPh.close();
    }

    //3.2
    private static void readApPcap (String apPcapFile) throws NotOpenException, PcapNativeException, EOFException, TimeoutException {
        PcapHandle apPh = Pcaps.openOffline(apPcapFile, PcapHandle.TimestampPrecision.NANO);


        //ArrayList<Packet> packets = new ArrayList<>();

        int packetNumber = 0;
        int tcpPacketsNum=0;
        Packet packet = null;
        //apPh.setFilter("src host 192.0.2.12", BpfProgram.BpfCompileMode.NONOPTIMIZE);
        while ((packet=apPh.getNextPacket()) != null) {
            //packets.add(packet);
            packetNumber++;

//            System.out.println("Packet "+packetNumber);
//            System.out.println("TSFT:\n"+apPcapManager.getTSFT(packet));
//            System.out.println(packet.toString());

            RadiotapPacket radiotapPacket = packet.get(RadiotapPacket.class);
            try {
                if(radiotapPacket!=null){
//                    System.out.println("Получен radiotap");
//                    System.out.println(radiotapPacket.toString());
                    byte[] payload = radiotapPacket.getPayload().getRawData();
                    Dot11FrameType type = Dot11FrameType.getInstance(
                            (byte) (((payload[0] << 2) & 0x30) | ((payload[0] >> 4) & 0x0F))
                    );
                    //Смотрим IEEE802.11 Type/Subtipe
                    switch (type.value()) {
                        case 0: // assoc-req
                            System.out.println("assoc-req");
                            break;
                        case 0x0020:
                            //IEEE802.11 data frames
                            System.out.println("Wlan data frame");
                            //Пропускаем поля IEEE802.11, которые для типа кадра Data занимают 32 байта
                            //Пример как побайтово читать пакет
//                            int payload2Length=payload.length-32;
//                            byte[]payload2= new byte[payload.length-32];
//                            System.arraycopy(payload,32,payload2,0,payload2Length);
//                            System.out.println( byteArrayToHex( payload2));
                            int wlanAddrLen = 6;

                            byte[]wlanDA = new byte [wlanAddrLen];
                            System.arraycopy(payload,16,wlanDA,0,wlanAddrLen);
                            System.out.println("wlan destination address: " + byteArrayToHex(wlanDA));

                            byte[]wlanSA = new byte [wlanAddrLen];
                            System.arraycopy(payload,10,wlanSA,0,wlanAddrLen);
                            System.out.println("wlan source address: " + byteArrayToHex(wlanSA));
                            System.out.println("payload: "+ byteArrayToHex(payload));
                            //System.out.println("Payload [49]" +byteArrayToHex(Arrays.copyOfRange(payload,49,payload.length)));


                            byte[]checksumTCP = new byte[]{0x0,0x0};
                            //if  IPv4 and IPv4 protocol field == TCP
                            if (payload[40]==0x45 && payload[49]==0x06){
                                //System.out.println("Packet "+packetNumber);
                                tcpPacketsNum++;
                                System.arraycopy(payload,76,checksumTCP,0,2);
                                System.out.println("TCP Checksum " + byteArrayToHex(checksumTCP));
                            }

                            break;
                        default:
//                            System.out.println("Not handling frame type  "+ type.value());
//                            System.out.println("Type: "+ type.value()+", Header: "+
//                                    radiotapPacket.getHeader().getRawData().length+
//                                    "bytes, Payload: length  "+payload.length);
                    }
                }
            }catch (Exception e){

            }

        }
        System.out.println(tcpPacketsNum + " tcp packets have been read from " + apPcapFile);
        System.out.println(packetNumber + " packets have been read from " + apPcapFile);
        apPh.close();

    }
    //Convert byte array to string
    //https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    //Get Time delta from previous frame
    public static Double getTimeDelta(PcapHandle ph, Timestamp previousFrameTime) {
        double time_delta = 0;

        //If previous frame didn't have time delta
        if (previousFrameTime != null) {

            int deltaInMs = (int) Math.abs(previousFrameTime.getTime() - ph.getTimestamp().getTime());
            //If delta in seconds is > 0 then we should count seconds together with nano seconds
            if (deltaInMs / 1000 != 0) {
                time_delta = deltaInMs / 1000;
            }
            //If not, then we can simply count delta in nano seconds
            int prevNanos = previousFrameTime.getNanos();
            time_delta += (double) Math.abs(ph.getTimestamp().getNanos() - prevNanos) / 1000000000;


        }
        return time_delta;

    }

}
