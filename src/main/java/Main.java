// This program uses library from
// https://github.com/kaitoy/pcap4j
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.Dot11FrameType;

import java.io.EOFException;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.concurrent.TimeoutException;

public class Main {

    public static String resultFile1;
    public static String resultFile2;
    public static String staPcapFile;
    public static String apPcapFile;

    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {


        String staFilepath = "C:\\Study\\Magister\\Diploma\\Data";
        String staFilename = "sta.pcap";
         staPcapFile = staFilepath + "\\" + staFilename;


        String apFilePath = "C:\\Study\\Magister\\Diploma\\Data";
        String apFileName = "ap.pcap" ;
        //String apFileName = "sta.pcap";
        //String apFileName = "packet6754.pcap";
        //String apFileName = "decrypted2.pcap" ;
        //String apFileName = "tcp_only.pcap";
        //String apFileName = "exported2.pcap" ;

         apPcapFile = apFilePath + "\\" + apFileName;

        resultFile1 = "C:\\Study\\Magister\\Diploma\\Data\\"
                + "time delta from previous captured frame. (packets from STA to AP) (STA side)"
                + ".txt" ;
        resultFile2 = "C:\\Study\\Magister\\Diploma\\Data\\"
                + "time delta from previous captured frame. (packets from STA to AP) (AP side)"
                + ".txt" ;

        find_1();
        find_2();
       // find_3_1(staPcapFile,apPcapFile);
       // find_3_2(staPcapFile,apPcapFile);


// This part will be deleted,rewritten or replaced with PcapManager class.

        //readStaPcap(staPcapFile);
        //readApPcap(apPcapFile);
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
    //1 time delta from previous captured frame. (packets from Station to AP) (Station side)
    private static void  find_1 () throws PcapNativeException, NotOpenException, IOException {

        PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);

        FileWriter writer = new FileWriter(resultFile1,false);
        int packetNumber = 0;
        Packet packet = null;
        Timestamp previousCapturedFrameTime=null;
        //Timestamp previousDisplayedFrameTime=null;
        while ((packet = staPh.getNextPacket()) != null) {
            packetNumber++;
            boolean isFromStation=false;
            try {
                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                if(ipV4Packet.getHeader().getSrcAddr().equals(InetAddress.getByName(ConstantsIface.STA1_IPv4)))
                    isFromStation=true;
            }
            catch (Exception e){

            }
            //If packet is from STA with IP 192.0.2.12
            if (isFromStation){
                double time_delta=getTimeDelta(staPh.getTimestamp(),previousCapturedFrameTime);
//                System.out.println(String.format(packetNumber
//                        + " \nTime from previous captured frame = %.9f",time_delta));
                writer.write(String.format("%.9f\n",time_delta));
            }
            previousCapturedFrameTime=staPh.getTimestamp();
        }
        writer.close();
        staPh.close();
        System.out.println("time delta from previous captured frame. (packets from Station to AP) (Station side)");
        System.out.println(packetNumber + " packets have been read from " + staPcapFile);
        System.out.println();

    }
    //packet time delta from previous captured frame (Station to Access Point) (AP side)
    private static void find_2 () throws PcapNativeException, NotOpenException, IOException {
        PcapHandle apPh = Pcaps.openOffline(apPcapFile, PcapHandle.TimestampPrecision.NANO);

        FileWriter writer = new FileWriter(resultFile2,false);
        int packetNumber = 0;
        int filteredPackets=0;
        Packet packet = null;

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

                    //When using following algorithm of parsing wlan frames in search of SA,
                    //It gives a little bit more packets than the Wireshark
                    //For instance, for ap.pcap it gathered 6308 packets instead of 6295,
                    //i.e. 9 extra packets.
                    //Don't know why this happens
                    short wlanAddrLen=6;
                    //Source address position in payload
                    short wlanSaPos=10;

                    //Usually only 3 addresses in WLAN frame used. BUT
                    //There is a case when source address is a 4th address in a WLAN frame
                    //Frame Control field == 0x0842
                    if (payload[0]==0x08 && payload[1]==0x42){
                        wlanSaPos=16;
                    }

                    byte[]byteWlanSa = new byte [wlanAddrLen];
                    System.arraycopy(payload,wlanSaPos,byteWlanSa,0,wlanAddrLen);
                    String wlanSa = byteArrayToHex(byteWlanSa);
//
                    if (wlanSa.equals(ConstantsIface.STA1_MAC)||wlanSa.equals(ConstantsIface.STA2_MAC)){
//                        System.out.println("THIS IS OUR FRAME");
                        filteredPackets++;
                        double time_delta=getTimeDelta(apPh.getTimestamp(),previousCapturedFrameTime);
//                        System.out.println(String.format(packetNumber
//                                + " \nTime from previous captured frame = %.9f",time_delta));
//
//                        System.out.println("wlan source address: " + wlanSa);
//                        System.out.println("payload: "+ byteArrayToHex(payload));
//                        System.out.println(String.format("%.9f",time_delta));
                        writer.write(String.format("%.9f\n",time_delta));
                    }
                    else
                    {
//                        System.out.println(packetNumber);
//                        System.out.println("wlan source address: " + wlanSa);
//                        System.out.println("payload: "+ byteArrayToHex(payload));
                    }

                }

            }
            catch (Exception e){}

            previousCapturedFrameTime=apPh.getTimestamp();

        }
        System.out.println(filteredPackets + " packets were captured from our stations " + apPcapFile);
        System.out.println(packetNumber + " packets have been read from " + apPcapFile);
        System.out.println();
        writer.close();
        apPh.close();
    }
    //Time of processing WLAN traffic
    //Find delta 1. From STA to AP
    private static boolean find_3_1(String staPcapFile, String apPcapFile) throws PcapNativeException, NotOpenException {

        PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);

        //MACs for searching
        String saMac ="803049236661";//80:30:49:23:66:61
        String daMac ="00c0ca98dfdf";//00:c0:ca:98:df:df
        int staPacketNum = 0;
        Packet staPacket = null;
        Timestamp previousCapturedFrameTime=null;
        //Timestamp previousDisplayedFrameTime=null;
        while ((staPacket = staPh.getNextPacket()) != null) {
            staPacketNum++;

            boolean isFromStation=false;
            boolean isTCP=false;
            short checksumTCP=0;

            try {
                IpV4Packet ipV4Packet = staPacket.get(IpV4Packet.class);
                if(ipV4Packet.getHeader().getSrcAddr().equals(InetAddress.getByName("192.0.2.12")))
                    isFromStation=true;
                if(ipV4Packet.getHeader().getProtocol().toString().equals("6 (TCP)")){
                    isTCP=true;
                }
//                System.out.println(ipV4Packet.getHeader().getProtocol().toString());
            }
            catch (Exception e){}

            //If staPacket is from STA with IP 192.0.2.12 and staPacket has TCP header
            if (isFromStation && isTCP){
                try {
                    TcpPacket tcpPacket = staPacket.get(TcpPacket.class);
                    if(tcpPacket!=null)
                    {
                        checksumTCP=tcpPacket.getHeader().getChecksum();
                        byte checksumTCPBytes[] = new byte[2];
                        // Big Endian
                        //https://stackoverflow.com/questions/2188660/convert-short-to-byte-in-java
                        checksumTCPBytes[0] = (byte) (checksumTCP >> 8);
                        checksumTCPBytes[1] = (byte) checksumTCP;

                        System.out.println("Found TCP packet from STA to AP in file " + staPcapFile+
                                "\nPacket number "+staPacketNum);
                        System.out.println("TCP checksum for verifying "+byteArrayToHex(checksumTCPBytes));
                        System.out.println("Now checking this TCP paket in "+apPcapFile);

                        PcapHandle apPh= find_3_TCP_in_AP(apPcapFile,checksumTCPBytes,saMac,daMac);
                        //If we found the same packet on AP side
                        if (apPh!=null){
//                            System.out.println("Packet was found in "+apPcapFile);

                            System.out.println("t1 = "+ apPh.getTimestamp().getTime());
                            System.out.println("t1 nanos = " + apPh.getTimestamp().getNanos());
                            System.out.println("t2  = " + staPh.getTimestamp().getTime());
                            System.out.println("t2 nanos = " + staPh.getTimestamp().getNanos());
                            System.out.println("delta1 = "+getTimeDelta(staPh.getTimestamp(),apPh.getTimestamp()));
                            //TODO export these values somewhere
                            System.out.println(staPacketNum + " packets have been read from " + staPcapFile);
                            System.out.println();
                            staPh.close();
                            return true;
                        }
                        else {
                            System.out.println("There was no such TCP packet in "+apPcapFile);
                        }

                    }
                }
                catch (Exception e){}
            }
        }
        staPh.close();
        System.out.println(staPacketNum + " packets have been read from " + staPcapFile);
        System.out.println();
        return false;
    }

    //find delta 2 ( FROM AP TO STA )
    private static boolean find_3_2(String staPcapFile, String apPcapFile) throws PcapNativeException, NotOpenException {

        PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);

        //MACs for searching
        String staMac ="803049236661";//80:30:49:23:66:61
        String apMac ="00c0ca98dfdf";//00:c0:ca:98:df:df
        int staPacketNum = 0;
        Packet staPacket = null;
        Timestamp previousCapturedFrameTime=null;
        //Timestamp previousDisplayedFrameTime=null;
        while ((staPacket = staPh.getNextPacket()) != null) {
            staPacketNum++;

            boolean isFromStation=false;
            boolean isTCP=false;
            short checksumTCP=0;

            try {
                IpV4Packet ipV4Packet = staPacket.get(IpV4Packet.class);
                if(ipV4Packet.getHeader().getDstAddr().equals(InetAddress.getByName("192.0.2.12")))
                    isFromStation=true;
                if(ipV4Packet.getHeader().getProtocol().toString().equals("6 (TCP)")){
                    isTCP=true;
                }
//                System.out.println(ipV4Packet.getHeader().getProtocol().toString());
            }
            catch (Exception e){}

            //If staPacket is to STA with IP 192.0.2.12 and staPacket has TCP header
            if (isFromStation && isTCP){
                try {
                    TcpPacket tcpPacket = staPacket.get(TcpPacket.class);
                    if(tcpPacket!=null)
                    {
                        checksumTCP=tcpPacket.getHeader().getChecksum();
                        byte checksumTCPBytes[] = new byte[2];
                        // Big Endian
                        //https://stackoverflow.com/questions/2188660/convert-short-to-byte-in-java
                        checksumTCPBytes[0] = (byte) (checksumTCP >> 8);
                        checksumTCPBytes[1] = (byte) checksumTCP;

                        System.out.println("Found TCP packet from AP to STA in file " + staPcapFile+
                                "\nPacket number "+staPacketNum);
                        System.out.println("TCP checksum for verifying "+byteArrayToHex(checksumTCPBytes));
                        System.out.println("Now checking this TCP paket in "+apPcapFile);

                        PcapHandle apPh= find_3_TCP_in_AP(apPcapFile,checksumTCPBytes,apMac,staMac);
                        //If we found the same packet on AP side
                        if (apPh!=null){
//                            System.out.println("Packet was found in "+apPcapFile);

                            System.out.println("t1 = "+ apPh.getTimestamp().getTime());
                            System.out.println("t1 nanos = " + apPh.getTimestamp().getNanos());
                            System.out.println("t2  = " + staPh.getTimestamp().getTime());
                            System.out.println("t2 nanos = " + staPh.getTimestamp().getNanos());
                            System.out.println("delta2 = "+getTimeDelta(staPh.getTimestamp(),apPh.getTimestamp()));
                            //TODO export these values somewhere
                            System.out.println(staPacketNum + " packets have been read from " + staPcapFile);
                            System.out.println();
                            staPh.close();
                            return true;
                        }
                        else {
                            System.out.println("There was no such TCP packet in "+apPcapFile);
                        }

                    }
                }
                catch (Exception e){}
            }
        }
        staPh.close();
        System.out.println(staPacketNum + " packets have been read from " + staPcapFile);
        System.out.println();
        return false;
    }
// find TCP packet in AP side
    //returns PcapHandle so we could find time
    private static PcapHandle find_3_TCP_in_AP(String apPcapFile, byte checksumTCPBytes[],String saMac,
                                               String daMac) throws PcapNativeException, NotOpenException {

        PcapHandle apPh = Pcaps.openOffline(apPcapFile);

        int apPacketNum = 0;
        Packet packet = null;

        while ((packet= apPh.getNextPacket())!=null) {
            apPacketNum++;
            RadiotapPacket radiotapPacket = packet.get(RadiotapPacket.class);
            try {
                if (radiotapPacket != null) {
                    byte[] payload = radiotapPacket.getPayload().getRawData();

                    Dot11FrameType type = Dot11FrameType.getInstance(
                            (byte) (((payload[0] << 2) & 0x30) | ((payload[0] >> 4) & 0x0F))
                    );
                    //Looking only for  IEEE802.11 data frames in a Type/Subtype field
                    switch (type.value()) {
                        case 0x0020:
                            //IEEE802.11 data frames
//                            System.out.println("Wlan data frame");

                            //When using following algorithm of parsing wlan frames in search of SA,
                            //It gives a little bit more packets than the Wireshark
                            //For instance, for ap.pcap it gathered 6308 packets instead of 6295,
                            //i.e. 9 extra packets.
                            //Don't know why this happens

                            short wlanAddrLen=6;
                            //Destination address position in payload
                            short wlanDaPos=4;
                            //Source address position in payload in case of 3 addresses used in WLAN frame
                            short wlanSaPos=10;

                            //There is a case when source address is a 4th address in a WLAN frame
                            if (payload[0]==0x08 && payload[1]==0x42){
                                wlanSaPos=16;
                            }

                            byte[]byteWlanSa = new byte [wlanAddrLen];
                            System.arraycopy(payload,wlanSaPos,byteWlanSa,0,wlanAddrLen);
                            String wlanSa = byteArrayToHex(byteWlanSa);

                            byte[]byteWlanDa = new byte [wlanAddrLen];
                            System.arraycopy(payload,wlanDaPos,byteWlanDa,0,wlanAddrLen);
                            String wlanDa = byteArrayToHex(byteWlanDa);

                            //If SA and DA in both AP and STA are equal and
                            //If checksums in both AP and STA packets are equal
                            //then we have found exactly the same packet
                            //in AP file. And we can take timestamp from this packet
                            if (wlanSa.equals(saMac) && wlanDa.equals(daMac) &&
                                    payload[76]==checksumTCPBytes[0] && payload[77]==checksumTCPBytes[1]){

                                System.out.println("TCP packet  was found in "+apPcapFile);
                                System.out.println("Packet number in the file is " + apPacketNum);

                                //TSFT. Not sure that we need this timestamp
//                                //Now we are looking for TSFT
//                                ArrayList<RadiotapPacket.RadiotapData> rtDataFields = radiotapPacket.getHeader().getDataFields();
//                                for (RadiotapPacket.RadiotapData field: rtDataFields){
//                                    if (!field.toString().equals(null) &&  field.getClass().equals(RadiotapDataTsft.class)){
//                                        System.out.println("t1 = " + ((RadiotapDataTsft) field).getMacTimestamp());
////                                System.out.println(" Field " +field.toString());
//                                    }
//                                }
                                apPh.close();
                                return apPh;
                            }
                            break;
                    }
                }
            }
            catch (Exception e) {}

        }
        System.out.println("All" + apPacketNum + " packets have been read from AP file" );
        apPh.close();
        return null;
    }
    //sample
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

    //sample. TODO Delete it. When I finish the program
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

    //Get Time delta between 2 frames
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

}
