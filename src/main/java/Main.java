// This program uses library for reading PCAP files from
// https://github.com/kaitoy/pcap4j

import org.apache.commons.io.filefilter.FileFileFilter;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.Dot11FrameType;
import org.apache.commons.io.comparator.LastModifiedFileComparator;

import java.io.*;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

public class Main implements Constants {
  
  public static ArrayList<Session> sessions = new ArrayList<>();
  public static ArrayList<MultimediaSession> dsSessions = new ArrayList<>();
  public static String staPcapFile;
  public static String apPcapFile;
  public static ArrayList<File> apFiles = new ArrayList<>();
  public static ArrayList<File> staFiles = new ArrayList<>();
  public static Timestamp lastReadTimestamp = null;
  
  public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {
	
  
	
	init();
	readApFilesAndAnalise();
	
	//Functions searching for
	//delta t tx
//        find_1();
//        //delta t rx
//        find_2();
//        //delta t 1
//        find_3_1();
//        //delta t2
//        find_3_2();
//        // epsilon
//        find3_3();

//        find_sessions();
	
	
  }
  
  private static void readApFilesAndAnalise() throws PcapNativeException, IOException, NotOpenException {
	
	int fNum = 0;
	int sessionNum = 0;
	int dsNum = 0;
	int telegNum = 0;
	int sizeApFiles = apFiles.size();
	
	for (int i = 0; i < sizeApFiles; i++) {
	  System.out.println("\nReading file " + ++fNum + " out of " + sizeApFiles);
	  apPcapFile = AP_DUMP_PATH + "\\" + apFiles.get(i).getName();
	  find_sessions();
	  
	  int sessionSize = sessions.size();
	  Session session;
	  ArrayList<Session> finishedSessions = new ArrayList<>();
	  
	  System.out.println(sessionSize + " sessions are found ");
	  
	  //Look for finished sessions and write them to file
	  for (int j = 0; j < sessionSize; j++) {
		session = sessions.get(j);
		
		
		boolean isFinished = session.checkIsFinished();
		boolean isTooLong = session.checkIsTooLong(lastReadTimestamp);
//                boolean isDiscord = session.checkIsDiscord();
//                boolean isTelegram = session.checkIsTelegram();
		//If the session was finished or if the last added packet was added too long ago
		//If this is the last file
		if (isFinished || isTooLong || i == sizeApFiles - 1) {
		  sessionNum++;
		  analyseSession(session, resultFiles[7], resultFiles[8], resultFiles[9], resultFiles[10]);
		  //TODO delete it
		  
//                    if(isDiscord){
//                        dsNum++;
//                        analyseSession(session,resultFiles[11],resultFiles[12],resultFiles[13], resultFiles[14]);
//                    }
//                    if(isTelegram){
//                        telegNum++;
//                        analyseSession(session,resultFiles[15],resultFiles[16],resultFiles[17], resultFiles[18]);
//                    }
		  finishedSessions.add(session);
		  
		}
	  }
	  
	  //Delete finished sessions
	  System.out.println(finishedSessions.size() + " finished sessions have been closed");
	  for (Session finished : finishedSessions) {
		sessions.remove(finished);
	  }
	  
	  finishedSessions = new ArrayList<>();
	  
	  int dsSize = dsSessions.size();
	  System.out.println(dsSize + " discord sessions are found ");
	  for (int j = 0; j < dsSize; j++) {
		MultimediaSession dsSession = dsSessions.get(j);
		boolean isFinished = dsSession.checkIsFinished();
		boolean isTooLong = dsSession.checkIsTooLong(lastReadTimestamp);
		if (isFinished || isTooLong || i == sizeApFiles - 1) {
		  dsNum++;
		  analyseSession(dsSession, resultFiles[11], resultFiles[12], resultFiles[13], resultFiles[14]);
		  finishedSessions.add(dsSession);
		}
		
	  }
	  //Delete finished sessions
	  System.out.println(finishedSessions.size() + " finished discord sessions have been closed");
	  for (Session finished : finishedSessions) {
		dsSessions.remove(finished);
	  }
	  
	  
	}
	
	
	System.out.println(" Sessions total number: " + sessionNum);
	System.out.println(" discord sessions total number: " + dsNum);
//        System.out.println(" telegram sessions total number: " + telegNum);
	
  }
  
  //Initialisation of filenames
  public static void init() throws IOException {


//      If there is no directory for results then create it
	if (!Files.exists(Paths.get(RESULTS_PATH)))
	  Files.createDirectory(Paths.get(RESULTS_PATH));
	
	// File names for result files
	resultFnames[0] = "time delta from previous captured frame (only packets from STA to AP) (STA side)";
	resultFnames[1] = "time delta from previous captured frame (only packets from STA to AP) (AP side)";
	resultFnames[2] = "";
	resultFnames[3] = "";
	resultFnames[4] = "";
	resultFnames[5] = "";
	resultFnames[6] = "";
	
	resultFnames[7] = "tcp session duration";
	resultFnames[8] = "packet intervals in sessions";
	resultFnames[9] = "packet lengths in sessions";
	resultFnames[10] = "timed out sessions";
	
	resultFnames[11] = "discord " + resultFnames[7];
	resultFnames[12] = "discord " + resultFnames[8];
	resultFnames[13] = "discord " + resultFnames[9];
	resultFnames[14] = "discord " + resultFnames[10];
	
	resultFnames[15] = "telegram " + resultFnames[7];
	resultFnames[16] = "telegram " + resultFnames[8];
	resultFnames[17] = "telegram " + resultFnames[9];
	resultFnames[18] = "telegram " + resultFnames[10];
	
	for (short i = 0; i < NUMBER_OF_RESULT_FILES; i++) {
	  resultFiles[i] = RESULTS_PATH + "\\" + resultFnames[i] + ".txt";
	  //If some result files from previous Run are left, delete them
	  if (Files.exists(Paths.get(resultFiles[i]))) {
		Files.delete(Paths.get(resultFiles[i]));
	  }
	  
	}
	
	getFileList(AP_DUMP_PATH, apFiles, ".pcap");
	getFileList(STA_DUMP_PATH, staFiles, ".pcap");
	
	System.out.println(apFiles.size() + " pcap files have been found in " + AP_DUMP_PATH);
	System.out.println(staFiles.size() + " pcap files have been found in " + STA_DUMP_PATH);

//        String staFilename = "sta.pcap";

//        String apFileName = "ap.pcap" ;
	//String apFileName = "sta.pcap";
	//String apFileName = "packet6754.pcap";
	//String apFileName = "decrypted2.pcap" ;
	//String apFileName = "tcp_only.pcap";
	//String apFileName = "exported2.pcap" ;
	
  }
  
  public static void getFileList(String filepath, ArrayList<File> fileList, String fileFormat) {
	
	File directory = new File(filepath);
	// get just files, not directories
	File[] files = directory.listFiles((FileFilter) FileFileFilter.FILE);
	
	//sort by last modified (asc order)
	Arrays.sort(files, LastModifiedFileComparator.LASTMODIFIED_COMPARATOR);
//        System.out.println("\nLast Modified Ascending Order (LASTMODIFIED_COMPARATOR)");
	
	//Add pcap files to array list
	for (File f : files) {
	  if (f.getName().endsWith(fileFormat)) {
		fileList.add(f);
//                System.out.println(f+" file added to list");
	  }
	  
	}
  }
  
  //1 time delta from previous captured frame. (packets from Station to AP) (Station side)
  private static void find_1() throws PcapNativeException, NotOpenException, IOException {
	
	PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);
	
	FileWriter timesWriter = new FileWriter(resultFiles[0], false);
	FileWriter packetLengthWriter = new FileWriter(resultFiles[1], false);
	int packetNumber = 0;
	Packet packet = null;
	Timestamp previousCapturedFrameTime = null;
	//Timestamp previousDisplayedFrameTime=null;
	while ((packet = staPh.getNextPacket()) != null) {
	  packetNumber++;
	  boolean isFromStation = false;
	  try {
		IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
		if (ipV4Packet.getHeader().getSrcAddr().equals(InetAddress.getByName(STA1_IPv4)))
		  isFromStation = true;
	  } catch (Exception e) {
		System.out.println("Exception in find_1 " + e.getMessage());
	  }
	  //If packet is from STA with IP 192.0.2.12
	  if (isFromStation) {
		double time_delta = getTimeDelta(staPh.getTimestamp(), previousCapturedFrameTime);
//                System.out.println(String.format(packetNumber
//                        + " \nTime from previous captured frame = %.9f",time_delta));
		timesWriter.write(String.format("%.9f\n", time_delta).replaceAll(",", "."));
		// No need in writing this:
		packetLengthWriter.write(packet.length() + "\n");
	  }
	  previousCapturedFrameTime = staPh.getTimestamp();
	}
	timesWriter.close();
	packetLengthWriter.close();
	staPh.close();
	System.out.println("time delta from previous captured frame. (packets from Station to AP) (Station side)");
	System.out.println(packetNumber + " packets have been read from " + staPcapFile);
	System.out.println();
	
  }
  
  //packet time delta from previous captured frame (Station to Access Point) (AP side)
  private static void find_2() throws PcapNativeException, NotOpenException, IOException {
	PcapHandle apPh = Pcaps.openOffline(apPcapFile, PcapHandle.TimestampPrecision.NANO);
	
	FileWriter timesWriter = new FileWriter(resultFiles[2], false);
	FileWriter packetLengthWriter = new FileWriter(resultFiles[3], false);
	int packetNumber = 0;
	int filteredPackets = 0;
	Packet packet = null;
	
	Timestamp previousCapturedFrameTime = null;
	
	while ((packet = apPh.getNextPacket()) != null) {
	  //packets.add(packet);
	  packetNumber++;
	  
	  RadiotapPacket radiotapPacket = packet.get(RadiotapPacket.class);
	  try {
		if (radiotapPacket != null) {
//                    System.out.println("Получен radiotap");
//                    System.out.println(radiotapPacket.toString());
		  byte[] payload = radiotapPacket.getPayload().getRawData();
		  
		  //When using following algorithm of parsing wlan frames in search of SA,
		  //It gives a little bit more packets than the Wireshark
		  //For instance, for ap.pcap it gathered 6308 packets instead of 6295,
		  //i.e. 9 extra packets.
		  //Don't know why this happens
		  short wlanAddrLen = 6;
		  //Source address position in payload
		  short wlanSaPos = 10;
		  
		  //Usually only 3 addresses in WLAN frame used. BUT
		  //There is a case when source address is a 4th address in a WLAN frame
		  //Frame Control field == 0x0842
		  if (payload[0] == 0x08 && payload[1] == 0x42) {
			wlanSaPos = 16;
		  }
		  
		  byte[] byteWlanSa = new byte[wlanAddrLen];
		  System.arraycopy(payload, wlanSaPos, byteWlanSa, 0, wlanAddrLen);
		  String wlanSa = byteArrToHexStr(byteWlanSa);
//
		  if (wlanSa.equals(STA1_MAC) || wlanSa.equals(STA2_MAC)) {
//                        System.out.println("THIS IS OUR FRAME");
			filteredPackets++;
			double time_delta = getTimeDelta(apPh.getTimestamp(), previousCapturedFrameTime);
//                        System.out.println(String.format(packetNumber
//                                + " \nTime from previous captured frame = %.9f",time_delta));
//
//                        System.out.println("wlan source address: " + wlanSa);
//                        System.out.println("payload: "+ byteArrayToHex(payload));
//                        System.out.println(String.format("%.9f",time_delta));
			timesWriter.write(String.format("%.9f\n", time_delta).replaceAll(",", "."));
			//No need in writing this
			packetLengthWriter.write(packet.length() + "\n");
		  } else {
//                        System.out.println(packetNumber);
//                        System.out.println("wlan source address: " + wlanSa);
//                        System.out.println("payload: "+ byteArrayToHex(payload));
		  }
		  
		}
		
	  } catch (Exception e) {
		System.out.println("Exception in find_2 " + e.getMessage());
	  }
	  
	  previousCapturedFrameTime = apPh.getTimestamp();
	  
	}
	System.out.println(filteredPackets + " packets were captured from our stations " + apPcapFile);
	System.out.println(packetNumber + " packets have been read from " + apPcapFile);
	System.out.println();
	timesWriter.close();
	packetLengthWriter.close();
	apPh.close();
  }
  
  //Time of processing WLAN traffic
  //Find delta 1. From STA to AP
  private static boolean find_3_1() throws PcapNativeException, NotOpenException, IOException {
	
	PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);
	
	FileWriter tcpTimeDeltaWriter = new FileWriter(resultFiles[4], false);
	
	//MACs for searching
	String saMac = "803049236661";//80:30:49:23:66:61
	String daMac = "00c0ca98dfdf";//00:c0:ca:98:df:df
	int staPacketCounter = 0;
	Packet staPacket = null;
//        Timestamp previousCapturedFrameTime=null;
	//Timestamp previousDisplayedFrameTime=null;
	while ((staPacket = staPh.getNextPacket()) != null) {
	  staPacketCounter++;
	  
	  boolean isFromStation = false;
	  boolean isTCP = false;
	  short checksumTCP = 0;
	  
	  try {
		IpV4Packet ipV4Packet = staPacket.get(IpV4Packet.class);
		if (ipV4Packet.getHeader().getSrcAddr().equals(InetAddress.getByName("192.0.2.12")))
		  isFromStation = true;
		if (ipV4Packet.getHeader().getProtocol().toString().equals("6 (TCP)")) {
		  isTCP = true;
		}
//                System.out.println(ipV4Packet.getHeader().getProtocol().toString());
	  } catch (Exception e) {
	  }
	  
	  //If staPacket is from STA with IP 192.0.2.12 and staPacket has TCP header
	  if (isFromStation && isTCP) {
		try {
		  TcpPacket tcpPacket = staPacket.get(TcpPacket.class);
		  if (tcpPacket != null) {
			checksumTCP = tcpPacket.getHeader().getChecksum();
			byte[] checksumTCPBytes = new byte[2];
			// Big Endian
			//https://stackoverflow.com/questions/2188660/convert-short-to-byte-in-java
			checksumTCPBytes[0] = (byte) (checksumTCP >> 8);
			checksumTCPBytes[1] = (byte) checksumTCP;
			
			System.out.println("Found TCP packet from STA to AP in file " + staPcapFile +
					"\nPacket number " + staPacketCounter);
			System.out.println("TCP checksum for verifying " + byteArrToHexStr(checksumTCPBytes));
			System.out.println("Now checking this TCP paket in " + apPcapFile);
			
			PcapHandle apPh = find_3_TCP_in_AP(apPcapFile, checksumTCPBytes, saMac, daMac);
			//If we found the same packet on AP side
			if (apPh != null) {
//                            System.out.println("Packet was found in "+apPcapFile);
			  
			  System.out.println("t1 = " + apPh.getTimestamp().getTime());
			  System.out.println("t1 nanos = " + apPh.getTimestamp().getNanos());
			  System.out.println("t2  = " + staPh.getTimestamp().getTime());
			  System.out.println("t2 nanos = " + staPh.getTimestamp().getNanos());
			  double delta1 = getTimeDelta(staPh.getTimestamp(), apPh.getTimestamp());
			  System.out.println("delta1 = " + delta1);
			  
			  tcpTimeDeltaWriter.write(String.format("%.9f\n", delta1).replaceAll(",", "."));
			  
			  System.out.println(staPacketCounter + " packets have been read from " + staPcapFile);
			  System.out.println();
			  
			  tcpTimeDeltaWriter.close();
			  staPh.close();
			  return true;
			} else {
			  System.out.println("There was no such TCP packet in " + apPcapFile);
			}
			
		  }
		} catch (Exception e) {
		}
	  }
	}
	
	tcpTimeDeltaWriter.close();
	staPh.close();
	System.out.println(staPacketCounter
			+ " packets have been read from " + staPcapFile);
	System.out.println();
	return false;
  }
  
  //find delta 2 ( FROM AP TO STA )
  private static boolean find_3_2() throws PcapNativeException,
		  NotOpenException, IOException {
	
	PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);
	
	FileWriter tcpTimeDeltaWriter = new FileWriter(resultFiles[5], false);
	
	//MACs for searching
	String staMac = "803049236661";//80:30:49:23:66:61
	String apMac = "00c0ca98dfdf";//00:c0:ca:98:df:df
	int staPacketCounter = 0;
	Packet staPacket = null;
	Timestamp previousCapturedFrameTime = null;
	//Timestamp previousDisplayedFrameTime=null;
	while ((staPacket = staPh.getNextPacket()) != null) {
	  staPacketCounter++;
	  
	  boolean isFromStation = false;
	  boolean isTCP = false;
	  short checksumTCP = 0;
	  
	  try {
		IpV4Packet ipV4Packet = staPacket.get(IpV4Packet.class);
		if (ipV4Packet.getHeader().getDstAddr().equals(InetAddress.getByName("192.0.2.12")))
		  isFromStation = true;
		if (ipV4Packet.getHeader().getProtocol().toString().equals("6 (TCP)")) {
		  isTCP = true;
		}
//                System.out.println(ipV4Packet.getHeader().getProtocol().toString());
	  } catch (Exception e) {
	  }
	  
	  //If staPacket is to STA with IP 192.0.2.12 and staPacket has TCP header
	  if (isFromStation && isTCP) {
		try {
		  TcpPacket tcpPacket = staPacket.get(TcpPacket.class);
		  if (tcpPacket != null) {
			checksumTCP = tcpPacket.getHeader().getChecksum();
			byte[] checksumTCPBytes = new byte[2];
			// Big Endian
			//https://stackoverflow.com/questions/2188660/convert-short-to-byte-in-java
			checksumTCPBytes[0] = (byte) (checksumTCP >> 8);
			checksumTCPBytes[1] = (byte) checksumTCP;
			
			System.out.println("Found TCP packet from AP to STA in file " + staPcapFile +
					"\nPacket number " + staPacketCounter);
			System.out.println("TCP checksum for verifying " + byteArrToHexStr(checksumTCPBytes));
			System.out.println("Now checking this TCP paket in " + apPcapFile);
			
			PcapHandle apPh = find_3_TCP_in_AP(apPcapFile, checksumTCPBytes, apMac, staMac);
			//If we found the same packet on AP side
			if (apPh != null) {
//                            System.out.println("Packet was found in "+apPcapFile);
			  
			  System.out.println("t1 = " + apPh.getTimestamp().getTime());
			  System.out.println("t1 nanos = " + apPh.getTimestamp().getNanos());
			  System.out.println("t2  = " + staPh.getTimestamp().getTime());
			  System.out.println("t2 nanos = " + staPh.getTimestamp().getNanos());
			  double delta2 = getTimeDelta(staPh.getTimestamp(), apPh.getTimestamp());
			  System.out.println("delta2 = " + delta2);
			  
			  tcpTimeDeltaWriter.write(String.format("%.9f\n", delta2).replaceAll(",", "."));
			  System.out.println(staPacketCounter + " packets have been read from " + staPcapFile);
			  System.out.println();
			  
			  tcpTimeDeltaWriter.close();
			  staPh.close();
			  return true;
			} else {
			  System.out.println("There was no such TCP packet in " + apPcapFile);
			}
			
		  }
		} catch (Exception e) {
		}
	  }
	}
	
	tcpTimeDeltaWriter.close();
	staPh.close();
	System.out.println(staPacketCounter + " packets have been read from " + staPcapFile);
	System.out.println();
	return false;
  }
  
  //function that reads values from each of 2 files  and finds average between 2 values
  private static void find3_3() throws IOException {
	
	FileReader fileReader1 = new FileReader(resultFiles[4]);
	FileReader fileReader2 = new FileReader(resultFiles[5]);
	FileWriter writer = new FileWriter(resultFiles[6], false);
	
	
	//создаем BufferedReader с существующего FileReader для построчного считывания
	BufferedReader reader1 = new BufferedReader(fileReader1);
	BufferedReader reader2 = new BufferedReader(fileReader2);
	
	// считаем сначала первую строку
	String delta1 = reader1.readLine();
	String delta2 = reader2.readLine();
	
	while (delta1 != null && delta2 != null) {
	  double error = (Double.parseDouble(delta1) + Double.parseDouble(delta2)) / 2;
	  
	  System.out.println(" Counted error = " + error);
	  
	  writer.write(String.format("%.9f\n", error).replaceAll(",", "."));
	  
	  // считываем остальные строки в цикле
	  delta1 = reader1.readLine();
	  delta2 = reader2.readLine();
	}
	
	
	fileReader1.close();
	fileReader2.close();
	writer.close();
  }
  
  // find TCP packet in AP side
  //returns PcapHandle so we could find time
  private static PcapHandle find_3_TCP_in_AP(String apPcapFile, byte[] checksumTCPBytes, String saMac,
                                             String daMac) throws PcapNativeException, NotOpenException {
	
	PcapHandle apPh = Pcaps.openOffline(apPcapFile);
	
	int apPacketCounter = 0;
	Packet packet = null;
	
	while ((packet = apPh.getNextPacket()) != null) {
	  apPacketCounter++;
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
			  
			  short wlanAddrLen = 6;
			  //Destination address position in payload
			  short wlanDaPos = 4;
			  //Source address position in payload in case of 3 addresses used in WLAN frame
			  short wlanSaPos = 10;
			  
			  //There is a case when source address is a 4th address in a WLAN frame
			  if (payload[0] == 0x08 && payload[1] == 0x42) {
				wlanSaPos = 16;
			  }
			  
			  byte[] byteWlanSa = new byte[wlanAddrLen];
			  System.arraycopy(payload, wlanSaPos, byteWlanSa, 0, wlanAddrLen);
			  String wlanSa = byteArrToHexStr(byteWlanSa);
			  
			  byte[] byteWlanDa = new byte[wlanAddrLen];
			  System.arraycopy(payload, wlanDaPos, byteWlanDa, 0, wlanAddrLen);
			  String wlanDa = byteArrToHexStr(byteWlanDa);
			  
			  //If SA and DA in both AP and STA are equal and
			  //If checksums in both AP and STA packets are equal
			  //then we have found exactly the same packet
			  //in AP file. And we can take timestamp from this packet
			  if (wlanSa.equals(saMac) && wlanDa.equals(daMac) &&
					  payload[76] == checksumTCPBytes[0] && payload[77] == checksumTCPBytes[1]) {
				
				System.out.println("TCP packet  was found in " + apPcapFile);
				System.out.println("Packet number in the file is " + apPacketCounter);
				
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
	  } catch (Exception e) {
	  }
	  
	}
	System.out.println("All" + apPacketCounter + " packets have been read from AP file");
	apPh.close();
	return null;
  }
  
  //Find all sessions in apPcapFile
  private static void find_sessions() throws PcapNativeException, NotOpenException, IOException {
	
	PcapHandle apPh = Pcaps.openOffline(apPcapFile);
	
	int apPacketCounter = 0;
	//for testing purposes
	int tcpCounter = 0;
	int udpCounter = 0;
	Packet packet = null;
	
	while ((packet = apPh.getNextPacket()) != null) {
	  apPacketCounter++;
	  lastReadTimestamp = apPh.getTimestamp();
	  RadiotapPacket radiotapPacket = packet.get(RadiotapPacket.class);
	  try {
		if (radiotapPacket != null) {
		  byte[] payload = radiotapPacket.getPayload().getRawData();
		  int payloadLength = payload.length;
		  
		  Dot11FrameType type = Dot11FrameType.getInstance(
				  (byte) (((payload[0] << 2) & 0x30) | ((payload[0] >> 4) & 0x0F))
		  );
		  //Looking only for  IEEE802.11 data frames in a Type/Subtype field
		  //that belong to our network
		  if (type.value() == DOT11_DATA && (belongsToTestbed(payload))) {
			//Position of ip and port in Radiotap Payload
			int ipPos = 40;
			int portPos = ipPos + 20;
			IpV4Packet ipV4Packet = null;
			try {
			  ipV4Packet = IpV4Packet.newPacket(payload, ipPos, payloadLength - ipPos);
			} catch (Exception e) {
//                                    System.out.println(e.getMessage());
			}
			
			
			// if ip packet is not null
			if (ipV4Packet != null) {
			  String ip1 = "", ip2 = "", port1 = "", port2 = "";
			  boolean isTcp = false, isUdp = false;
			  
			  ip1 = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
			  ip2 = ipV4Packet.getHeader().getDstAddr().getHostAddress();
			  
			  int protocol = Integer.parseInt(ipV4Packet.getHeader().getProtocol().valueAsString());
			  
			  switch (protocol) {
				case UDP_INT:
				  udpCounter++;
				  UdpPacket udpPacket = UdpPacket.newPacket(payload, portPos, payloadLength - portPos);
				  port1 = String.valueOf(udpPacket.getHeader().getSrcPort().valueAsInt());
				  port2 = String.valueOf(udpPacket.getHeader().getDstPort().valueAsInt());
				  break;
				case TCP_INT:
				  tcpCounter++;
				  TcpPacket tcpPacket = TcpPacket.newPacket(payload, portPos, payloadLength - portPos);
				  port1 = String.valueOf(tcpPacket.getHeader().getSrcPort().valueAsInt());
				  port2 = String.valueOf(tcpPacket.getHeader().getDstPort().valueAsInt());
				  break;
				case ICMPv4_INT:
				  //ICMPv4 contains UDP, so we count it as UDP
				  udpCounter++;
				  //Position of UDP in ICMPv4 protocol
				  portPos = ipPos + 8 + 20;
				  udpPacket = UdpPacket.newPacket(payload, portPos, payloadLength - portPos);
				  port1 = String.valueOf(udpPacket.getHeader().getSrcPort().valueAsInt());
				  port2 = String.valueOf(udpPacket.getHeader().getDstPort().valueAsInt());
				  break;
				default:
				  break;
			  }
			  if (port1.equals(null) || port2.equals((null)) || port1.equals("") || port2.equals("")) {
//                                    System.out.println("trouble packet+ "+ apPacketCounter + "\n"+ipV4Packet.toString());
				break;
			  }
			  
			  //Add packet to session arraylist.
			  Session session = new Session(ip1, port1, ip2, port2);
			  addPacketToSessionList(session, ipV4Packet, apPh.getTimestamp());
			  if (session.checkIsDiscord()) {
				addPacketToDiscordSessionList(session, ipV4Packet, apPh.getTimestamp());
			  }
			}
		  }
		  
		}
	  } catch (Exception e) {
//                System.out.println(" Exception in find_sessions: " +e.getMessage());
	  }
	  
	}

//        System.out.println(tcpCounter + " tcp packets have been found in " + apPcapFile);
//        System.out.println(udpCounter + " udp packets have been found in " + apPcapFile);
	System.out.println("All " + apPacketCounter + " packets have been read from AP file " + apPcapFile);
	
	apPh.close();
	
  }
  
  private static void addPacketToDiscordSessionList(Session newSession, IpV4Packet ipV4Packet, Timestamp timestamp) {
	MultimediaSession newMultimediaSession = new MultimediaSession(newSession);
	int sessionsSize = dsSessions.size();
	//If sessions arraylist is empty
	if (sessionsSize == 0) {
	  newMultimediaSession.appendPacket(ipV4Packet, timestamp);
	  dsSessions.add(newMultimediaSession);
	}
	//Else check in sessions arraylist
	else {
	  for (int i = 0; i < sessionsSize; i++) {
		//if we have found already existing session
		MultimediaSession existingSession = dsSessions.get(i);
		
		//if new session is already exists
		if (existingSession.has(newMultimediaSession)) {
		  //add packet to the existing session and break the cycle FOR
		  existingSession.appendPacket(ipV4Packet, timestamp);
		  break;
		}
		//All sessions were checked and this packet doesn't belong to any of them
		if (i == sessionsSize - 1) {
		  newMultimediaSession.appendPacket(ipV4Packet, timestamp);
		  dsSessions.add(newMultimediaSession);
		}
		
	  }
	}
	
  }
  
  private static void addPacketToSessionList(Session newSession, IpV4Packet ipV4Packet, Timestamp timestamp) {
	
	int sessionsSize = sessions.size();
	//If sessions arraylist is empty
	if (sessionsSize == 0) {
	  newSession.appendPacket(ipV4Packet, timestamp);
	  sessions.add(newSession);
	}
	//Else check in sessions arraylist
	else {
	  for (int i = 0; i < sessionsSize; i++) {
		//if we have found already existing session
		Session existingSession = sessions.get(i);
		
		//if new session is already exists
		if (existingSession.has(newSession)) {
		  //add packet to the existing session and break the cycle FOR
		  existingSession.appendPacket(ipV4Packet, timestamp);
		  break;
		}
		//All sessions were checked and this packet doesn't belong to any of them
		if (i == sessionsSize - 1) {
		  newSession.appendPacket(ipV4Packet, timestamp);
		  sessions.add(newSession);
		}
		
	  }
	}
  }
  
  //Checks radiotap payload
  //Returns true if wlan addresses contain testbed MACs
  private static boolean belongsToTestbed(byte[] payload) {
	//Standard MAC length
	short wlanAddrLen = 6;
	//Destination address position in payload
	short wlanDaPos = 4;
	//Source address position in payload in case of 3 addresses used in WLAN frame
	short wlanSaPos = 10;
	
	//There is a case when source address is a 4th address in a WLAN frame
	if (payload[0] == 0x08 && payload[1] == 0x42) {
	  wlanSaPos = 16;
	}
	
	byte[] byteWlanSa = new byte[wlanAddrLen];
	System.arraycopy(payload, wlanSaPos, byteWlanSa, 0, wlanAddrLen);
	String wlanSa = byteArrToHexStr(byteWlanSa);
	
	byte[] byteWlanDa = new byte[wlanAddrLen];
	System.arraycopy(payload, wlanDaPos, byteWlanDa, 0, wlanAddrLen);
	String wlanDa = byteArrToHexStr(byteWlanDa);
	
	//If SA and DA in both AP and STA are equal and
	//If checksums in both AP and STA packets are equal
	//then we have found exactly the same packet
	//in AP file. And we can take timestamp from this packet
	
	// If traffic belongs to our STAs or to our AP
      return (wlanDa.equals(STA1_MAC) || wlanDa.equals(STA2_MAC))
              && wlanSa.equals(AP_MAC)
              ||
              wlanDa.equals(AP_MAC) &&
                      (wlanSa.equals(STA1_MAC) || wlanSa.equals(STA2_MAC));
  }
  
  
  //Write parameters of session to files
  private static void analyseSession(Session session, String FileForDuration,
									 String FileForInterval, String FileForLength, String FileForTimedOut) throws IOException {
	
	
	//Packet Lengths
	FileWriter pktLengthsWriter = new FileWriter(FileForLength, APPEND_TO_FILE);
	ArrayList<IpV4Packet> pkts = session.getIpV4Packets();
	for (IpV4Packet pkt : pkts) {
//                    System.out.println("Packet length = "+pkt.getHeader().getTotalLengthAsInt());
	  pktLengthsWriter.write(String.format("%d\n", pkt.getHeader().getTotalLengthAsInt()));
	}
	//Splitter between sessions
	pktLengthsWriter.write("\n");
	pktLengthsWriter.close();
	
	
	//Intervals
	FileWriter intervalWriter = new FileWriter(FileForInterval, APPEND_TO_FILE);
	Timestamp prevPacketTmstmp = null;
	ArrayList<Timestamp> tmstmps = session.getPacketTimestamps();
	for (Timestamp tmstmp : tmstmps) {
	  Double interval = getTimeDelta(tmstmp, prevPacketTmstmp);
	  prevPacketTmstmp = tmstmp;
//                    System.out.println("interval " + String.format("%.9f",interval).replaceAll(",", "."));
	  intervalWriter.write(String.format("%.9f\n", interval).replaceAll(",", "."));
	}
	//Splitter between sessions
	intervalWriter.write("\n");
	intervalWriter.close();
	
	
	//Session duration
	FileWriter durWriter = new FileWriter(FileForDuration, APPEND_TO_FILE);
	double dur = session.getSessionDuration();
	if (dur > 0) {
//                System.out.println(" Session duration in seconds: "+dur);
	  durWriter.write(String.format("%.9f\n", dur).replaceAll(",", "."));
	} else {
	  durWriter.write(String.format("%.9f\n", 0.0).replaceAll(",", "."));
	  //For testing
//                System.out.printf("File:%s\n session %s:%s %s:%s has bad duration %f\n",apPcapFile,session.getIp1(),
//                        session.getPort1(),session.getIp2(),session.getPort2(),dur);
//                System.out.printf("Session start time: %s\nSession end time: %s\n",
//                        session.getStartTime().toString(),session.getEndTime());
	}
	durWriter.close();
	
	
	//For testing
	//Timed out but not finished sessions
	if (session.checkIsTooLong(lastReadTimestamp) & !session.checkIsFinished()) {
//                        System.out.printf("Session %s:%s %s:%s were finished because of timeout\n",
//                                session.getIp1(),session.getPort1(),session.getIp2(),session.getPort2());
//                        System.out.println("Amount of packets in the session: "+session.getIpV4Packets().size());
	  FileWriter timedOutWriter = new FileWriter(FileForTimedOut, APPEND_TO_FILE);
	  timedOutWriter.write(String.format("Session %s:%s %s:%s was finished because of timeout\t",
			  session.getIp1(), session.getPort1(), session.getIp2(), session.getPort2()));
	  timedOutWriter.write(String.format("Amount of packets in the session: %d\t",
			  session.getIpV4Packets().size()));
	  timedOutWriter.write(String.format("Session was considered timed out after reading: %s\n",
			  apPcapFile));
	  timedOutWriter.close();
	}
	
  }
  
  //sample. TODO Delete it. When I finish the program
//    private static void readStaPcap(String staPcapFile) throws PcapNativeException, NotOpenException {
//        PcapHandle staPh = Pcaps.openOffline(staPcapFile, PcapHandle.TimestampPrecision.NANO);
//        // PcapManager staPcapManager = new PcapManager(staPcapFile,STATION);
//
//        //ArrayList<Packet> packets = new ArrayList<>();
//
//        int packetNumber = 0;
//        Packet packet = null;
//        while ((packet = staPh.getNextPacket()) != null) {
//            //packets.add(packet);
//            packetNumber++;
//            System.out.println("Packet "+packetNumber);
//            // System.out.println("Time:\n"+staPcapManager.getArrivalTime(staPh));
//            //System.out.println(packet.toString());
//
//        }
//        System.out.println(packetNumber + " packets have been read from " + staPcapFile);
//        staPh.close();
//    }
//
//    //sample. TODO Delete it. When I finish the program
//    private static void readApPcap (String apPcapFile) throws NotOpenException, PcapNativeException, EOFException,
//            TimeoutException {
//        PcapHandle apPh = Pcaps.openOffline(apPcapFile, PcapHandle.TimestampPrecision.NANO);
//
//
//        //ArrayList<Packet> packets = new ArrayList<>();
//
//        int packetNumber = 0;
//        int tcpPacketsNum=0;
//        Packet packet = null;
//        //apPh.setFilter("src host 192.0.2.12", BpfProgram.BpfCompileMode.NONOPTIMIZE);
//        while ((packet=apPh.getNextPacket()) != null) {
//            //packets.add(packet);
//            packetNumber++;
//
////            System.out.println("Packet "+packetNumber);
////            System.out.println("TSFT:\n"+apPcapManager.getTSFT(packet));
////            System.out.println(packet.toString());
//
//            RadiotapPacket radiotapPacket = packet.get(RadiotapPacket.class);
//            try {
//                if(radiotapPacket!=null){
////                    System.out.println("Получен radiotap");
////                    System.out.println(radiotapPacket.toString());
//                    byte[] payload = radiotapPacket.getPayload().getRawData();
//                    Dot11FrameType type = Dot11FrameType.getInstance(
//                            (byte) (((payload[0] << 2) & 0x30) | ((payload[0] >> 4) & 0x0F))
//                    );
//                    //Смотрим IEEE802.11 Type/Subtipe
//                    switch (type.value()) {
//                        case 0: // assoc-req
//                            System.out.println("assoc-req");
//                            break;
//                        case 0x0020:
//                            //IEEE802.11 data frames
//                            System.out.println("Wlan data frame");
//                            //Пропускаем поля IEEE802.11, которые для типа кадра Data занимают 32 байта
//                            //Пример как побайтово читать пакет
////                            int payload2Length=payload.length-32;
////                            byte[]payload2= new byte[payload.length-32];
////                            System.arraycopy(payload,32,payload2,0,payload2Length);
////                            System.out.println( byteArrayToHex( payload2));
//                            int wlanAddrLen = 6;
//
//                            byte[]wlanDA = new byte [wlanAddrLen];
//                            System.arraycopy(payload,16,wlanDA,0,wlanAddrLen);
//                            System.out.println("wlan destination address: " + byteArrToHexStr(wlanDA));
//
//                            byte[]wlanSA = new byte [wlanAddrLen];
//                            System.arraycopy(payload,10,wlanSA,0,wlanAddrLen);
//                            System.out.println("wlan source address: " + byteArrToHexStr(wlanSA));
//                            System.out.println("payload: "+ byteArrToHexStr(payload));
//                            //System.out.println("Payload [49]" +byteArrayToHex(Arrays.copyOfRange(payload,49,payload.length)));
//
//
//                            byte[]checksumTCP = new byte[]{0x0,0x0};
//                            //if  IPv4 and IPv4 protocol field == TCP
//                            if (payload[40]==0x45 && payload[49]==0x06){
//                                //System.out.println("Packet "+packetNumber);
//                                tcpPacketsNum++;
//                                System.arraycopy(payload,76,checksumTCP,0,2);
//                                System.out.println("TCP Checksum " + byteArrToHexStr(checksumTCP));
//                            }
//
//                            break;
//                        default:
////                            System.out.println("Not handling frame type  "+ type.value());
////                            System.out.println("Type: "+ type.value()+", Header: "+
////                                    radiotapPacket.getHeader().getRawData().length+
////                                    "bytes, Payload: length  "+payload.length);
//                    }
//                }
//            }catch (Exception e){
//
//            }
//
//        }
//        System.out.println(tcpPacketsNum + " tcp packets have been read from " + apPcapFile);
//        System.out.println(packetNumber + " packets have been read from " + apPcapFile);
//        apPh.close();
//
//    }
  
  //Convert byte array to string. See more:
  //https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
  public static String byteArrToHexStr(byte[] byteArr) {
	StringBuilder sb = new StringBuilder(byteArr.length * 2);
	for (byte b : byteArr)
	  sb.append(String.format("%02x", b));
	return sb.toString();
  }
  
  //Get Time difference (a.k.a. delta) between 2 frames
  public static Double getTimeDelta(Timestamp time1, Timestamp time2) {
	double time_delta = 0;
	
	//If both timestamps are not null
	if (time1 != null && time2 != null) {
	  
	  int deltaInMs = (int) Math.abs(time2.getTime() - time1.getTime());
	  //If delta in seconds is > 0 then we should count seconds together with nano seconds
	  if (deltaInMs / 1000 != 0) {
		time_delta = deltaInMs / 1000;
	  }
	  //If not, then we can simply count delta in nano seconds
	  int time2Nanos = time2.getNanos();
	  time_delta += (double) Math.abs(time1.getNanos() - time2Nanos) / 1000000000;
	  
	  
	}
	return time_delta;
	
  }
  
}
