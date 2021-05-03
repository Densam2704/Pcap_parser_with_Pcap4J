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
  public static ArrayList<MultimediaSession> telegramSessions = new ArrayList<>();
  public static String staPcapFile;
  public static String apPcapFile;
  public static PcapHandle apPh;
  public static byte[] radiotapPayload;
  public static boolean isLastApFile = false;
  public static ArrayList<File> apFiles = new ArrayList<>();
  public static ArrayList<File> staFiles = new ArrayList<>();
  public static Timestamp lastReadTimestamp = null;
  
  public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {
  
	init();
	readApFilesAndAnalise();
	
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
	
	resultFnames[7] = "session duration";
	resultFnames[8] = "packet intervals in sessions";
	resultFnames[9] = "packet lengths in sessions";
	resultFnames[10] = "finished sessions";
	
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
	
	System.out.println(apFiles.size() + " pcap files were found in " + AP_DUMP_PATH);
	System.out.println(staFiles.size() + " pcap files were found in " + STA_DUMP_PATH);

//        String staFilename = "sta.pcap";

//        String apFileName = "ap.pcap" ;
	//String apFileName = "sta.pcap";
	//String apFileName = "packet6754.pcap";
	//String apFileName = "decrypted2.pcap" ;
	//String apFileName = "tcp_only.pcap";
	//String apFileName = "exported2.pcap" ;
	
  }
  
  private static void readApFilesAndAnalise() throws PcapNativeException, IOException, NotOpenException {
  
	int fNum = 0;
	int sessionsTotal = 0;
	int discordTotal = 0;
	int telegramTotal = 0;
	int sizeApFiles = apFiles.size();
	String[] analysisResultFiles = Arrays.copyOfRange(resultFiles, 7, 11);
	String[] dsAnalysisResultFiles = Arrays.copyOfRange(resultFiles, 11, 15);
	String[] telegramAnalysisResultFiles = Arrays.copyOfRange(resultFiles, 15, 19);
 
	for (int i = 0; i < sizeApFiles; i++){
//	for (int i = 11; i < 12; i++) {
	  System.out.println("\nReading file " + ++fNum + " out of " + sizeApFiles);
	  apPcapFile = AP_DUMP_PATH + "\\" + apFiles.get(i).getName();
	  readFileAndFindSessions();
	
	  
	  if (i == sizeApFiles - 1) {
		isLastApFile = true;
	  }
	  
	  int before=0,after=0;
	  
	  before=sessions.size();
	  System.out.println(before + " sessions are found ");
	  analiseSession(sessions, analysisResultFiles);
	  after=sessions.size();
	  System.out.println(after + " sessions are left opened \n");
	  sessionsTotal+=before-after;

	  before=dsSessions.size();
	  System.out.println(before+" discord sessions found");
	  analiseMultimediaSession(dsSessions, dsAnalysisResultFiles);
	  after=dsSessions.size();
	  System.out.println(after+" discord sessions left opened\n");
	  discordTotal+=before-after;
	  
	  before=telegramSessions.size();
	  System.out.println(before+" telegram sessions found");
	  analiseMultimediaSession(telegramSessions, telegramAnalysisResultFiles);
	  after=telegramSessions.size();
	  System.out.println(after+" telegram sessions left opened\n");
	  telegramTotal+=before-after;
	  
	  
	  System.out.println("Sessions total number: " + sessionsTotal);
	  System.out.println("discord sessions total number: " + discordTotal);
	  System.out.println("telegram sessions total number: " + telegramTotal);
	
	}
  }
  
  private static void analiseSession(ArrayList<Session>sessions,String[]resultFiles)
		  throws IOException {
  
	int sessionSize = sessions.size();
	Session session;
	ArrayList<Session> finishedSessions = new ArrayList<>();
	
	//Look for finished sessions and write them to file
	for (int j = 0; j < sessionSize; j++) {
	  session = sessions.get(j);
	
	  boolean isFinished = session.checkIsFinished();
	  boolean isTooLong = session.checkIsTimedOut(lastReadTimestamp);
	  //If the session was finished or if the last added packet was added too long ago
	  //If this is the last file
	  if (isFinished || isTooLong || isLastApFile) {
		writeSessionParamsToFiles(session,resultFiles);
		finishedSessions.add(session);
	  
	  }
	}
 
	//Delete finished sessions
	System.out.println(finishedSessions.size() + " finished sessions were closed");
	for (Session finished : finishedSessions) {
	  sessions.remove(finished);
	}
  }
  
  
  private static void analiseMultimediaSession(ArrayList<MultimediaSession> multimediaSessions, String[] resultFiles
											   ) throws IOException {
	ArrayList<MultimediaSession>finishedSessions = new ArrayList<>();
 
	int dsSize = multimediaSessions.size();
	for (int j = 0; j < dsSize; j++) {
	  MultimediaSession multimediaSession = multimediaSessions.get(j);
	  boolean isFinished = multimediaSession.checkIsFinished();
	  boolean isTooLong = multimediaSession.checkIsTimedOut(lastReadTimestamp);
	  if (isFinished || isTooLong || isLastApFile) {
		writeSessionParamsToFiles(multimediaSession,resultFiles);
		finishedSessions.add(multimediaSession);
	  }
	  
	}
	//Delete finished sessions
	System.out.println(finishedSessions.size() + " finished sessions were closed");
	for (Session finished : finishedSessions) {
	  multimediaSessions.remove(finished);
	}
	
  }
  
  
  public static void getFileList(String filepath, ArrayList<File> fileList, String fileFormat) {
	
	File directory = new File(filepath);
	File[] files = directory.listFiles((FileFilter) FileFileFilter.FILE);
	
	//sort by last modified (asc order)
	Arrays.sort(files, LastModifiedFileComparator.LASTMODIFIED_COMPARATOR);
	
	//Add pcap files to array list
	for (File f : files) {
	  if (f.getName().endsWith(fileFormat)) {
		fileList.add(f);
	  }
	}
	
  }
  
  
  //Find all sessions in apPcapFile
  private static void readFileAndFindSessions() throws PcapNativeException, NotOpenException, IOException {
	
    apPh = Pcaps.openOffline(apPcapFile);
	
	int apPacketCounter = 0;
	Packet packet = null;
	
	while ((packet = apPh.getNextPacket()) != null) {
	  apPacketCounter++;
	  lastReadTimestamp = apPh.getTimestamp();
	  RadiotapPacket radiotapPacket = packet.get(RadiotapPacket.class);
	  try {
	    parseRadiotapPacket(radiotapPacket);
	  }
	  catch (Exception e) {
//     System.out.println(" Exception in find_sessions: " +e.getMessage());
	  }
	  
	}
	System.out.println("All " + apPacketCounter + " packets were read from AP file " + apPcapFile);
	
	apPh.close();
	
  }
  
  //Parse Radiotap packet to find IP packet
  private static void parseRadiotapPacket(RadiotapPacket radiotapPacket) throws IllegalRawDataException {
  
	if (radiotapPacket != null) {
	  radiotapPayload= radiotapPacket.getPayload().getRawData();
	  int payloadLength = radiotapPayload.length;
	  Dot11FrameType type = Dot11FrameType
			  .getInstance((byte) (((radiotapPayload[0] << 2) & 0x30) | ((radiotapPayload[0] >> 4) & 0x0F))
	  );
	  //Looking only for  IEEE802.11 data frames in a Type/Subtype field
	  //that belong to Testbed network
	  if (type.value() == DOT11_DATA && (belongsToTestbed(radiotapPayload))) {
		
		int ipPos = IPv4_POSITION_IN_RADIOTAP_PAYLOAD;
		IpV4Packet ipV4Packet = null;
		
		try {
		  ipV4Packet = IpV4Packet.newPacket(radiotapPayload, ipPos, payloadLength - ipPos);
		  parseIPv4Packet(ipV4Packet);
		}
		catch (Exception e) {
//       System.out.println(e.getMessage());
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
  
  //Parse IPv4Packet to find sessions
  private static void parseIPv4Packet(IpV4Packet ipV4Packet) throws IllegalRawDataException {
	// if ip packet is not null
	if (ipV4Packet != null) {
	  int portPos = PORT_NUMBER_POSITION_IN_RADIOTAP_PAYLOAD;
	  int ipPos = IPv4_POSITION_IN_RADIOTAP_PAYLOAD;
	  String ip1 = "", ip2 = "", port1 = "", port2 = "";
	  int payloadLength=radiotapPayload.length;
	
	  ip1 = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
	  ip2 = ipV4Packet.getHeader().getDstAddr().getHostAddress();
	
	  int protocol = Integer.parseInt(ipV4Packet.getHeader().getProtocol().valueAsString());
	
	  switch (protocol) {
		case UDP_INT:
//			  udpCounter++;
		  UdpPacket udpPacket = UdpPacket.newPacket(radiotapPayload, portPos, payloadLength - portPos);
		  port1 = String.valueOf(udpPacket.getHeader().getSrcPort().valueAsInt());
		  port2 = String.valueOf(udpPacket.getHeader().getDstPort().valueAsInt());
		  break;
		case TCP_INT:
//			  tcpCounter++;
		  TcpPacket tcpPacket = TcpPacket.newPacket(radiotapPayload, portPos, payloadLength - portPos);
		  port1 = String.valueOf(tcpPacket.getHeader().getSrcPort().valueAsInt());
		  port2 = String.valueOf(tcpPacket.getHeader().getDstPort().valueAsInt());
		  break;
		case ICMPv4_INT:
		  //ICMPv4 contains UDP, so we count it as UDP
//			  udpCounter++;
		  //Position of UDP in ICMPv4 protocol
		  portPos = ipPos + 8 + 20;
		  udpPacket = UdpPacket.newPacket(radiotapPayload, portPos, payloadLength - portPos);
		  port1 = String.valueOf(udpPacket.getHeader().getSrcPort().valueAsInt());
		  port2 = String.valueOf(udpPacket.getHeader().getDstPort().valueAsInt());
		  break;
		default:
		  break;
	  }
	  
	  //Unless protocol is TCP/UDP/ICMP, go to the next packet.
	  if (port1.equals(null) || port2.equals((null)) || port1.equals("") || port2.equals("")) {
//				System.out.println("trouble packet+ "+ apPacketCounter + "\n"+ipV4Packet.toString());
		return;
	  }
	  
	  //Add packet to session arraylist.
	  Session session = new Session(ip1, port1, ip2, port2);
	  addPacketToSessionList(sessions,session, ipV4Packet, apPh.getTimestamp());
	
	  //Add packet to Multimedia lists
	  if (session.checkIsDiscord()) {
		addPacketToMultimediaSessionList(dsSessions,session, ipV4Packet, apPh.getTimestamp());
	  }
	  
	  if (session.checkIsTelegram()) {
		addPacketToMultimediaSessionList(telegramSessions,session, ipV4Packet, apPh.getTimestamp());
	  }
	}
	
  }
  
  private static void addPacketToSessionList(ArrayList<Session>sessions,
											 Session newSession, IpV4Packet ipV4Packet, Timestamp timestamp) {
	
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
		
		//if  existing session has new session parameters and existing session is not finished or timed out
		if (existingSession.has(newSession) &&
				!existingSession.checkIsFinished() && !existingSession.checkIsTimedOut(lastReadTimestamp)) {
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
  
  private static void addPacketToMultimediaSessionList(ArrayList<MultimediaSession>multimediaSessions,
													   Session newSession, IpV4Packet ipV4Packet, Timestamp timestamp) {
	MultimediaSession newMultimediaSession = new MultimediaSession(newSession);
	int sessionsSize = multimediaSessions.size();
	//If sessions arraylist is empty
	if (sessionsSize == 0) {
	  newMultimediaSession.appendPacket(ipV4Packet, timestamp);
	  multimediaSessions.add(newMultimediaSession);
	}
	//Else check in sessions arraylist
	else {
	  for (int i = 0; i < sessionsSize; i++) {
		//if we have found already existing session
		MultimediaSession existingSession = multimediaSessions.get(i);
		
		//if existing session is not finished and existing session has the same session parameters
		if (existingSession.has(newMultimediaSession) && !existingSession.checkIsFinished()) {
		  //add packet to the existing session and break the cycle FOR
		  existingSession.appendPacket(ipV4Packet, timestamp);
		  break;
		}
		//All sessions were checked and this packet doesn't belong to any of them
		if (i == sessionsSize - 1) {
		  newMultimediaSession.appendPacket(ipV4Packet, timestamp);
		  multimediaSessions.add(newMultimediaSession);
		}
		
	  }
	}
	
  }
  
  //Write parameters of session to files
  private static void writeSessionParamsToFiles(Session session, String[] fileNames) throws IOException {
	String FileForDuration = fileNames[0];
	String FileForInterval = fileNames[1];
	String FileForLength = fileNames[2];
	String FileForTimedOut = fileNames[3];
	
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
 
	//TODO for testing
//	System.out.println();
//	int index=0;
	for (Timestamp tmstmp : tmstmps) {
	  Double interval = Session.getTimeDifference(tmstmp, prevPacketTmstmp);
	  //TODO for testing
//	  System.out.print("Start time: " +session.getStartTime() + "\tEnd time: "+session.getEndTime()+"\t");
//	  System.out.print("Dur = " + session.getSessionDuration()+"\n");
//	  System.out.print(tmstmp+"\t"+prevPacketTmstmp+"\t");
//	  System.out.println("interval " + String.format("%.9f",interval).replaceAll(",", "."));
//	  System.out.println(session.getIpV4Packets().get(index++).toString());
	  
	  intervalWriter.write(String.format("%.9f\n", interval).replaceAll(",", "."));
	  prevPacketTmstmp = tmstmp;
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
	
	//If session is not finished and not timed out and not the last read AP file in list
	if (!session.checkIsTimedOut(lastReadTimestamp) && !session.checkIsFinished() && !isLastApFile) {
//                        System.out.printf("Session %s:%s %s:%s were finished because of timeout\n",
//                                session.getIp1(),session.getPort1(),session.getIp2(),session.getPort2());
//                        System.out.println("Amount of packets in the session: "+session.getIpV4Packets().size());
	  return;
	}
 
	String tcpOrUdp="Unknown\t";
	if(session.isUDP())
	  tcpOrUdp="UDP\t";
	if(session.isTCP())
	  tcpOrUdp="TCP\t";
  
	String finishedBecauseOf="normally";
	//If session was finished because of timeout
	if ( !session.checkIsFinished() && session.checkIsTimedOut(lastReadTimestamp)){
	  finishedBecauseOf="because of timeout";
	}
 
	FileWriter timedOutWriter = new FileWriter(FileForTimedOut, APPEND_TO_FILE);
	timedOutWriter.write(String.format("%sSession %s:%s %s:%s was finished %s\t",
			tcpOrUdp,session.getIp1(), session.getPort1(), session.getIp2(), session.getPort2(),finishedBecauseOf));
	timedOutWriter.write(String.format("Timeout value: %f\t",
			session.getTimeout()));
	timedOutWriter.write(String.format("Amount of packets in the session: %d\t",
			session.getIpV4Packets().size()));
	timedOutWriter.write(String.format("Session was considered timed out after reading: %s\n",
			apPcapFile));
	timedOutWriter.close();
	
  }
  
  //Convert byte array to string. See more:
  //https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
  public static String byteArrToHexStr(byte[] byteArr) {
	StringBuilder sb = new StringBuilder(byteArr.length * 2);
	for (byte b : byteArr)
	  sb.append(String.format("%02x", b));
	return sb.toString();
  }
  
  
}
