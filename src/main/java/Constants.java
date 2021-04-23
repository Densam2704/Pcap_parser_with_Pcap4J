public interface Constants {
  int NUMBER_OF_RESULT_FILES = 20;
  boolean APPEND_TO_FILE = true;
  String STATION = "sta";
  String ACCESS_POINT = "ap";
  
  int ICMPv4_INT = 1;
  String ICMPv4_STRING = "1 (ICMPv4)";
  int UDP_INT = 17;
  String UDP_STRING = "17 (UDP)";
  int TCP_INT = 6;
  String TCP_STRING = "6 (TCP)";
  
  int DOT11_DATA = 0x0020;
  
  String STA_DUMP_PATH = "C:\\Study\\Magister\\Diploma\\Data\\Captured traffic\\STA";
  String AP_DUMP_PATH = "C:\\Study\\Magister\\Diploma\\Data\\Captured traffic\\AP";
  String RESULTS_PATH = "C:\\Study\\Magister\\Diploma\\Data\\Captured traffic\\Result files";
  
  String[] resultFnames = new String[NUMBER_OF_RESULT_FILES];
  String[] resultFiles = new String[NUMBER_OF_RESULT_FILES];
  
  //AP MAC
  //00:c0:ca:98:df:df
  String AP_MAC = "00c0ca98dfdf";
  //Sta1
  //80:30:49:23:66:61
  String STA1_MAC = "803049236661";
  //Sta2
  //04:92:26:34:4f:ff
  String STA2_MAC = "049226344fff";
  //Timeout value for sessions in seconds
  //1 minute
  double TIMEOUT_SHORT = 60;
  //5 minutes
  double TIMEOUT_MEDIUM = 300;
  //24 hours
  double TIMEOUT_LONG = 86400;
  
  //Telegram IPs 149.154.164.0 - 149.154.167.255 (149.154.164.0/22)
  String TELEGRAM_SUBNET = "149.154.164.0";
  int TELEGRAM_BITMASK = 22;
  //162.158.0.0
  int TELEGRAM_HEX_SUBNET = 0x959aa400;
  int TELEGRAM_MASK = -1 << (32 - TELEGRAM_BITMASK);
  
  //Discord IPs 162.158.0.0 - 162.159.255.255 (162.158.0.0/15)
  String DISCORD_SUBNET = "162.158.0.0";
  int DISCORD_BITMASK = 15;
  //162.158.0.0
  int DISCORD_HEX_SUBNET = 0xa29e0000;
  int DISCORD_MASK = -1 << (32 - DISCORD_BITMASK);
  
  // Testbed IPs 192.0.2.0/24
  String TESTBED_SUBNET = "192.0.2.0";
  int TESTBED_BITMASK = 24;
  int TESTBED_HEX_SUBNET = 0xc0000200;
  int TESTBED_MASK = 0xFFFFFF00;
  
  String STA1_IPv4 = "192.0.2.12";
  String STA2_IPv4 = "192.0.2.15";
  
  // Some raw byte data positions
  int IPv4_POSITION_IN_RADIOTAP_PAYLOAD = 40;
  int PORT_NUMBER_POSITION_IN_RADIOTAP_PAYLOAD = IPv4_POSITION_IN_RADIOTAP_PAYLOAD + 20;
  
}
