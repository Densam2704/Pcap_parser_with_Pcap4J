public interface Constants {
    public static final int NUMBER_OF_RESULT_FILES = 20;
    public static final boolean APPEND_TO_FILE = true;
    public static final String STATION = "sta";
    public static final String ACCESS_POINT = "ap";

    public static final String STA_DUMP_PATH="C:\\Study\\Magister\\Diploma\\Data\\Captured traffic\\STA";
    public static final String AP_DUMP_PATH="C:\\Study\\Magister\\Diploma\\Data\\Captured traffic\\AP";
    public static final String RESULTS_PATH="C:\\Study\\Magister\\Diploma\\Data\\Captured traffic\\Result files";

    public static final String resultFnames[] = new String[NUMBER_OF_RESULT_FILES];
    public static final String resultFiles[] = new String[NUMBER_OF_RESULT_FILES];

    //AP MAC
    //00:c0:ca:98:df:df
    public static final String AP_MAC = "00c0ca98dfdf";
    //Sta1
    //80:30:49:23:66:61
    public static final String STA1_MAC = "803049236661";
    //Sta2
    //04:92:26:34:4f:ff
    public static final String STA2_MAC = "049226344fff";
    //Timeout value for sessions in seconds
    //1 minute
    public static final double TIMEOUT_SHORT=60;
    //24 hours
    public static final double TIMEOUT_LONG=86400;

//Telegram IPs 149.154.164.0 - 149.154.167.255 (149.154.164.0/22)
    public static final String TELEGRAM_SUBNET="149.154.164.0";
    public static final int TELEGRAM_BITMASK=22;
    //162.158.0.0
    public static final int TELEGRAM_HEX_SUBNET=0x959aa400;
    public static final int TELEGRAM_MASK=-1<<(32-TELEGRAM_BITMASK);

//Discord IPs 162.158.0.0 - 162.159.255.255 (162.158.0.0/15)
    public static final String DISCORD_SUBNET="162.158.0.0";
    public static final int DISCORD_BITMASK=15;
    //162.158.0.0
    public static final int DISCORD_HEX_SUBNET=0xa29e0000;
    public static final int DISCORD_MASK=-1<<(32-DISCORD_BITMASK);

// Testbed IPs 192.0.2.0/24
    public static final String TESTBED_SUBNET = "192.0.2.0";
    public static final int TESTBED_BITMASK=24;
    public static final int TESTBED_HEX_SUBNET=0xc0000200;
    public static final int TESTBED_MASK=0xFFFFFF00;

    public static final String STA1_IPv4 = "192.0.2.12";
    public static final String STA2_IPv4 = "192.0.2.15";

}
