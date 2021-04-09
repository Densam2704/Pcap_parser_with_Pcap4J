public interface ConstantsIface {
    public static final int NUMBER_OF_RESULT_FILES = 10;
    public static final String STATION = "sta";
    public static final String ACCESS_POINT = "ap";

    public static final String STA_DUMP_PATH="C:\\Study\\Magister\\Diploma\\Data";
    public static final String AP_DUMP_PATH="C:\\Study\\Magister\\Diploma\\Data";
    public static final String RESULTS_PATH="C:\\Study\\Magister\\Diploma\\Data\\Result files";

    public static final String resultFnames [] = new String[NUMBER_OF_RESULT_FILES];
    public static final String resultFiles[] = new String[NUMBER_OF_RESULT_FILES];

    public static final boolean APPEND_TO_FILE = false;

    public static final String STA1_IPv4 = "192.0.2.12";
    //AP MAC
    //00:c0:ca:98:df:df
    public static final String AP_MAC = "00c0ca98dfdf";
    //Sta1
    //80:30:49:23:66:61
    public static final String STA1_MAC = "803049236661";
    //Sta2
    //04:92:26:34:4f:ff
    public static final String STA2_MAC = "049226344fff";

}
