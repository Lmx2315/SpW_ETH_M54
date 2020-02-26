#include <unistd.h>
#include <string.h>
#include "../src/headers/spw_eth_structure.h"
#include "../src/headers/spw_eth.h"
#include "../src/headers/spw_eth_print.h"
#define DEMO_PROGRAM_VERSION "v1.1.0"

#define DIALOG_SET_MAC_DST 5
#define DIALOG_SET_MAC_SOURCE 6
#define DIALOG_CREATE 1
#define DIALOG_LOAD 2
#define DIALOG_SEND 4
#define DIALOG_SAVE 3
#define DIALOG_EXIT 0
#define BUF_SIZE 1600

int show_menu(struct spw_eth_conf_header_2 str ) {
    unsigned result;
    unsigned char *mac_src = get_current_source_mac_adress();
    unsigned char *mac_dst = get_current_dest_mac_adress();
    printf("==============================================\n");
    printf("Current source MAC address PC           : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
    printf("Current destination MAC address PC      : %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
    printf("Dest MAC adress of PC must be the same with Source MAC adress of Bridge \n");
    printf("=========================================== \n");
    printf("=============        Menu     ============= \n");
    debug_dump("Conf packet:",&str, SIZE_CONF_STRUCTURE);
    printf(" %d Create new packet: \n", DIALOG_CREATE);
    printf(" %d Load packet: \n", DIALOG_LOAD);
    printf(" %d Save current packet: \n", DIALOG_SAVE);
    printf(" %d Send current packet: \n", DIALOG_SEND);
    printf(" %d Set destination address: \n", DIALOG_SET_MAC_DST);
//    printf(" %d Set source address: \n", DIALOG_SET_MAC_SOURCE);
    printf(" %d Exit: \n", DIALOG_EXIT);
    printf(" Enter value: ");
    scanf("%d",&result);
    return result;
}

int load_packet(struct spw_eth_conf_header_2* str) {
    char fname[30];
    unsigned size = 0;
    printf("Enter file name(Example xxxx.dat): ");
    scanf("%s",fname);
    FILE *file;
    file = fopen(fname,"rb");
    if(file == NULL)
    {
        printf(" ERROR %s",fname);
        return 0;
    }
    fread( &size, sizeof(int),1 , file );
    fread (str, sizeof(__u8), size , file );
    if (size != SIZE_CONF_STRUCTURE)      printf("ERROR in SIZE %u != %lu ",size, SIZE_CONF_STRUCTURE );
    debug_dump( "read packet : ",str,SIZE_CONF_STRUCTURE );
    fclose(file);
    return 0;
}

int save_packet(struct spw_eth_conf_header_2 str) {
    FILE *file;
    char fname[30];
    __u8 buffer[SIZE_CONF_STRUCTURE];
    int tmp;
    printf("Enter file name ( Example: config_1.dat): ");
    scanf("%s",fname);
    memcpy(buffer,&str, SIZE_CONF_STRUCTURE);
    file = fopen(fname, "wb");
    if(file == NULL)
    {
        printf("file not open '%s'",fname);
        return 0;
    }
    tmp = SIZE_CONF_STRUCTURE;
    fwrite (&tmp, sizeof(int),1 , file );
    fwrite (buffer, sizeof(__u8),SIZE_CONF_STRUCTURE , file );
    fclose(file);
    return 0;
}

#if defined( LINUX)
int send_packet(struct spw_eth_conf_header_2 str, unsigned rawsock) {
#elif defined (WIN)
int send_packet(struct spw_eth_conf_header_2 str, pcap_t * rawsock) {
#endif
    int result, i;
    debug_dump("Current struct : ", &str, SIZE_CONF_STRUCTURE);    
    result = SpW_Eth_Send_Conf_Packet(rawsock, str);
    //    result = SpW_Send_Packet(rawsock, &str, SIZE_CONF_STRUCTURE, SpW_Eth_Configure);
    unsigned char exchange[6];

    /* В случае если пользователь настроил новый source mac adress моста,
     * то этот новый  source mac adress моста должен быть установлен как dest mac adress ПО
     * чтобы отправляемые пакеты доходили до моста
     * По умолчанию на мосту  (source MAC adress) и в ПО (dest mac adress) установлены в значение
     * 00:01:02:03:04:05
     * По умолчанию в мосту установлен dest mac adress устанволен в значение ff:ff:ff:ff:ff:ff,
     * что соответствует broadcast  рассылке, в случае если  через  конфигурационный фрем настройки моста
     * будет установлено новое значение dest mac adress моста отличное от mac adress ПК, то ПК и ПО
     * запущенное на ПК перестанет принимать фреймы от моста
    */
    if(str.edit0 & CONF_SET_MAC_SOURCE) {
        memcpy(&exchange[0],str.new_src_addr, ETH_ALEN);
        for (i = 0; i < ETH_ALEN; i++)
            str.new_src_addr[ETH_ALEN-1-i] = exchange[i];
        set_dest_mac_adress(str.new_src_addr, ETH_ALEN);
    }
    return result;
}

struct spw_eth_conf_header_2 create_packet()
{
    unsigned  speed,  i;
    int val;
    unsigned char mac[ETH_ALEN];
    struct spw_eth_conf_header_2 conf_packet_2;
    memset(&conf_packet_2, 0, SIZE_CONF_STRUCTURE);
    memcpy(&conf_packet_2.GE_SPW, &CONF_STRING, sizeof(CONF_STRING));
    char bExit = 0;
    unsigned char  menuSelect;
    while (!bExit)
    {
        debug_dump("Current struct : ", &conf_packet_2, SIZE_CONF_STRUCTURE);
        printf("\n Select Option: \n");
        printf(" (%d) Set source MAC adress \n",   1);
        printf(" (%d) Set dest MAC adress \n", 2);
        printf(" (%d) Set SpW speed \n",     3);
        printf(" (%d) Set filtr mode \n", 4);
        printf(" (%d) Auto source MAC adress \n", 5);
        printf(" (%d) Auto dest MAC adress \n",        6);
        printf(" (%d) Reset configure  \n",        7);
        printf(" (a) Configure switch data \n");
        printf(" (b) Configure switch CCode \n" );
        printf(" (c) Status frequence \n" );
#ifdef XILINX_GE_SPW_01_2019
        printf(" (d) Set eth filtr mode \n" );
#endif
        printf(" (%d) Exit (without send) \n", 0);
        printf("Please Select Menu Option: ");
        do {
            scanf("%c", &menuSelect);
        }
        while (menu_select_valid(menuSelect) == 0);

        switch(menuSelect)
        {
        case '0':
            printf("\n Exit create mode \n ");
            return conf_packet_2;
            break;

        case '1':
            printf(" Enter new source MAC adress\n(Example: ff ff ff ff ff ff)\n");
            printf(" If you what to set 01:12:23:34:45:56 \n");
            printf(" you must enter  56:45:34:23:12:01    \n");
            while(ETH_ALEN != scanf("%hhx %hhx %hhx %hhx %hhx %hhx%*c",
                                    &mac[0], &mac[1], &mac[2],
                                    &mac[3], &mac[4], &mac[5])) {
                printf("Invalid MAC! Example: ff ff ff ff ff ff\n");
                fflush(stdin);
            }
            for (i = 0; i < ETH_ALEN; i++) {
                conf_packet_2.new_src_addr[i] = mac[i];
            }
            conf_packet_2.edit0 |= CONF_SET_MAC_SOURCE;
            break;

        case '2':
            printf(" Enter new dest MAC adress\n(Example: ff ff ff ff ff ff) \n ");
            printf(" If you what to set 01:12:23:34:45:56 \n");
            printf(" you must enter  56:45:34:23:12:01    \n");
            while(ETH_ALEN != scanf("%hhx %hhx %hhx %hhx %hhx %hhx%*c",
                                    &mac[0], &mac[1], &mac[2],
                                    &mac[3], &mac[4], &mac[5])) {
                printf("Invalid MAC! Example: ff ff ff ff ff ff\n");
                fflush(stdin);
            }
            for (i = 0; i < ETH_ALEN; i++) {
                conf_packet_2.new_dest_addr[i] = mac[i];
            }
            conf_packet_2.edit0 |= CONF_SET_MAC_DEST;
            break;

        case '3':
            do {
                printf(" Choose speed value (10, 50, 100, 200,300,400,500):\n ");
                scanf("%d", &val);
                speed = val;
                if ((speed != 10) && (speed != 50) && (speed != 100) && (speed != 200) && (speed != 300) && (speed != 400) && (speed != 500))
                {
                    printf("Error: speed (%d) \n", speed);
                }
            }
            while ((speed != 10) && (speed != 50) && (speed != 100) && (speed != 200) && (speed != 300) && (speed != 400) && (speed != 500));
            conf_packet_2.edit0 |= CONF_SET_SPEED;
            switch(speed) {
            case 500: conf_packet_2.Spw_Speed = 32;
                break;
            case 400: conf_packet_2.Spw_Speed = 0;
                break;
            case 300: conf_packet_2.Spw_Speed = 1;
                break;
            case 200: conf_packet_2.Spw_Speed = 2;
                break;
            case 100: conf_packet_2.Spw_Speed = 4;
                break;
            case 50: conf_packet_2.Spw_Speed = 8;
                break;
            case 10: conf_packet_2.Spw_Speed = 16;
                break;
            default:
                conf_packet_2.Spw_Speed = 0;
                break;
            }
            break;

        case '4':
            printf(" Enter filtr mode value (0- NO, 1 -YES)  \n ");
            scanf("%d", &val);

            if ((val < 0)||(val > 1)) {
                printf("Error: FILTR \n");
            } else {
                conf_packet_2.edit0 |= CONF_SET_FILTR;
                conf_packet_2.filtr = val;
            }
            break;

        case '5':
            printf(" Set source MAC auto (0 - NO, 1 - YES)\n");
            scanf("%d", &val);

            if(val == 0) {
                conf_packet_2.edit0 &= CONF_SET_AUTO_MAC_SRC;
            } else if(val == 1) {
                conf_packet_2.edit0 |= CONF_SET_AUTO_MAC_SRC;
            } else {
                printf("Error: CONF_SET_AUTO_MAC_SRC \n");
            }
            break;

        case '6':
            printf(" Set dest MAC auto (0 - NO, 1 - YES)\n");
            scanf("%d", &val);

            if(val == 0) {
                conf_packet_2.edit0 &= CONF_SET_AUTO_MAC_DST;
            } else if(val == 1) {
                conf_packet_2.edit0 |= CONF_SET_AUTO_MAC_DST;
            } else {
                printf("Error: CONF_SET_AUTO_MAC_DST \n");
            }
            break;


        case '7':
            printf(" RESET  (0 - NO, 1 - YES) \n ");
            scanf("%d", &val);

            if(val == 0) {
                conf_packet_2.edit0 &= ~CONF_RESET;
            } else if(val == 1) {
                conf_packet_2.edit0 |= CONF_RESET;
            } else {
                printf("Error: CONF_RESET \n");
            }
            break;

        case 'a':
            printf(" Data send mode\n");
            scanf("%d", &val);
            if ((val < 0) || (val > 8)) {
                printf("Error: SWITCH_MODE_DATA_SET \n");
            } else {
                conf_packet_2.edit1 |= CONF_SET_SWITCH_MODE;
                conf_packet_2.switch_mode &= ~SWITCH_MODE_DATA_mask;
                conf_packet_2.switch_mode |= SWITCH_MODE_DATA_SET(val);
            }
            break;
        case 'b':
            printf(" CCode send mode   \n ");
            scanf("%d", &val);
            if ((val < 0) || (val > 8)) {
                printf("Error: SWITCH_MODE_CCODE_SET \n");
            } else {
                conf_packet_2.edit1 |= CONF_SET_SWITCH_MODE;
                conf_packet_2.switch_mode &= ~SWITCH_MODE_CCODE_mask;
                conf_packet_2.switch_mode |= SWITCH_MODE_CCODE_SET(val);
            }
            break;
        case 'c':
            printf(" Status frequence (seconds)  \n ");
            scanf("%d", &val);
            if ((val < 0) || (val > 256)) {
                printf("Error: STATS FREQ \n");
            } else {
                conf_packet_2.edit1 |= CONF_SET_STATUS_FREQ;
                conf_packet_2.stat_freq = val;
            }
            break;
#ifdef XILINX_GE_SPW_01_2019
        case 'd':
            printf("set sniffer byte in HEX (Example: 0x1A): \n ");
            scanf("%x", &val);
            if (val < 0) {
                printf("Error: set filtr byte  \n");
            } else {
                conf_packet_2.edit1 |= CONF_SET_ETH_SNIFFER;
                conf_packet_2.sniff_filtr = val;
            }
            printf("set sniffer mask in HEX (Example: 0xFF): \n ");
            scanf("%x", &val);
            if (val < 0) {
                printf("Error: set sniffer mask \n");
            } else {
                conf_packet_2.edit1 |= CONF_SET_ETH_SNIFFER;
                conf_packet_2.sniff_mask = val;
            }
            break;
#endif
        default:
            printf("\nERROR: Incorrect menu option  %d %c  \n", menuSelect, menuSelect);
            break;
        }
    }
    printf("Exiting...\n");
    return conf_packet_2;
}

int main(int argc, char **argv)
{
    unsigned char mac_tmp[ETH_ALEN];
    unsigned buf_size = 20;
    int res;
#if defined(LINUX)
    char *dev_name, buf_name[16];
    unsigned rawsock, i = 0;
    //------------------
    FILE *fp, *fp_all_devs;
    //------------------
    if(argc > 1) {
        dev_name = argv[1];
    } else { //if ethernet dev have other name
        /* Open the command for reading. */
        fp = popen("ip a | grep -E -v '^ ' | awk '{print $2;}'", "r");
        // использовать только строки которые не начинаются с пробелов или табуляций в ip a
        if(!fp) {
            printf("Failed to run command\n");
            exit(1);
        }
        fp_all_devs=fopen ("all_devs.txt","w+");
        /* Read the output a line at a time - output it. */
        printf("All devices: \n");
        while((dev_name = fgets(buf_name, sizeof(buf_name), fp)) != NULL) {
            dev_name[strlen(dev_name) - 2] = '\0';
            //            if(strcmp("eth0", dev_name) == 0) break;
            fprintf(fp_all_devs,"%s\n",dev_name);
            printf("%d:  %s \n",i, dev_name);
            i++;
        }
        /* close */
        pclose(fp);
        printf("Use device: ");
        scanf("%d", &res);
        fseek(fp_all_devs,0,SEEK_SET);
        for (i = 0; i <= res ;i++) {
            dev_name = fgets(buf_name, sizeof(buf_name), fp_all_devs);
        }
        dev_name[strlen(dev_name) - 1] = '\0';
        printf("Now we use %s \n", dev_name);
        fclose(fp_all_devs);
    }
    rawsock = SpW_Socket_Init(dev_name);
    //rawsock = SpW_Socket_Init("eth0");
#elif defined (WIN)
    pcap_t * rawsock;
    rawsock = SpW_Socket_Init_Dialog();
#endif

    struct spw_eth_conf_header_2 conf_packet_2;
    memset(&conf_packet_2, 0, SIZE_CONF_STRUCTURE);
    while(1){
        res = show_menu(conf_packet_2);
        switch (res) {
        case DIALOG_SET_MAC_DST:
            printf(" Enter new destination MAC address\n(Example: ff ff ff ff ff ff) \n ");
            scanf("%hhx %hhx %hhx %hhx %hhx %hhx", &mac_tmp[0], &mac_tmp[1], &mac_tmp[2], &mac_tmp[3], &mac_tmp[4], &mac_tmp[5]);
            set_dest_mac_adress(mac_tmp, ETH_ALEN);
            break;
//        case DIALOG_SET_MAC_SOURCE:
//            printf(" Enter new source MAC address\n(Example: ff ff ff ff ff ff) \n ");
//            scanf("%hhx %hhx %hhx %hhx %hhx %hhx", &mac_tmp[0], &mac_tmp[1], &mac_tmp[2], &mac_tmp[3], &mac_tmp[4], &mac_tmp[5]);
//            set_source_mac_adress(mac_tmp, ETH_ALEN);
//            break;
        case DIALOG_CREATE:
            conf_packet_2 = create_packet();
            break;
        case DIALOG_EXIT:
            return 0;
            break;
        case DIALOG_LOAD:
            buf_size = load_packet(&conf_packet_2);
            if (buf_size == 0) printf("ERROR \n");
            break;
        case DIALOG_SAVE:
            save_packet(conf_packet_2);
            break;
        case DIALOG_SEND:
            send_packet(conf_packet_2,rawsock);
            break;
        default:
            break;
        }
    }
    SpW_Socket_Close(rawsock);
    return 0;

}
