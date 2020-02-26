#include "../src/headers/spw_eth_structure.h"
#include "../src/headers/spw_eth.h"
#include "../src/headers/spw_eth_print.h"

#include "time.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DEMO_PROGRAM_VERSION "v1.1.0"
#define NUM_PACKETS 100000
#define BUF_SIZE 7500
unsigned char mac[ETH_ALEN]; //received mac (from status/packets sender)
int key = 0;
void ccode_recv(const void *buf, unsigned len, unsigned char *mac_recv)
{
    unsigned i;
    unsigned char val;
    for(i = 0; i < len; ++i) {
        val = ((const unsigned char *)buf)[i];
        printf(">> MAC of CCode sender: %hhx %hhx %hhx %hhx %hhx %hhx \n", mac_recv[0], mac_recv[1], mac_recv[2], mac_recv[3], mac_recv[4], mac_recv[5]);
        printf(">> CCode recieved: value %X (FULL), value (5bit) hex = %X dec = %d\n", val, (val & 0x1f), (val & 0x1f));
    }
}

void err_frame_recv(const void *buf, unsigned len, unsigned char *mac_recv)
{
    unsigned i;
    unsigned char frame_num, err_code;
    for(i = 0; i < len; i += 2) {
        err_code  = ((const unsigned char *)buf)[i];
        frame_num  = ((const unsigned char *)buf)[i + 1];
        printf(">> MAC of EFrame sender: %hhx %hhx %hhx %hhx %hhx %hhx\n", mac_recv[0], mac_recv[1], mac_recv[2], mac_recv[3], mac_recv[4], mac_recv[5]);
        printf(">> Error frame recieved: frame_num / creidt info = %d , err_code %d\n",  frame_num ,err_code);
        print_error_type(err_code);
    }
}

void status_recv(const void *buf, unsigned len, unsigned char *mac_recv) {
    printf(">> MAC of Status sender:%hhx %hhx %hhx %hhx %hhx %hhx, Packet len = %u", mac_recv[0], mac_recv[1], mac_recv[2], mac_recv[3], mac_recv[4], mac_recv[5], len);
    print_spw_eth_state((struct spw_eth_state_new *)buf);
}

int main(int argc, char **argv)
{
    int length;
    unsigned  cur_pos= 0;
    unsigned char *buf2;
    buf2 = malloc(sizeof(char) * BUF_SIZE);
    srand(time(NULL));
    unsigned char end_packet;
#if defined(LINUX)
    char *dev_name, buf_name[16];
    int res;
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
        printf(" Now we use %s \n", dev_name);
        dev_name[strlen(dev_name) - 1] = '\0';
        fclose(fp_all_devs);
    }
    rawsock = SpW_Socket_Init(dev_name);
#elif defined(WIN)
    const u_char *pkt_data;
    struct pcap_pkthdr *header;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* rawsock;
    rawsock = SpW_Socket_Init_Dialog();
#endif
    register_ccode_event_handler(ccode_recv);
    //   Если нужна обрабока пакетов статуса и пакетов с отчетами об ошибках
    //    необходимо раскоментировать следующие строчки
//    register_err_frame_event_handler(err_frame_recv);
//    register_status_event_handler(status_recv);

    printf("Do You want to get single packet from certain device?"
           "\nPress [1] - Yes, [Any key] - No\nEnter value: ");
    scanf("%d", &key);
    if(key == 1) {
        printf("Enter MAC of device in format:"
               "\nExample: ff ff ff ff ff ff\n");

        while(ETH_ALEN != scanf("%hhx %hhx %hhx %hhx %hhx %hhx%*c",
                                &mac[0], &mac[1], &mac[2],
                                &mac[3], &mac[4], &mac[5])) {
            printf("Invalid MAC! Example: ff ff ff ff ff ff\n");
            fflush(stdin);
        }
        printf("Receiving single packet\n");
    } else {
        printf("Receiving single packet from any device\n");
    }
    /* receive example */
    for (cur_pos = 0; cur_pos < NUM_PACKETS; ){
        bzero(buf2,sizeof(char) * BUF_SIZE);
        printf("Wait packet #%d: \n",cur_pos);
        if(key == 1)
            length =  SpW_Recv_Packet_From_MAC(rawsock, buf2, BUF_SIZE, mac, &end_packet);
        else     length =  SpW_Recv_Packet(rawsock, buf2, BUF_SIZE, mac, &end_packet);
        if (length > 0) {
            printf("\nRecieved packet #%d. Packet end %d (0 - eop, 1 - eep)\nfrom MAC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",cur_pos, end_packet,mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            debug_dump(" packet: ",buf2, length );
            cur_pos++;
        }
    }
    free(buf2);
    SpW_Socket_Close(rawsock);
    return 0;
}
