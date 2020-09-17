#include "../src/headers/spw_eth_structure.h"
#include "../src/headers/spw_eth.h"
#include "../src/headers/spw_eth_print.h"
#include "time.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <math.h>
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

//#pragma comment(lib,"ws2_32.lib") //Winsock Library это тут не работает
//-------------------

#define PROGRAM_VERSION "v1.1.0"

#define BUF_SIZE 32000


/* Menu option codes */
#define MENU_DISPLAY_INFORMATION            '1'
#define MENU_TRANSMIT_SINGLE                '2'
#define MENU_TRANSMIT_MULTI                 '3'
#define MENU_RECEIVE_SINGLE                 '4'
#define MENU_RECEIVE_MULTI                  '5'
#define MENU_DISPLAY_STATE                  '6'
#define MENU_SET_SPEED                      '7'
#define MENU_TRANSMIT_CONFIGURE_PACKET      '8'
#define MENU_TRANSMIT_CONFIGURE_TESTER      '9'
#define MENU_RESET_DEVICE                  'a'
#define MENU_TRANSMITE_CCODE               'b'
#define MENU_TRANSMITE_CCODES              'c'
#define MENU_TRANSMITE_FROM_CHANNEL        'd'
#define MENU_RECEIVE_SINGLE_TYPE           'e'
#define MENU_SET_MAC_DA                     'f'
#define MENU_SET_CCODE_TYPE                 'g'
#define MENU_ON_OFF_FUNC_OBR                'h'
#define MENU_SET_MAC_SOURCE                 'i'
#define MENU_SHOW_SEND_RECEIVE_PACKETS      'k'


#define MENU_EXIT                       '0'

//===========================================
char *dev_name, buf_name[16];
#if defined(LINUX)
int rawsock;
#elif defined(WIN)
pcap_if_t *device;
pcap_t * rawsock;
#endif
int result, type,  length, regime_5_bit = 0, value;
int counter,  speed,  val, f_exit;
unsigned char buf[BUF_SIZE];
unsigned char *buf2;
unsigned int j, size_rand, for_scanf = 0,loop, i;
unsigned print_send = 1, print_rec = 1;
//===========================================

//------------------UDP--------------------
//------------------UDP--------------------

	int udp_socket, n_bytes;
	char buffer[1024];
	struct sockaddr_in local_addr, client_addr,dest_adr;
	struct sockaddr_storage server_storage;
	socklen_t addr_size, client_addr_size;
    SOCKET my_sock;

#define Bufer_size 64000
char strng[64];
char msg[Bufer_size];
char buff[64000];//буфер UDP смотри в main.c
unsigned int idx=0;



#define PORT 666    // порт сервера
int UDP_init()
{
   int i;
    printf("UDP Server\n");

   // шаг 1 - подключение библиотеки
    if (WSAStartup(0x202,(WSADATA *) &buff[0]))
    {
      printf("WSAStartup error: %d\n",
             WSAGetLastError());
      return -1;
    }

    // шаг 2 - создание сокета

    my_sock=socket(AF_INET,SOCK_DGRAM,0);
    if (my_sock==INVALID_SOCKET)
    {
      printf("Socket() error: %d\n",WSAGetLastError());
      WSACleanup();
      return -1;
    }

    // шаг 3 - связывание сокета с локальным адресом
    local_addr.sin_family=AF_INET;
    local_addr.sin_addr.s_addr=INADDR_ANY;
    local_addr.sin_port=htons(PORT);

    if (bind(my_sock,(struct sockaddr *) &local_addr,
        sizeof(local_addr)))
    {
      printf("bind error: %d\n",WSAGetLastError());
      closesocket(my_sock);
      WSACleanup();
      return -1;
    }

    return 0;
}

void UDP_work(int buf_size)
{
 int i;
    dest_adr.sin_family     =AF_INET;
    dest_adr.sin_addr.s_addr=inet_addr("127.0.0.1");//адресс куда пересылаем данные
    dest_adr.sin_port       =htons(8888);//порт куда пересылаем данные
   sendto(my_sock,&buff,buf_size,0,(struct sockaddr *)&dest_adr, sizeof(dest_adr));

   dest_adr.sin_family     =AF_INET;
   dest_adr.sin_addr.s_addr=inet_addr("127.0.0.1");//адресс куда пересылаем данные
   dest_adr.sin_port       =htons(8889);//порт куда пересылаем копию данных
  sendto(my_sock,&buff,buf_size,0,(struct sockaddr *)&dest_adr, sizeof(dest_adr));
}

void UDP_transmit (int k)
{
    int i=0;
    int l=0;

    for (i=0;i<k;i++)
    {        
        buff[i]=buf2[i];
 //     printf ("buff[i]:%x\n",buff[i]);
    }
    UDP_work(k);
}
//----------------------------------------

void data_out (int a)
{
    buf2[3+idx]=(a>>24)&0xff;
    buf2[2+idx]=(a>>16)&0xff;
    buf2[1+idx]=(a>> 8)&0xff;
    buf2[0+idx]=(a>> 0)&0xff;
    idx=idx+4;
}

void test_to_data ( int size)
{
     int i=0;
    size=size/4;
    unsigned int reg = 0;
    double A1=1000;
    double A2=2000;
    double A3=100;
    double F1=0;
    double F2=0;
    double F3=0;
    double freq1=0;
    double freq2=400;
    double freq3=700;
    double Fclk=6250;//KHz
    double pi=3.1415926535;

    idx=0;

  for(i=0;i<size;i++)//изменил начало индекса!!!!
    {
        F1=((int)(A1*(cos(i*2*pi*freq1/Fclk)))<<16)+A1*(sin(i*2*pi*freq1/Fclk));
        F2=((int)(A2*(cos(i*2*pi*freq2/Fclk)))<<16)+A2*(sin(i*2*pi*freq2/Fclk));
        F3=((int)(A3*(cos(i*2*pi*freq3/Fclk)))<<16)+A3*(sin(i*2*pi*freq3/Fclk));
        reg=F1+F2+F3;
        data_out(reg);
//      printf ("reg:%d\n",reg);
    }
}

//----------------------------------------

void ccode_recv(const void *buf, unsigned len, unsigned char *mac_recv)
{
    unsigned i;
    unsigned char val;
    for(i = 0; i < len; ++i) {
        val = ((const unsigned char *)buf)[i];
        printf(">> MAC of CCode sender: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx \n", mac_recv[0], mac_recv[1], mac_recv[2], mac_recv[3], mac_recv[4], mac_recv[5]);
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
        printf(">> MAC of EFrame sender: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac_recv[0], mac_recv[1], mac_recv[2], mac_recv[3], mac_recv[4], mac_recv[5]);
        printf(">> Error frame recieved: frame_num / creidt info = %d , err_code %d\n",  frame_num ,err_code);
        print_error_type(err_code);
    }
}

void get_current_type_ccode(){
    if (regime_5_bit == 0) printf("6-bit regime\n");
    else printf("5 bit regime\n");
}

void status_recv(const void *buf, unsigned len, unsigned char *mac_recv) {
    printf(">> MAC of Status sender: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx, Packet len = %u", mac_recv[0], mac_recv[1], mac_recv[2], mac_recv[3], mac_recv[4], mac_recv[5], len);
    print_spw_eth_state((struct spw_eth_state_new *)buf);
}

void enable_show_packets(){
    printf(" Show send packets : ");
    if (print_send == 0)  printf("OFF \n");
    else printf("ON \n");
    printf(" Show send packets\nPress [0] - Disable, [Any key] - Enable\n");
    scanf("%d", &print_send);

    printf("Show receive packets: ");
    if (print_rec == 0)  printf("OFF \n");
    else printf("ON \n");
    printf("Show receive packets\nPress [0] - Disable, [Any key] - Enable\n");
    scanf("%d", &print_rec);

}
//-------------------------------------------------------
void ON_OFF_handlers(){
    int key = 0;

    printf("CCode handler : ");
    if (get_handler_ccode_state()==NULL)  printf("OFF \n");
    else printf("ON \n");
    printf("CCode handler "
           "\nPress [0] - Disable, [Any key] - Enable\n");
    scanf("%d", &key);
    if (key == 0) disable_handler_ccode();
    else     register_ccode_event_handler(ccode_recv);

    printf("Status handler : ");
    if (get_handler_status_state()==NULL) printf("OFF \n");
    else printf("ON \n");
    printf("Status handler "
           "\nPress [0] - Disable, [Any key] - Enable\n");
    scanf("%d", &key);
    if (key == 0) disable_handler_status();
    else     register_status_event_handler(status_recv);

    printf("Error frame handler : ");
    if (get_handler_err_frame_state()==NULL)  printf("OFF \n");
    else printf(" ON \n");
    printf("Error frame handler "
           "\nPress [0] - Disable, [Any key] - Enable\n");
    scanf("%d", &key);
    if (key == 0) disable_handler_err_frame();
    else register_err_frame_event_handler(err_frame_recv);
}
//-------------------------------------------------------
void Dispalay_State() {
    int key = 0;
    unsigned char mac_tmp[ETH_ALEN];

    struct spw_eth_state_new state;
    printf("Dispalay_State \n");

    printf("Do You want to get state from certain device?"
           "\nPress [1] - Yes, [Any key] - No\n");
    scanf("%d", &key);
    if(key == 1) {
        printf("Enter MAC of device in format:"
               "\nExample: ff ff ff ff ff ff\n");

        while(ETH_ALEN != scanf("%hhx %hhx %hhx %hhx %hhx %hhx%*c",
                                &mac_tmp[0], &mac_tmp[1], &mac_tmp[2],
                                &mac_tmp[3], &mac_tmp[4], &mac_tmp[5])) {
            printf("Invalid MAC! Example: ff ff ff ff ff ff\n");
            fflush(stdin);
        }

#if defined(LINUX)
        SpW_Eth_Get_State_By_Dev_From_MAC(dev_name, &state, mac_tmp);
#elif defined(WIN)
        SpW_Eth_Get_State_By_Dev_From_MAC(&state, mac_tmp);
#endif
    } else {
        printf("Getting state of any device that transmit state\n");
#if defined(LINUX)
        SpW_Eth_Get_State_By_Dev(dev_name, &state, mac_tmp);
#elif defined(WIN)
        SpW_Eth_Get_State_By_Dev( &state, mac_tmp);
#endif
    }
    print_spw_eth_state(&state);
}

void set_speed(){
    printf("What speed set  ( avaliable 10,50,100,200,300,400,500)? ");
    scanf("%d", &speed);
    SpW_Eth_set_SpW_Speed(rawsock, speed);
}

void set_speed_m54(int speed)
{
    printf("speed set: %d",speed);
	printf("\r\n");
    SpW_Eth_set_SpW_Speed(rawsock, speed);
}

void handlerCtrlC(int signo)
{
    assert(signo == SIGINT);
    printf("client: <Ctrl + C> has been press\n");
    // Завершение
#if defined(LINUX)
    close(rawsock);
    free(buf2);
#elif defined(WIN)
    pcap_close(rawsock);
    free(buf2);
#endif
    exit(0);
}

void ResetDevice(){
    printf("ResetDevice \n");
    SpW_Eth_Reset(rawsock);

}
void    DisplayInformation(){
    printf("Demo for SpaceWire-Etherner bridge  %s \n",PROGRAM_VERSION);
}

void   Transmit_SinglePacket() {
    printf("Transmit_SinglePacket \n");
    printf ("Enter packet size: ");
    scanf("%i", &size_rand);
    printf("Enter path len: ");
    scanf("%d",&for_scanf);
    for (i = 0; i < (size_rand +for_scanf) ; i ++) {
        //        buf[i] = rand() % 256;
        buf[i+for_scanf] = i % 256;
    }
    for (i = 0; i < for_scanf; i++) {
        printf("(in HEX) path[%d]= ",i);
        scanf("%x",&val);
        buf[i] = val;
    }
    size_rand += for_scanf;
    printf("Type of end packet (1 - eep, other - eop): ");
    scanf("%d",&for_scanf);
    if (print_send > 0)
        debug_dump("Transmit packet: \n", buf, size_rand);
    if (for_scanf == 1)
        result = SpW_Send_Packet(rawsock, buf, size_rand, SpW_Eth_Full_EEF);
    else
        result = SpW_Send_Packet(rawsock, buf, size_rand, SpW_Eth_Full_EOF);


}

void   Transmit_MultiPacket(){
    printf("Transmit_MultiPacket \n");
    printf("Enter loop counter: ");
    scanf("%i", &loop);
    printf("Enter packet size: ");
    scanf("%i", &size_rand);
    printf("Enter  path len: ");
    scanf("%d",&for_scanf);
    for (i = 0; i < for_scanf; i++) {
        printf("(in HEX) path[%d]= ",i);
        scanf("%x",&val);
        buf[i] = val;
    }
    size_rand += for_scanf;
    for (j=0;j < loop; j++) {
        for (i = 0; i < size_rand  ; i ++) {
            //            buf[i+for_scanf] = rand() % 256;
            buf[i+for_scanf] = i % 256;
        }
        if (j!=0) buf[9] = (j%256);
        printf("Loop counter =  %d , Size packet = %d \n",j, size_rand );
        if (print_send > 0)
            debug_dump("Transmit packet : \n", buf, size_rand );
        result = SpW_Send_Packet(rawsock, buf, size_rand , SpW_Eth_Full_EOF);
    }

}

void   Transmit_Packet_From_Channel(){
    int temp;
    printf("Transmit_Packet_From_Channel \n");
    printf("Enter packet size: ");
    scanf("%i", &size_rand);
    printf("Enter  path len: ");
    scanf("%d",&for_scanf);
    for (i = 0; i < (size_rand ) ; i++) {
        buf[i+for_scanf] = i % 256;
    }
    for (i = 0; i < for_scanf; i++) {
        printf("(in HEX) path[%d]= ",i);
        scanf("%x",&val);
        buf[i] = val;
    }
    printf("Enter  channel num: ");
    scanf("%d",&temp);
    size_rand += for_scanf;
    if (print_send > 0)
        debug_dump("Transmit packet : \n", buf, size_rand);
    result = SpW_Send_Packet_From_Channel(rawsock, buf, size_rand, SpW_Eth_Full_EOF, temp);
}

void Receive_SinglePacket_m54() {
    int key = 0;
    unsigned char mac_tmp[ETH_ALEN];
    unsigned char end_packet;

 // printf("Receiving single packet from any device\n");
    length =  SpW_Recv_Packet(rawsock, buf2, BUF_SIZE, mac_tmp, &end_packet);
    print_rec=0;
    if (length > 0) 
	{
   //   test_to_data (length);
        UDP_transmit (length);
        if (print_rec > 0) 
		{
            printf("\nPacket end %d (0 - eop, 1 - eep)\nfrom MAC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", end_packet, mac_tmp[0], mac_tmp[1], mac_tmp[2], mac_tmp[3], mac_tmp[4], mac_tmp[5]);
            debug_dump("Packet: ", buf2, length);
        }
    }
}


void Receive_SinglePacket() {
    int key = 0;
    unsigned char mac_tmp[ETH_ALEN];
    unsigned char end_packet;
    printf("Do You want to get single packet from certain device?"
           "\nPress [1] - Yes, [Any key] - No\nEnter value: ");
    scanf("%d", &key);
    if(key == 1) {
        printf("Enter MAC of device in format:"
               "\nExample: ff ff ff ff ff ff\n");

        while(ETH_ALEN != scanf("%hhx %hhx %hhx %hhx %hhx %hhx%*c",
                                &mac_tmp[0], &mac_tmp[1], &mac_tmp[2],
                                &mac_tmp[3], &mac_tmp[4], &mac_tmp[5])) {
            printf("Invalid MAC! Example: ff ff ff ff ff ff\n");
            fflush(stdin);
        }
        printf("Receiving single packet\n");
        length = SpW_Recv_Packet_From_MAC(rawsock, buf2, BUF_SIZE, mac_tmp, &end_packet);
    } else {
        printf("Receiving single packet from any device\n");
        length =  SpW_Recv_Packet(rawsock, buf2, BUF_SIZE, mac_tmp, &end_packet);
    }
    if (length > 0) {
        if (print_rec > 0) {
            printf("\nPacket end %d (0 - eop, 1 - eep)\nfrom MAC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", end_packet, mac_tmp[0], mac_tmp[1], mac_tmp[2], mac_tmp[3], mac_tmp[4], mac_tmp[5]);
            debug_dump("Packet: ", buf2, length);
        }
    }
}

void Receive_SinglePacket_Type(unsigned mask_type){
    int key = 0;
    unsigned char mac_tmp[ETH_ALEN];
    unsigned type_rec;
    printf("Do You want to get single packet from certain device?"
           "\nPress [1] - Yes, [Any key] - No\nEnter value: ");
    scanf("%d", &key);
    if(key == 1) {
        printf("Enter MAC of device in format:"
               "\nExample: ff ff ff ff ff ff\n");

        while(ETH_ALEN != scanf("%hhx %hhx %hhx %hhx %hhx %hhx%*c",
                                &mac_tmp[0], &mac_tmp[1], &mac_tmp[2],
                                &mac_tmp[3], &mac_tmp[4], &mac_tmp[5])) {
            printf("Invalid MAC! Example: ff ff ff ff ff ff\n");
            fflush(stdin);
        }
        printf("Receiving single packet type\n");
        length = SpW_Recv_Frame_Type_From_MAC(rawsock, buf2, BUF_SIZE, mask_type, &type_rec, mac_tmp);
    } else {
        printf("Receiving single packet type from any device\n");
        length = SpW_Recv_Frame_Type(rawsock, buf2, BUF_SIZE, mask_type, &type_rec, mac_tmp);
    }
    if (length > 0) {
        if (print_rec > 0)
            printf("Receiving single packet  with type: %X \n", type_rec);
        debug_dump("Received packet: ", buf2, length);
    }
}


void Receive_MultiPacket() {
    int key = 0;
    unsigned char mac_tmp[ETH_ALEN];
    unsigned char end_packet;
    printf("Do You want to get single packet from certain device?"
           "\nPress [1] - Yes, [Any key] - No\nEnter value: ");
    scanf("%d", &key);
    if(key == 1) {
        printf("Enter MAC of device in format:"
               "\nExample: ff ff ff ff ff ff\n");

        while(ETH_ALEN != scanf("%hhx %hhx %hhx %hhx %hhx %hhx%*c",
                                &mac_tmp[0], &mac_tmp[1], &mac_tmp[2],
                                &mac_tmp[3], &mac_tmp[4], &mac_tmp[5])) {
            printf("Invalid MAC! Example: ff ff ff ff ff ff\n");
            fflush(stdin);
        }
        printf("Enter num packets to receive: ");
        scanf("%i", &loop);
        for (j = 0; j < loop; j++) {
            length = SpW_Recv_Packet_From_MAC(rawsock, buf2, BUF_SIZE, mac_tmp, &end_packet);
            if (length > 0) {
                printf (" PACKET #%d Packet end %d (0 - eop, 1 - eep) \n", j, end_packet);
                if (print_rec > 0)
                    debug_dump("Received packet: ", buf2, length);
            }
        }
    }
    else {
        printf("Enter num packets to receive: ");
        scanf("%i", &loop);
        for (j = 0; j < loop; j++) {
            length = SpW_Recv_Packet(rawsock, buf2, BUF_SIZE, mac_tmp, &end_packet);
            if (length > 0) {
                printf ("PACKET #%d Packet end %d (0 - eop, 1 - eep)\n", j);
                if (print_rec > 0)
                    printf("Received packet from MAC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac_tmp[0], mac_tmp[1], mac_tmp[2], mac_tmp[3], mac_tmp[4], mac_tmp[5]);
                debug_dump("Packet: ", buf2, length);
            }
        }
    }
}
void Set_CCode_Type(){
    int key;
    printf("CCode type: ");
    if (regime_5_bit == 0)  printf(" 6 bit regime \n");
    else printf(" 5 bit regime \n");
    printf("\nCCode type: \n 0 - 6 bit regime \n 1 - 5 bit regime \n[other] - disable \n");
    scanf("%d", &key);
    if (key == 0) {
        regime_5_bit = 0;
    }
    if (key == 1) {
        regime_5_bit = 1;
    }
}

void Transmite_CCode( ) {
    printf("Transmite_CCode \n");
    f_exit = 1;
    while(f_exit) {
        printf ("Enter type of CCode (%d - time , %d - int, %d - ack, %d - CC11, %d - CC01) or Exit - 5: ", TIMECODE_TYPE, INTCODE_TYPE, ACKCODE_TYPE, CC11CODE_TYPE, CC01CODE_TYPE);
        scanf("%i", &type);
        switch (type) {
        case 0:
            printf ("Enter Time code value:  ");
            scanf("%i", &value);
            SpW_Send_Time_Code(rawsock, value);
            f_exit = 0;
            break;
        case 1:
            printf ("Enter INT code value:  ");
            scanf("%i", &value);
            SpW_Send_INT_Code(rawsock, value, regime_5_bit);
            f_exit = 0;
            break;
        case 2:
            printf ("Enter ACK code value:  ");
            scanf("%i", &value);
            SpW_Send_ACK_Code(rawsock, value, regime_5_bit);
            f_exit = 0;
            break;
        case 3:
            printf ("Enter CC11 code value:  ");
            scanf("%i", &value);
            SpW_Send_CC11_Code(rawsock, value, regime_5_bit);
            f_exit = 0;
            break;
        case 4:
            printf ("Enter CCO1 code value:  ");
            scanf("%i", &value);
            SpW_Send_CC01_Code(rawsock, value, regime_5_bit);
            f_exit = 0;
            break;
        case 5:
            f_exit = 0;
            break;
        default:
            printf("ERROR TYPE \n");
            break;
        }
    }
}

void Transmite_CCodes( ) {
    printf("Transmite_CCode \n");
    f_exit = 1;
    unsigned char *ccode_buf;
    unsigned ccode_len;
    ccode_buf = malloc(200);
    while(f_exit) {
        printf ("Enter type of CCode (%d - time , %d - int, %d - ack, %d - CC11, %d - CC01) or Exit - 5: ", TIMECODE_TYPE, INTCODE_TYPE, ACKCODE_TYPE, CC11CODE_TYPE, CC01CODE_TYPE);
        scanf("%i", &type);
        switch (type) {
        case 0:
            printf ("Enter number of time codes: ");
            scanf("%i", &ccode_len);
            printf ("Enter values:  \n");
            for (i = 0 ; i < ccode_len; i++) {
                printf ("ccode[%d] = ", i);
                scanf("%i", &value);
                ccode_buf[i] = value;
            }
            SpW_Send_Time_Codes(rawsock, ccode_buf, ccode_len);
            f_exit = 0;
            break;
        case 1:
            printf ("Enter number of int codes: ");
            scanf("%i", &ccode_len);
            printf ("Enter values:  \n");
            for (i = 0 ; i < ccode_len; i++) {
                printf ("ccode[%d] = ", i);
                scanf("%i", &value);
                ccode_buf[i] = value;
            }
            SpW_Send_INT_Codes(rawsock, ccode_buf, ccode_len, regime_5_bit);
            f_exit = 0;
            break;
        case 2:
            printf ("Enter number of ack codes: ");
            scanf("%i", &ccode_len);
            printf ("Enter values:  \n");
            for (i = 0 ; i < ccode_len; i++) {
                printf ("ccode[%d] = ", i);
                scanf("%i", &value);
                ccode_buf[i] = value;
            }
            SpW_Send_ACK_Codes(rawsock, ccode_buf, ccode_len, regime_5_bit);
            f_exit = 0;
            break;
        case 3:
            printf ("Enter number of CC11 codes: ");
            scanf("%i", &ccode_len);
            printf ("Enter values:  \n");
            for (i = 0 ; i < ccode_len; i++) {
                printf ("ccode[%d] = ", i);
                scanf("%i", &value);
                ccode_buf[i] = value;
            }
            SpW_Send_CC11_Codes(rawsock, ccode_buf, ccode_len, regime_5_bit);
            f_exit = 0;
            break;
        case 4:
            printf ("Enter number of CC01 codes: ");
            scanf("%i", &ccode_len);
            printf ("Enter values:  \n");
            for (i = 0 ; i < ccode_len; i++) {
                printf ("ccode[%d] = ", i);
                scanf("%i", &value);
                ccode_buf[i] = value;
            }
            SpW_Send_CC01_Codes(rawsock, ccode_buf, ccode_len, regime_5_bit);
            f_exit = 0;
            break;
        case 5:
            f_exit = 0;
            break;
        default:
            printf("ERROR TYPE \n");
            break;
        }
    }
    free(ccode_buf);
}

int run_WORK(void)
{
	char bExit = 0;
    unsigned char cmd;
    int key;
    unsigned mask_type = 0;
    const char i=0;

    unsigned char mac_tmp[ETH_ALEN];
    unsigned char *mac_src, *mac_dst;

    mac_src = get_current_source_mac_adress();
    mac_dst = get_current_dest_mac_adress();
        printf("==============================================\n");
        printf("Current source      address of PC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
        printf("Current destination address of PC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
        printf("Dest MAC adress of PC must be the same with Source MAC adress of Bridge \n");
        printf("==============================================\n");

	
	printf("Receiving packets from any device\n");
	while (i==0)
	{
		Receive_SinglePacket_m54();
		scanf(&i);
	}	

    printf("Exiting...\n");

    SpW_Socket_Close(rawsock);
    free(buf2);
	return 0;
//  exit(0);
}

int runInteractive(void)
{
    char bExit = 0;
    unsigned char cmd;
    int key;
    unsigned mask_type = 0;

    unsigned char mac_tmp[ETH_ALEN];
    unsigned char *mac_src, *mac_dst;
    while (!bExit)
    {
        mac_src = get_current_source_mac_adress();
        mac_dst = get_current_dest_mac_adress();
        printf("==============================================\n");
        printf("Current source      address of PC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
        printf("Current destination address of PC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
        printf("Dest MAC adress of PC must be the same with Source MAC adress of Bridge \n");
        printf("==============================================\n");
        printf("\n Select Option: \n");
        printf("(%c)  Display  Version Information\n",   MENU_DISPLAY_INFORMATION);
        printf("(%c)  Transmit Single Packet \n", MENU_TRANSMIT_SINGLE);
        printf("(%c)  Transmit Multiple Packets \n",     MENU_TRANSMIT_MULTI);
        printf("(%c)  Transmite Single Packet from channel \n", MENU_TRANSMITE_FROM_CHANNEL);
        printf("(%c)  Receive Packet \n", MENU_RECEIVE_SINGLE);
        printf("(%c)  Receive Packet by Type \n", MENU_RECEIVE_SINGLE_TYPE);
        printf("(%c)  Receive Multiple Packets \n", MENU_RECEIVE_MULTI);
        printf("(%c)  Display Current State \n",        MENU_DISPLAY_STATE);
        printf("(%c)  Set SpaceWire Speed \n",        MENU_SET_SPEED);
        printf("(%c)  Reset Device\n", MENU_RESET_DEVICE);
        printf("(%c)  Transmite CCode \n", MENU_TRANSMITE_CCODE);
        printf("(%c)  Transmite CCodes \n", MENU_TRANSMITE_CCODES);
        printf("(%c)  Set Destination Address\n",   MENU_SET_MAC_DA);
        printf("(%c)  Set CCode type (5bit/6bit) Current: ",   MENU_SET_CCODE_TYPE); get_current_type_ccode();
        printf("(%c)  ON/OFF function handlers \n",   MENU_ON_OFF_FUNC_OBR);
        printf("(%c)  ON/OFF show send/receive packets \n",   MENU_SHOW_SEND_RECEIVE_PACKETS);
        //        printf("(%c)  Set Source MAC Address\n",   MENU_SET_MAC_SOURCE);
        printf("(%c)  Exit\n", MENU_EXIT);
        cmd = ' ';
        printf("Please Select Menu Option: ");
        do {
            scanf("%c", &cmd);
        }
        while (menu_select_valid(cmd) == 0);

        switch(cmd)
        {

        //        case MENU_SET_MAC_SOURCE:
        //            printf("Enter new source MAC address\n(Example: ff ff ff ff ff ff) \n ");
        //            scanf("%hhx %hhx %hhx %hhx %hhx %hhx", &mac_tmp[0], &mac_tmp[1], &mac_tmp[2], &mac_tmp[3], &mac_tmp[4], &mac_tmp[5]);
        //            set_source_mac_adress(mac_tmp, ETH_ALEN);
        //            break;

        case MENU_SET_MAC_DA:
            printf("Enter new destination MAC address\n(Example: ff ff ff ff ff ff) \n ");
            scanf("%hhx %hhx %hhx %hhx %hhx %hhx", &mac_tmp[0], &mac_tmp[1], &mac_tmp[2], &mac_tmp[3], &mac_tmp[4], &mac_tmp[5]);
            set_dest_mac_adress(mac_tmp, ETH_ALEN);
            break;

        case MENU_DISPLAY_INFORMATION:
            DisplayInformation();
            break;

        case MENU_TRANSMIT_SINGLE:
            Transmit_SinglePacket( );
            break;

        case MENU_TRANSMIT_MULTI:
            Transmit_MultiPacket( );
            break;

        case MENU_RECEIVE_SINGLE:
            Receive_SinglePacket();
            break;

        case MENU_RECEIVE_SINGLE_TYPE:
            mask_type = 0;
            printf("Enter type: \n");
            printf("(%d) SpW_Eth_MOF\n",        SpW_Eth_MOF);
            printf("(%d) SpW_Eth_Full_EOF\n",   SpW_Eth_Full_EOF);
            printf("(%d) SpW_Eth_Full_EEF\n",   SpW_Eth_Full_EEF);
            printf("(%d) SpW_Eth_SOF\n",        SpW_Eth_SOF);
            printf("(%d) SpW_Eth_EOF\n",        SpW_Eth_EOF);
            printf("(%d) SpW_Eth_EEF\n",        SpW_Eth_EEF);
            printf("(%d) SpW_Eth_CCode\n",      SpW_Eth_CCode);
            printf("(%d) SpW_Eth_EFrame\n",     SpW_Eth_EFrame);
            printf("(%d) SpW_Eth_Status\n",     SpW_Eth_Status);
            printf("(%d) SpW_Eth_Bridge_Version \n",     SpW_Eth_Bridge_Version);
            printf("(%d) SpW_Eth_Configure\n",  SpW_Eth_Configure);
            printf(" Exit : 256 and bigger \n",  SpW_Eth_Configure);
            key = -1;
            do {
                printf("Value: ");
                scanf("%d", &key);
                if ((key >= SpW_Eth_MOF) && (key <= SpW_Eth_Status)) {
                    mask_type |= 1 << key;
                }
                else {
                    if (key == SpW_Eth_Bridge_Version) {
                        mask_type |= Type_Mask_SpW_Eth_Bridge_Version;
                    }
                    else {
                        if (key == SpW_Eth_Configure) {
                            mask_type |= Type_Mask_SpW_Eth_Configure;
                        }
                        else {
                            if (key < 256)
                                printf("Error value %d: \n", key);
                        }
                    }

                }
            } while(key <= SpW_Eth_Configure);
            printf("Mask_types: %X\n", mask_type);
            Receive_SinglePacket_Type(mask_type);
            break;

        case MENU_RECEIVE_MULTI:
            Receive_MultiPacket();
            break;

        case MENU_DISPLAY_STATE:
            Dispalay_State();
            break;

        case MENU_SET_SPEED:
            set_speed();
            break;

        case MENU_TRANSMITE_CCODE:
            Transmite_CCode();
            break;

        case MENU_SET_CCODE_TYPE:
            Set_CCode_Type();
            break;

        case MENU_TRANSMITE_CCODES:
            Transmite_CCodes();
            break;

        case MENU_RESET_DEVICE:
            ResetDevice();
            break;

        case MENU_TRANSMITE_FROM_CHANNEL:
            Transmit_Packet_From_Channel();
            break;

        case MENU_ON_OFF_FUNC_OBR:
            ON_OFF_handlers();
            break;
        case MENU_SHOW_SEND_RECEIVE_PACKETS:
            enable_show_packets();
            break;


        case MENU_EXIT:
            printf("\nExiting SpaceWire test program \n ");
            bExit = 1;

            break;

        default:
            printf("\nERROR: Incorrect menu option  %d %c  \n", cmd,cmd);
            break;
        }
    }
    printf("Exiting...\n");
#if defined(LINUX)
    close(rawsock);
    free(buf2);
#elif defined(WIN)
    SpW_Socket_Close(rawsock);
    free(buf2 );
#endif
    exit(0);
}

void showHelp(void)
{
    printf("EMPTY HELP");
}

int main(int argc, char *argv[])
{
	int key=0;
    printf("M54 SW MOST : %s\n\n", PROGRAM_VERSION);
    rawsock = SpW_Socket_Init_Dialog();
	set_speed_m54(400);//скорость SW MBit/s 
	SpW_Eth_Set_Switch_Mode(rawsock,4,3);//задаём  режим работы портов ...
    register_ccode_event_handler(ccode_recv);
	UDP_init();
    buf2 = malloc(BUF_SIZE);
    run_WORK();
//	scanf("%d", &key);
    return 0;
}
