#ifndef _SPW_ETH_STRUCTURE_H_
#define _SPW_ETH_STRUCTURE_H_

#ifdef __cplusplus
extern "C"{
#endif

#include <stdio.h>
#include <string.h>

#if defined(__WIN32) || defined  (__WIN32__) || defined(__WIN64) || defined  (__WIN64__)
#define WIN // Windows
#endif

#if defined (__gnu_linux__) || defined (__unix__) || defined (__linux) || defined (__linux__)
#define LINUX // Linux
#endif

//#define LINUX
//#define WIN

// Library version macros
#define BRIDGE_LIBRARY_VERSION "BRIDGE_LIBRARY v2.2"

// Hardware version macros
//#define XILINX_GE_SPW_01_2019

#if defined(LINUX)
#include <linux/types.h>
#include <linux/if_ether.h>
#elif defined(WIN)

typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int  __u32;

#define ETH_ALEN        6               /* Octets in one ethernet addr   */
#define ETH_HLEN        14              /* Total octets in header.       */
#define ETH_ZLEN        60              /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500            /* Max. octets in payload        */
#define ETH_FRAME_LEN   1514            /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN     4               /* Octets in the FCS             */


#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define bzero(a,b) memset(a,0,b)


#endif

#define END_OF_PACKET 0
#define ERROR_END_OF_PACKET 1


#define DS_STATE_ERROR_RESET    0x0
#define DS_STATE_ERROR_WAIT     0x1
#define DS_STATE_READY          0x2
#define DS_STATE_STARTED        0x3
#define DS_STATE_CONNECTING     0x4
#define DS_STATE_RUN            0x5

// DEBUG INFO of library
//#define HARD_DEBUG


#define SPW_ETH_DATA_LEN (ETH_DATA_LEN - (1 + 1 + 2 + 1))
// структура конфигурационного пакета
struct spw_eth_conf_header_2
{
    unsigned char GE_SPW[ETH_ALEN];
    __u8 edit0;
    __u8 edit1;
    unsigned char new_src_addr[ETH_ALEN];
    unsigned char new_dest_addr[ETH_ALEN];
    __u8 Spw_Speed;
    __u8 filtr;
    __u8 switch_mode;
    __u8 stat_freq;
#ifdef XILINX_GE_SPW_01_2019
    __u8 sniff_filtr;
    __u8 sniff_mask;
#endif
} __attribute__ ((packed));

#define SIZE_CONF_STRUCTURE sizeof(struct spw_eth_conf_header_2)

//EDIT 0
//Маска устанавливаемых параметров.
#define CONF_SET_MAC_SOURCE     (1 << 0)            //Бит 0 — установка MAC адреса устройства
#define CONF_SET_MAC_DEST       (1 << 1)           //Бит 1 — установка MAC адреса назначения
#define CONF_SET_SPEED          (1 << 2)            //Бит 2 — установка скорости SpW
#define CONF_SET_FILTR          (1 << 3)            //Бит 3 — установка режима фильтрации
#define CONF_SET_AUTO_MAC_SRC   (1 << 4)            //Бит 4 — автоматическая настройка MAC адреса устройства
#define CONF_SET_AUTO_MAC_DST   (1 << 5)            //Бит 5 — автоматическая настройка MAC  адреса назначения
#define CONF_RESET              (1 << 6)            //Бит 6 — сброс в конфигурацию по умолчанию
#define CONF_SET_CHECK_MAC      (1 << 7)           //Бит 7 — настройка с проверкой текущего MAC адреса устройства.

// EDIT 1
#define CONF_SET_SWITCH_MODE    (1 << 0)            //Бит 0 — установка режима коммутатора
#define CONF_SET_STATUS_FREQ    (1 << 1)            //Бит 1 — установка частоты посылки фреймов состояния моста

#ifdef XILINX_GE_SPW_01_2019
#define CONF_SET_ETH_SNIFFER    (1 << 3)          	//Бит 3 — установка фильтра на данные в eth
#endif

//switch mode
//Бит 3-0. Режимы передачи данных. По умолчанию режим 0
#define SWITCH_MODE_DATA_DIS                                0
/* коммутатор отключен. Передача по подключенному порту.
Если подключено 2 порта — передача только по первому. */
#define SWITCH_MODE_DATA_1_PORT                             1           /*передача и приём только в первый порт*/
#define SWITCH_MODE_DATA_2_PORT                             2           /*передача и приём только во второй порт*/
#define SWITCH_MODE_DATA_ENABLE                             3           /*коммутатор включен. Работают одновременно 2 порта.*/
#define SWITCH_MODE_DATA_AUTO_ENABLE                        4           /*автоматический режим. Если подключено 2 порта, то работает как режим 3.
    если 1 порт то режим 1 или 2 соответственно*/
#define SWITCH_MODE_DATA_PORT_TO_PORT                       5           /* передача данных из порта SpW в порт SpW, в Eth  данные не идут*/
#define SWITCH_MODE_DATA_PORT_TO_PORT_SNIFF_1               6           /* передача данных из порта SpW в порт SpW, в Eth идут данные из SpW1*/
#define SWITCH_MODE_DATA_PORT_TO_PORT_SNIFF_2               7           /* передача данных из порта SpW в порт SpW, в Eth идут данные из SpW2*/
#define SWITCH_MODE_DATA_PORT_TO_PORT_SNIFF_BOTH            8           /* передача данных из порта SpW в порт SpW, в Eth идут данные из SpW1 и SpW2*/


//Бит 7-4. Режимы передачи управляющих кодов. По умолчанию режим 3.
#define SWITCH_MODE_CCODE_DIS                                0           /* Передача запрещена*/
#define SWITCH_MODE_CCODE_1_PORT                             1           /* Передача и приём только в первый порт.*/
#define SWITCH_MODE_CCODE_2_PORT                             2           /* Передача и приём только во второй порт.*/
#define SWITCH_MODE_CCODE_DOUBLE                             3           /* Передача и приём по двум портам.*/
#define SWITCH_MODE_CCODE_PORT_TO_PORT                       5           /* передача из порта SpW в порт SpW, в Eth  данные не идут*/
#define SWITCH_MODE_CCODE_PORT_TO_PORT_SNIFF_1               6           /* передача из порта SpW в порт SpW, в Eth идут данные из SpW1*/
#define SWITCH_MODE_CCODE_PORT_TO_PORT_SNIFF_2               7           /* передача из порта SpW в порт SpW, в Eth идут данные из SpW2*/
#define SWITCH_MODE_CCODE_PORT_TO_PORT_SNIFF_BOTH            8           /* передача из порта SpW в порт SpW, в Eth идут данные из SpW1 и SpW2*/

#define SWITCH_MODE_DATA_SET(a)        (a & 0xf)
#define SWITCH_MODE_DATA_GET(val)      (val & 0xf)
#define SWITCH_MODE_DATA_mask         0xf

#define SWITCH_MODE_CCODE_SET(a)        ((a & 0xf) << 4)
#define SWITCH_MODE_CCODE_GET(val)      ((val & 0xf0) >> 4)
#define SWITCH_MODE_CCODE_mask         0xf0
//-----------------------------------
// структура статуса порта SpW
struct spw_eth_port_state {
    unsigned long long tx_byte_count;
    unsigned long long rx_byte_count;
    unsigned tx_packet_count;
    unsigned rx_packet_count;
    unsigned rx_packet_count_EEP;
    unsigned tx_byte_count_sec;
    unsigned rx_byte_count_sec;
    __u8 state;
} __attribute__((packed));

// полная структура статуса
struct spw_eth_state_new {
    unsigned time;
    struct spw_eth_port_state spw1;
    struct spw_eth_port_state spw2;
    __u8 speed;
    unsigned short loopback_err_count1;
    unsigned short delay1;
    unsigned short loopback_err_count2;
    unsigned short delay2;
    __u8 switch_mode;
} __attribute__((packed));

#define SpW_Eth_ERROR_0 		0x00	/*
    Информация о состоянии буферов кредитования
    */
#define SpW_Eth_ERROR_1 		0x01	/*
    Пришедший SOF, FEEF, FEOF пакет данных имеет номер на 2 и более больше, чем предыдущий.
    Предыдущий пакет данных был SOF или MOF.ащий часть пакета SpW
    */
#define SpW_Eth_ERROR_2	    0x02	/*
    Пришедший SOF, FEEF, FEOF пакет данных имеет номер на 2 и более больше, чем предыдущий.
    Предыдущий пакет данных был EOF, EEF, FEOF или FEEF.
    */

#define SpW_Eth_ERROR_3	    0x03	/*
    Пришедший MOF, EOF или EEF пакет данных имеет номер на 2 и более больше, чем предыдущий.
    Предыдущий пакет данных был MOF или SOF.
    */
#define SpW_Eth_ERROR_4		0x04	/*
    Пришедший MOF, EOF или EEF пакет данных имеет номер на 2 и более больше, чем предыдущий.
    Предыдущий пакет данных был EOF, EEF, FEOF или FEEF.
    */
#define SpW_Eth_ERROR_5		0x05	/*
    Пришедший пакет управляющего кода на 2 и более больше чем предыдущий пакет управляющих кодов
    */
#define SpW_Eth_ERROR_6		0x06	/*      */
#define SpW_Eth_ERROR_7		0x07	/*      */

#define SpW_Eth_ERROR_Num_Frame 0x1
#define SpW_Eth_ERROR_Num_ERROR 0x0


// Типы пакетов
#define SpW_Eth_MOF 		0x00	// Передается промежуточный пакет, содержащий часть пакета SpW //MOF
#define SpW_Eth_Full_EOF	0x01	// Передается пакет SpW целиком, который заканчивается нормальным символом конца пакета (EOP)
#define SpW_Eth_Full_EEF	0x02	// Передается пакет SpW целиком, который заканчивается нормальным символом конца пакета (EEP)
#define SpW_Eth_SOF			0x03	// Передается начало пакета SpW
#define SpW_Eth_EOF			0x04	// Передается заключительный пакет пакета SpW, который заканчивается нормальным символом пакета EOP
#define SpW_Eth_EEF			0x05	// Передается заключительный пакет пакета SpW, который заканчивается нормальным символом пакета EEP
#define SpW_Eth_CCode		0x06	// Передается пакет, содержащий 1 или несколько служебных кодов
#define SpW_Eth_EFrame		0x07	// Фрейм с кодами ошибок, содержит информацию об ошибках
#define SpW_Eth_Status      0x08	// Фрейм статуса (текущее состояние портов SpaceWire)
#define SpW_Eth_Bridge_Version	0x88  // Фрейм c информацией о текущей версии прошивки
#define SpW_Eth_Configure	0xFF	// Конфигурационный пакет



/* маски типов конца пакета для функций SpW_Recv_Frame_Type и SpW_Recv_Frame_Type_From_MAC */
#define Type_Mask_SpW_Eth_MOF               0x01	// Передается промежуточный пакет, содержащий часть пакета SpW //MOF
#define Type_Mask_SpW_Eth_Full_EOF          0x02	// Передается пакет SpW целиком, который заканчивается нормальным символом конца пакета (EOP)
#define Type_Mask_SpW_Eth_Full_EEF          0x04	// Передается пакет SpW целиком, который заканчивается нормальным символом конца пакета (EEP)
#define Type_Mask_SpW_Eth_SOF               0x08	// Передается начало пакета SpW
#define Type_Mask_SpW_Eth_EOF               0x010	// Передается заключительный пакет пакета SpW, который заканчивается нормальным символом пакета EOP
#define Type_Mask_SpW_Eth_EEF           	0x020	// Передается заключительный пакет пакета SpW, который заканчивается нормальным символом пакета EEP
#define Type_Mask_SpW_Eth_CCode             0x040	// Передается пакет, содержащий 1 или несколько служебных кодов
#define Type_Mask_SpW_Eth_EFrame    		0x080	// Фрейм с кодами ошибок, содержит информацию об ошибках
#define Type_Mask_SpW_Eth_Status            0x100	// Фрейм статуса (текущее состояние портов SpaceWire)
#define Type_Mask_SpW_Eth_Bridge_Version	0x20000000  // Фрейм c информацией о текущей версии прошивки
#define Type_Mask_SpW_Eth_Configure         0x80000000	// Конфигурационный пакет



// контрольное значение для конфигурационных пакетов
static const char CONF_STRING[]  = "GE_SPW";

// Macroses for ccodes
#define TIMECODE_TYPE	0
#define INTCODE_TYPE	1
#define ACKCODE_TYPE	2
#define CC11CODE_TYPE     3
#define CC01CODE_TYPE     4

// макросы для генерации управляющих кодов SpaceWire
// тайм коды (маркеры времени)
#define TIMECODE_VAL(val)   	(0x000 | ((val) & 0x3f))
//  5 битные управляющие коды
#define INTCODE_5_VAL(val)  	(0x080 | ((val) & 0x1f))
#define ACKCODE_5_VAL(val)  	(0x0A0 | ((val) & 0x1f))
#define CC11CODE_5_VAL(val) 	(0x0C0 | ((val) & 0x1f))
#define CC01CODE_5_VAL(val) 	(0x040 | ((val) & 0x1f))

//  6 битные управляющие коды
#define INTCODE_6_VAL(val)   	(0x040 | ((val) & 0x3f))
#define ACKCODE_6_VAL(val)  	(0x080 | ((val) & 0x3f))
#define CC11CODE_6_VAL(val) 	(0x0C0 | ((val) & 0x3f))

// тип пакета характеризующий пакеты моста
#define SpW_Ether_ID 0x06AB
#define SpW_Ether_ID_INV 0xAB06

#ifdef __cplusplus
}
#endif

#endif
