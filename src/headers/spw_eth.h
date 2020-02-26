#ifndef _SPW_ETH_H_
#define _SPW_ETH_H_

#ifdef __cplusplus
extern "C"{
#endif

#include <sys/types.h>

#include "spw_eth_structure.h"
#include "spw_eth_print.h"

#if defined(LINUX)
#include <linux/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#elif defined(WIN)
#include <locale.h>
#include <Winsock2.h>
#include <winsock.h>
#include <windows.h>
#include <nspapi.h>
#include <winnetwk.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <winsock2.h>
// Link to Iphlpapi.lib
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
//========================================================================
#if defined(LINUX)

//-------------------------------------
// (Вспомогательная функция) Инициализация моста SpW-Ethernet.
// Входной параметр         - имя Linux устройства Ethernet (к примеру, eth0),
// Возвращаемое значение    - сокет для передачи.
int SpW_Socket_Create_By_Dev(char *device);

// Инициализация моста и библиотеки SpW-Ethernet.
// Входной параметр         - имя Linux устройства Ethernet (к примеру, eth0),
// Возвращаемое значение    - сокет для передачи.
int SpW_Socket_Init(char *device);

// Завершение работы с мостом SpW-Ethernet.
// Входной параметр - сокет для передачи.
void SpW_Socket_Close(int s);

// Реинициализация моста и библиотеки SpW-Ethernet.
// Входные параметры:
// device   - имя Linux устройства Ethernet (к примеру, eth0),
// s        - полученный ранее сокет для передачи.
// Функция сбрасывает все три функции обработчика
// Также обнуляются счетчики последовательности пакетов
int SpW_Socket_Reset(char *device, int s);
//-------------------------------------

/* функции отправки пакетов */
//-------------------------------------
// Отправка пакета.
// Входные параметры:
// s        - сокет для передачи,
// buf      - содержимое пакета,
// buf_size - размер пакета,
// type     - тип пакета.
int SpW_Send_Packet(int s, unsigned char* buf, int buf_size, int type);
// Отправка пакета из канала.
// Входные параметры:
// s        - сокет для передачи,
// buf      - содержимое пакета,
// buf_size - размер пакета,
// type     - тип пакета,
// chn      - канал по которому идет отправка.
int SpW_Send_Packet_From_Channel(int s, unsigned char* buf, int buf_size, int type, char chn);
//-------------------------------------

/* функции приема пакетов */
//------------------------------------
// Блокирующая функция приема пакета.
// Входные параметры:
// s        - сокет для приема,
// buf      - содержимое пакета,
// buf_size - размер пакета.
// mac       - MAC адрес с которого принят пакет
// end_packet- тип принятого пакета ( EOP = 0, EEP = 1) для расширенной версии функции
// доваляются варианты управляющий код SpW_Eth_CCode = 0х6, ошибочный фрейм SpW_Eth_EFrame = 0х7, фрейм состояния SpW_Eth_Status 0х8
// mask      -  маска типов которые  нужно принимать ( допустимо указывать упр. коды, фремы состояния, фреймы об ошибках)
// расширенная  версия фукнкции позволяет работать с мостом без использования функций обработчиков.

int SpW_Recv_Packet(int s, unsigned char* buf, int buf_size, unsigned char* mac, unsigned char *end_packet);
int SpW_Recv_Packet_extended(int s, unsigned char* buf, int buf_size, unsigned char* mac, unsigned char *end_packet, unsigned mask);

//------------------------------------
// Блокирующая функция приема пакета с заданного MAC адреса.
// Входные параметры:
// s        - сокет для приема,
// buf      - содержимое пакета,
// buf_size - размер пакета.
// mac       - MAC адрес с которого ожидается приход пакета
// end_packet- тип принятого пакета ( EOP = 0, EEP = 1) для расширенной версии функции
// доваляются варианты управляющий код SpW_Eth_CCode = 0х6, ошибочный фрейм SpW_Eth_EFrame = 0х7, фрейм состояния SpW_Eth_Status 0х8
// mask      -  маска типов которые  нужно принимать ( допустимо указывать упр. коды, фремы состояния, фреймы об ошибках)   
// расширенная  версия фукнкции позволяет работать с мостом без использования функций обработчиков.
int SpW_Recv_Packet_From_MAC(int s, unsigned char* buf, int buf_size, unsigned char* mac, unsigned char *end_packet);
int SpW_Recv_Packet_From_MAC_extended(int s, unsigned char* buf, int buf_size, unsigned char* mac, unsigned char *end_packet, unsigned mask);

// Блокирующая функция приема пакета  заданного типа.
// Входные параметры:
// s        - сокет для приема,
// buf      - содержимое пакета,
// buf_size - размер пакета,
// type     - тип принимаего пакета.
// mac       - MAC адрес с которого принят пакет
int SpW_Recv_Frame_Type(int s, unsigned char* buf, int buf_size, unsigned mask_types, unsigned *type, unsigned char* mac);

// Блокирующая функция приема пакета заданного типа с заданного MAC адреса.
// Входные параметры:
// s        - сокет для приема,
// buf      - содержимое пакета,
// buf_size - размер пакета,
// type     - тип принимаего пакета.
// mac       - MAC адрес с которого ожидается приход пакета
int SpW_Recv_Frame_Type_From_MAC(int s, unsigned char* buf, int buf_size, unsigned mask_types, unsigned *type, unsigned char* mac);
//-------------------------------------


//-------------------------------------
/* функции отправки управляющих кодов */
// Отправка единичного управляющего когда
// s            - сокет для передачи,
// code         - значение управляющего кода
// regime_5_bit - тип управляющего кода 1- 5 битные упр. коды 0- 6 битные упр.коды
int SpW_Send_Time_Code(int s, unsigned code);
int SpW_Send_ACK_Code(int s, unsigned code,  unsigned regime_5_bit);
int SpW_Send_INT_Code(int s, unsigned code,  unsigned regime_5_bit);
int SpW_Send_CC01_Code(int s, unsigned code,  unsigned regime_5_bit);
int SpW_Send_CC11_Code(int s, unsigned code,  unsigned regime_5_bit);
// Отправка группы управляющих кодов
// s        - сокет для передачи,
// buf      - содержимое пакета,
// buf_size - размер пакета,
// regime_5_bit - тип управляющего кода 1- 5 битные упр. коды 0- 6 битные упр.коды
int SpW_Send_Time_Codes(int s, unsigned char* buf, int buf_size);
int SpW_Send_INT_Codes(int s, unsigned char* buf, int buf_size, unsigned regime_5_bit);
int SpW_Send_ACK_Codes(int s, unsigned char* buf, int buf_size, unsigned regime_5_bit);
int SpW_Send_CC01_Codes(int s, unsigned char* buf, int buf_size, unsigned regime_5_bit);
int SpW_Send_CC11_Codes(int s, unsigned char* buf, int buf_size, unsigned regime_5_bit);
//-------------------------------------
//Отправка группы управляющих кодов разного типа
int SpW_Send_CCodes(int s, unsigned char* buf, int buf_size);
//--------------------------------------
// Прием пакетов статуса
// Входные параметры:
// s             - сокет для приема,
// device        - устройство   для приема,
// state         - структура статуса
// mac           - MAC адрес с которого принят пакет
int SpW_Eth_Get_State(int s, struct spw_eth_state_new *state, unsigned char* mac);
int SpW_Eth_Get_State_By_Dev(char *device, struct spw_eth_state_new *state, unsigned char* mac);
// Прием пакетов статуса с заданного MAC адреса.
// Входные параметры:
// s             - сокет для приема,
// device        - устройство   для приема,
// state         - структура статуса
// mac           - MAC адрес с которого ожидается приход пакета
int SpW_Eth_Get_State_From_MAC(int s, struct spw_eth_state_new *state, unsigned char* mac);
int SpW_Eth_Get_State_By_Dev_From_MAC(char *device, struct spw_eth_state_new *state, unsigned char* mac);
//--------------------------------------

//--------------------------------------
// **** Конфигурационные функции ****
// отправка заранее настроенной структуры конфигурации моста
int SpW_Eth_Send_Conf_Packet(int s, struct spw_eth_conf_header_2 conf_packet_2);

//Установка скорости по каналу SpW (10, 50, 100, 200, 300, 400)
int SpW_Eth_set_SpW_Speed(int s, int speed);


//сброс в конфигурацию по умолчанию
int SpW_Eth_Reset(int s);

//установка MAC адреса назначения
int SpW_Eth_Set_MAC_Dest(int s, char mac[]);

//установка MAC адреса устройства
int SpW_Eth_Set_MAC_Source(int s, char mac[]);

//автоматическая настройка MAC  адреса назначения
int SpW_Eth_Set_Auto_MAC_Dest(int s);

//автоматическая настройка MAC адреса устройства
int SpW_Eth_Set_Auto_MAC_Source(int s);

//  установка режима фильтрации
int SpW_Eth_Set_Filtr(int s, unsigned filtr);

//  установка режима коммутатора
int SpW_Eth_Set_Switch_Mode(int s, unsigned mode_data, unsigned mode_ccode);
#ifdef XILINX_GE_SPW_01_2019
//  установка режима фильтрации пакетов в eth
int SpW_Eth_Set_Filter_Mode(int s, unsigned sniff_filtr, unsigned sniff_mask);
#endif
//  установка  частоты отправки статуса
int SpW_Eth_Set_Status_freq(int s, unsigned period);
//--------------------------------------

#elif defined(WIN)

// Инициализация моста и библиотеки SpW-Ethernet.

// Получение списка сетевых устройств, нумерация устройств 
// начинается с 0. Для отображения описания устройств необходимо  
// писпользовать поля  name и description полученного списка типа pcap_if_t*
pcap_if_t * Create_List_Devices();
// Инициализация сокета для работы с мостом по номеру сетевого устройства
// список устройств берется из результатов выполнения функции
// Create_List_Devices(), нумерация устройств начинается с 0!
pcap_t * SpW_Socket_Init(unsigned device);
// Инициализация сокета для работы с мостом в диалоговом режиме
// удобна для консольных программ
pcap_t * SpW_Socket_Init_Dialog();

// Завершение работы с мостом SpW-Ethernet.
// Входной параметр
// fp -  дескриптор для приема / передачи.
int SpW_Socket_Close(pcap_t *fp);

// Реинициализация моста и библиотеки SpW-Ethernet.
// Входные параметры:
// fp        - полученный ранее дескриптор для приема / передачи.
// Возвращаемое значение    - дескриптор для передачи.
// Функция сбрасывает все три функции обработчика
// Также обнуляются счетчики последовательности пакетов
pcap_t * SpW_Socket_Reset(pcap_t *fp);


/* функции приема пакетов */
// Блокирующая функция приема пакета.
// Входные параметры:
// fp -  дескриптор для приема.
// buf      - содержимое пакета,
// buf_size - размер пакета.
// mac       - MAC адрес с которого принят пакет
// end_packet- тип принятого пакета ( EOP = 0, EEP = 1) для расширенной версии функции
// доваляются варианты управляющий код SpW_Eth_CCode = 0х6, ошибочный фрейм SpW_Eth_EFrame = 0х7, фрейм состояния SpW_Eth_Status 0х8
// mask      -  маска типов которые  нужно принимать ( допустимо указывать упр. коды, фремы состояния, фреймы об ошибках)
// расширенная  версия фукнкции позволяет работать с мостом без использования функций обработчиков.
int SpW_Recv_Packet(pcap_t *fp, unsigned char* buf, int buf_size, unsigned char* mac, unsigned char *end_packet);
int SpW_Recv_Packet_extended(pcap_t *fp, unsigned char* buf, int buf_size, unsigned char* mac, unsigned char *end_packet, unsigned mask);

// Входные параметры:
// fp -  дескриптор для приема.
// buf      - содержимое пакета,
// buf_size - размер пакета.
// mac       - MAC адрес с которого ожидается приход пакета
// end_packet- тип принятого пакета ( EOP = 0, EEP = 1) для расширенной версии функции
// доваляются варианты управляющий код SpW_Eth_CCode = 0х6, ошибочный фрейм SpW_Eth_EFrame = 0х7, фрейм состояния SpW_Eth_Status 0х8
// mask      -  маска типов которые  нужно принимать ( допустимо указывать упр. коды, фремы состояния, фреймы об ошибках)
// расширенная  версия фукнкции позволяет работать с мостом без использования функций обработчиков.
int SpW_Recv_Packet_From_MAC(pcap_t *fp, unsigned char* buf, int buf_size, unsigned char* mac, unsigned char *end_packet);
int SpW_Recv_Packet_From_MAC_extended(pcap_t *fp, unsigned char* buf, int buf_size, unsigned char* mac, unsigned char *end_packet, unsigned mask);

// Блокирующая функция приема пакета  заданного типа.
// Входные параметры:
// fp -  дескриптор для приема.
// buf      - содержимое пакета,
// buf_size - размер пакета,
// type     - тип принимаего пакета.
// mac       - MAC адрес с которого принят пакет
int SpW_Recv_Frame_Type(pcap_t *fp, unsigned char* buf, int buf_size,unsigned mask_types, unsigned *type, unsigned char *mac);

// Блокирующая функция приема пакета заданного типа с заданного MAC адреса.
// Входные параметры:
// fp -  дескриптор для приема.
// buf      - содержимое пакета,
// buf_size - размер пакета,
// type     - тип принимаего пакета.
// mac       - MAC адрес с которого ожидается приход пакета
int SpW_Recv_Frame_Type_From_MAC(pcap_t *fp, unsigned char* buf, int buf_size, unsigned mask_types, unsigned *type, unsigned char* mac);

//------------------------------------
/* функции отправки пакетов */
//-------------------------------------
// Отправка пакета.
// Входные параметры:
// fp -  дескриптор для передачи.
// buf      - содержимое пакета,
// buf_size - размер пакета,
// type     - тип пакета.
int SpW_Send_Packet(pcap_t *fp, unsigned char* buf, int buf_size, int type);
// Отправка пакета из канала.
// Входные параметры:
// fp -  дескриптор для передачи.
// buf      - содержимое пакета,
// buf_size - размер пакета,
// type     - тип пакета,
// chn      - канал по которому идет отправка
int SpW_Send_Packet_From_Channel(pcap_t *fp,  unsigned char* buf, int buf_size, int type, int chn);


// Прием пакета статуса
// Входные параметры:
// fp           -  дескриптор для приема.
// state         - структура статуса
// mac           - MAC адрес с которого принят пакет
int SpW_Eth_Get_State(pcap_t *fp, struct spw_eth_state_new *state, unsigned char *mac);
int SpW_Eth_Get_State_By_Dev( struct spw_eth_state_new *state, unsigned char* mac);
// Прием пакетов статуса с заданного MAC адреса.
// Входные параметры:
// fp           -  дескриптор для приема.
// state         - структура статуса
// mac           - MAC адрес с которого ожидается приход пакета
int SpW_Eth_Get_State_From_MAC(pcap_t *fp, struct spw_eth_state_new *state, unsigned char* mac);
int SpW_Eth_Get_State_By_Dev_From_MAC(struct spw_eth_state_new *state, unsigned char* mac);

//-------------------------------------
/* функции отправки управляющих кодов */
// Отправка единичного управляющего когда
// fp -  дескриптор для передачи.
// code         - значение управляющего кода
// regime_5_bit - тип управляющего кода 1- 5 битные упр. коды 0- 6 битные упр.коды
int SpW_Send_Time_Code(pcap_t *fp, unsigned code);
int SpW_Send_ACK_Code(pcap_t *fp, unsigned code,  unsigned regime_5_bit);
int SpW_Send_INT_Code(pcap_t *fp, unsigned code,  unsigned regime_5_bit);
int SpW_Send_CC01_Code(pcap_t *fp, unsigned code,  unsigned regime_5_bit);
int SpW_Send_CC11_Code(pcap_t *fp, unsigned code,  unsigned regime_5_bit);

// Отправка группы управляющих кодов
// fp -  дескриптор для передачи.
// buf      - содержимое пакета,
// buf_size - размер пакета,
// regime_5_bit - тип управляющего кода 1- 5 битные упр. коды 0- 6 битные упр.коды
int SpW_Send_Time_Codes(pcap_t *fp, unsigned char* buf, int buf_size);
int SpW_Send_INT_Codes(pcap_t *fp, unsigned char* buf, int buf_size, unsigned regime_5_bit);
int SpW_Send_ACK_Codes(pcap_t *fp, unsigned char* buf, int buf_size, unsigned regime_5_bit);
int SpW_Send_CC01_Codes(pcap_t *fp, unsigned char* buf, int buf_size, unsigned regime_5_bit);
int SpW_Send_CC11_Codes(pcap_t *fp, unsigned char* buf, int buf_size, unsigned regime_5_bit);
//Отправка группы управляющих кодов разного типа
int SpW_Send_CCodes(pcap_t *fp, unsigned char* buf, int buf_size);



// **** Конфигурационные функции ****
//Установка скорости по каналу SpW (10, 50, 100, 200, 300, 400)
int SpW_Eth_set_SpW_Speed(pcap_t *fp, int speed);

// отправка заранее настроенной структуры конфигурации моста
int SpW_Eth_Send_Conf_Packet(pcap_t *fp, struct spw_eth_conf_header_2 conf_packet_2);

//сброс в конфигурацию по умолчанию
int SpW_Eth_Reset(pcap_t *fp);

//установка MAC адреса назначения
int SpW_Eth_Set_MAC_Dest(pcap_t *fp, char mac[]);

//установка MAC адреса устройства
int SpW_Eth_Set_MAC_Source(pcap_t *fp, char mac[]);

//автоматическая настройка MAC  адреса назначения
int SpW_Eth_Set_Auto_MAC_Dest(pcap_t *fp);

//автоматическая настройка MAC адреса устройства
int SpW_Eth_Set_Auto_MAC_Source(pcap_t *fp);

//  установка режима фильтрации
int SpW_Eth_Set_Filtr(pcap_t *fp, unsigned filtr);

//  установка режима коммутатора
int SpW_Eth_Set_Switch_Mode(pcap_t *fp, unsigned mode_data, unsigned mode_ccode);
#ifdef XILINX_GE_SPW_01_2019
//  установка режима фильтрации пакетов в eth
int SpW_Eth_Set_Filter_Mode(pcap_t *fp, unsigned sniff_filtr, unsigned sniff_mask);
#endif
//  установка  частоты отправки статуса
int SpW_Eth_Set_Status_freq(pcap_t *fp, unsigned period);

#endif

//======= Вспомагательный функционал ==============================
// установк всех счетчиков пакетов в нулевое значение
void set_sequence_to_zero();
// проверка типа пришедшего пакета, если тип пакета определен возвращает 1, в противном случае 0
int check_frame_type(int type);
//=======работа с mac adress
// функции считывания текуших занчений  mac adress из библиотеки, длина mac adress всегда равна ETH_ALEN (6 байт)
unsigned char* get_current_source_mac_adress(); //возвращает текущий mac adress
unsigned char* get_current_dest_mac_adress();  //возвращает текущий mac adress

/* функции устанавливает новые занчения mac adress, в качестве длины должно подаваться значение от 1 до ETH_ALEN
  в случае успешного выполнения возвращается значение 0, если подать не правильное значение длины функции вернут значение -1 */
int set_source_mac_adress(unsigned char* adress, int len);
int set_dest_mac_adress(unsigned char* adress, int len);




/*  Работа с функциями обработчиками  */
// Прототипы функций обработчиков, вызывающейся при возникновении прерывания  по приему пакета определенного типа
// buf      - содержимое пакета,
// buf_size - размер пакета,
// mac       - MAC адрес с которого принят пакет
typedef void (*SpW_Eth_CCode_Function)(const void *buf, unsigned len, unsigned char *mac_recv);
typedef void (*SpW_Eth_Err_Frame_Function)(const void *buf, unsigned len, unsigned char *mac_recv);
typedef void (*SpW_Eth_Status_Function)(const void *buf, unsigned len, unsigned char *mac_recv);

/* Регистрация функций обработчиков  */
/* В качестве параметра подается функция, которая будет обрабатывать произошедшее событие (прием статуса,
 * управляющего кода, пакета об ошибках), если регистрация прошла успешно, возращается 0, в случае ошибки -1
*/

int register_ccode_event_handler(SpW_Eth_CCode_Function func);
int register_err_frame_event_handler(SpW_Eth_Err_Frame_Function func);
int register_status_event_handler(SpW_Eth_Status_Function func);

//========================================
/* Функции проверки состояния функций обработчиков.
 * В случае если функция обработчик не зарегестрирована для текущего события,
 * то функции возвращают NULL
*/
SpW_Eth_Status_Function get_handler_status_state();
SpW_Eth_Err_Frame_Function get_handler_err_frame_state();
SpW_Eth_CCode_Function get_handler_ccode_state();

/* Функции отключения работы  функций обработчиков событий.
*/

void disable_handler_status();
void disable_handler_err_frame();
void disable_handler_ccode();


unsigned get_while_active();
void set_while_active(unsigned val);

#ifdef __cplusplus
}
#endif

#endif
