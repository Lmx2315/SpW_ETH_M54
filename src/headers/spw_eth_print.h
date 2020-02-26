#ifndef _SPW_ETH_PRINT_H_
#define _SPW_ETH_PRINT_H_

#ifdef __cplusplus
extern "C"{
#endif

#include "spw_eth_structure.h"

// отображение структуры конфигурации моста
void Show_Conf_Header (struct spw_eth_conf_header_2 conf_packet);
// вывод описания типа пакета
void print_frame_type(int type) ;
// вывод описания типа ошибки
void print_error_type(int type);
// вывод  блока памяти
// caption - комментарий к выводу
// data - указатель на начало блока памяти
// len   - длина вывода
void debug_dump (const char *caption, void* data, unsigned len);
// вывод  режима отправка данных моста
void print_switch_mode(__u8 switch_mode);
// вывод  режима отправка управляющих кодов моста
void print_switch_mode_ccode(__u8 switch_mode);
// вывод  текущей скорости в SpW  портах
void print_speed(__u8 speed);
// вывод  состояния в  SpW  порту
void print_conn_state(__u8 val);
// вывод структуры статуса
void print_spw_eth_state(struct spw_eth_state_new *st);
// служебная функция для проверки введеных парметров в  различных меню
int menu_select_valid (char s);

#ifdef __cplusplus
}
#endif

#endif
