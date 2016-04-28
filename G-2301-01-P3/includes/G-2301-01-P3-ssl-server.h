#ifndef _SERVER_SSL_H
#define _SERVER_SSL_H

#include <pthread.h>
#include <G-2301-01-P1-server.h>
#include <G-2301-01-P1-tcp.h>
#define DATA_SIZE 2000

#define SERVOK 0
#define SERVERR_PTHREAD -1
#define SERVERR_SIGNAL -2
#define SERVERR_SOCKET -3
#define SERVERR_ACCEPT -4
#define SERVERR_MALLOC -5
#define SERVERR_ARGS - -6
#define SERVERR_SELECT -7
#define SERVERR_RCV -8
#define SERVERR_NRUN -9

int server_launch_SSL(uint16_t port,  void*(*handler)(void*), void* more);
int connection_block_SSL(int socketd);
int connection_unblock_SSL(int socketd);
int connection_rmv_SSL(int socketd);
int server_stop_SSL(); 
char* get_ip_from_connection_SSL(int socketd);
int set_do_on_disconnect_SSL(void(*handler)(void*));
#endif 
