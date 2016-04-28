/* vim: set ts=4 sw=4 et: */
#ifndef _G_2301_01_P1_UDP_H
#define _G_2301_01_P1_UDP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Valores de retorno */
#define UDPOK 0
#define UDPERR_ARGS -1
#define UDPERR_SOCKET -2
#define UDPERR_BIND -3
#define UDPERR_SEND -7
#define UDPERR_RECV -8

/* Funciones */
int server_udpsocket_open(uint16_t port, int* socketd);
int client_udpsocket_open(uint16_t port, int* socketd);
int udpsocket_snd(int socketd, char* dst, uint16_t port, void* data, size_t len);
int udpsocket_rcv(int socketd, char* src, uint16_t port, void* data, size_t max, size_t* len);

#endif
