/* vim: set ts=4 sw=4 et: */
#ifndef _G_2301_01_P1_TCP_H
#define _G_2301_01_P1_TCP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Estructuras de datos */
typedef struct {
    int socketd, acceptd; 
    socklen_t clientlen; 
    struct sockaddr_in client;
} tcpsocket_args ;

/* Valores de retorno */
#define TCPCONN_CLOSED 1
#define TCPOK 0
#define TCPERR_ARGS -1
#define TCPERR_SOCKET -2
#define TCPERR_BIND -3
#define TCPERR_LISTEN -4
#define TCPERR_ACCEPT -6
#define TCPERR_SEND -7
#define TCPERR_RECV -8
#define TCPERR_NOHOST -9
#define TCPERR_CONN -9

/* Constantes */
#define BACKLOG 5

/* Funciones */
int server_tcpsocket_open(uint16_t port, int* socketd);
int client_tcpsocket_open(uint16_t port, int* socketd, char* hostname);
int tcpsocket_accept(int socketd, tcpsocket_args* args);
int tcpsocket_snd(int socketd, void* data, size_t len);
int tcpsocket_rcv(int socketd, void* data, size_t max, size_t* len);
void tcpsocket_close(int socketd);

#endif
