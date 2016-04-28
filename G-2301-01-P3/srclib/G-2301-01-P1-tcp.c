/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-tcp.c
  @brief Libreria de manejo de sockets TCP
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/02/01
  */
#include "G-2301-01-P1-tcp.h"
#include <stdio.h>         
#include <stdlib.h>
#include <netdb.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
/**
  @brief Abre un socket TCP para servidor
  @param port: Puerto desde el que se desea escuchar
  @param socketd: Puntero al descriptor del socket
  @return TCPOK si todo funciono correctamente
          TCPERR_ARGS/SOCKET/BIND/LISTEN en caso de error con estas funciones
*/
int server_tcpsocket_open(uint16_t port, int* socketd) { 
    struct sockaddr_in addr; 

    /* Control de errores */
    if(socketd==NULL || !port) {
        return TCPERR_ARGS;
    }
    /* Creacion del socket */
    if ((*socketd=socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {  
        return TCPERR_SOCKET;
    }

    /* Datos del servidor */
    addr.sin_family = AF_INET;         
    addr.sin_port = htons(port); 
    addr.sin_addr.s_addr = INADDR_ANY; 
    bzero(&addr.sin_zero,8); 

    int yes=1; 

     if (setsockopt(*socketd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) { 
        return TCPERR_BIND;
     }  
    /* Unimos el socket al proceso */
    if(bind(*socketd,(struct sockaddr*)&addr,sizeof(addr)) == -1) {
        return TCPERR_BIND;
    }     

    /* Empieza a escuchar conexiones */
    if(listen(*socketd,BACKLOG) == -1) {  
        return TCPERR_LISTEN;
    }

    return TCPOK;
}

/**
  @brief Abre un socket TCP para cliente
  @param port: Puerto desde el que se desea escuchar
  @param socketd: Puntero al descriptor del socket
  @return TCPOK si todo fue correcto
          TCPERR_ARGS/SOCKET/BIND/LISTEN en caso de error con estas funciones
*/
int client_tcpsocket_open(uint16_t port, int* socketd, char* hostname) { 
    struct sockaddr_in addr;
    struct hostent* dest;
    /* Control de errores */
    if(socketd==NULL || !port) {
        return TCPERR_ARGS;
    }
    /* Creacion del socket */
    if ((*socketd=socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {  
        return TCPERR_SOCKET;
    }

    dest = gethostbyname(hostname);
    if(dest==NULL) {
        return TCPERR_NOHOST;
    }
    /* Datos del socket */
    addr.sin_family = AF_INET;         
    addr.sin_port = htons(port); 
    bcopy((char *)dest->h_addr, &addr.sin_addr.s_addr, dest->h_length); 
    bzero(&addr.sin_zero,8); 

    if(connect(*socketd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        return TCPERR_CONN;
    }
    return TCPOK;
}

/**
  @brief Acepta una conexion a socket TCP
  @param socketd: Descriptor del socket escuchado
  @param args: estructura de datos de la conexion
  @return TCPOK si todo fue correcto
          TCPERR_ARGS/ACCEPT/PTHREAD en caso de error con estas funciones
*/
int tcpsocket_accept(int socketd, tcpsocket_args* args) {
    int acceptd=0;

    /* Control de errores */
    if(socketd==-1 || args==NULL) {
        return TCPERR_ARGS;
    }

    /* Acepta la conexión */
    args->acceptd=accept(socketd,(struct sockaddr *)&(args->client),&(args->clientlen));
    if(acceptd==-1) {
        return TCPERR_ACCEPT;
    }

    return TCPOK;
}


/**
  @brief Envia los datos a traves del socket TCP
  @param socketd: Descriptor del socket escuchado
  @param data: puntero a los datos que se han de enviar
  @param len: tamano de los datos a enviar
  @return TCPOK si todo fue correcto
          TCPERR_ARGS/SEND en caso de error con estas funciones
*/
int tcpsocket_snd(int socketd, void* data, size_t len) {
    int sent, rest;
    char debug[200];
    /* Control de errores */
    if(socketd==-1 || data==NULL || !len) {
        return TCPERR_ARGS;
    }
    /* Envia datos por el socket hasta que se acaban */
    do {
        sent=send(socketd,data,len,0); 
        if(sent==-1) {
            return TCPERR_SEND;
        }
        data+=sent;
        rest=len-sent;
    } while(rest);
    return TCPOK;
}

/**
  @brief Recibe a traves del socket TCP
  @param socketd: Descriptor del socket escuchado
  @param data: puntero a donde se almacenan los datos
  @param max: tamaño de la zona de memoria
  @param len: puntero a la variable de longitud recibida
  @return TCPOK si todo fue correcto
          TCPERR_ARGS/RECV en caso de error con estas funciones
*/
int tcpsocket_rcv(int socketd, void* data, size_t max, size_t* len) {
    size_t n;
    /* Control de errores */
    if(socketd==-1 || data==NULL || !max || len==NULL) {
        return TCPERR_ARGS;
    }
    
    /* Recepción de los datos */
    bzero(data, max);
    n=recv(socketd,data,max,0);
    if(n==-1) {
        return TCPERR_RECV;
    }
    *len=n;
    return n==0? TCPCONN_CLOSED:TCPOK;
}

/**
  @brief Cierra un socket TCP
  @param socketd: descriptor del socket
*/
void tcpsocket_close(int socketd) {
    close(socketd);
}
