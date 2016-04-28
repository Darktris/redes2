/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-udp.c
  @brief Libreria de manejo de sockets UDP
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/04/16
  */
#include <G-2301-01-P1-udp.h>
#include <stdio.h>          
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/**
  @brief Abre un socket UDP para servidor
  @param port: Puerto desde el que se desea escuchar
  @param socketd: Puntero al descriptor del socket
  @return UDPOK si todo funciono correctamente
          UDPERR_ARGS/SOCKET/BIND en caso de error con estas funciones
*/
int server_udpsocket_open(uint16_t port, int* socketd) { 
    struct sockaddr_in addr; 

    /* Control de errores */
    if(socketd==NULL || !port) {
        return UDPERR_ARGS;
    }
    /* Creacion del socket */
    if ((*socketd=socket(AF_INET, SOCK_DGRAM, 0)) == -1 ) {  
        return UDPERR_SOCKET;
    }

    /* Datos del servidor */
    addr.sin_family = AF_INET;         
    addr.sin_port = htons(port); 
    addr.sin_addr.s_addr = INADDR_ANY; 
    bzero(&addr.sin_zero,8); 

    /* Unimos el socket al proceso */
    if(bind(*socketd,(struct sockaddr*)&addr,sizeof(addr)) == -1) {
        return UDPERR_BIND;
    }     

    return UDPOK;
}

/**
  @brief Abre un socket UDP para cliente
  @param port: Puerto desde el que se desea escuchar
  @param socketd: Puntero al descriptor del socket
  @return UDPOK si todo fue correcto
          UDPERR_ARGS/SOCKET en caso de error con estas funciones
*/
int client_udpsocket_open(uint16_t port, int* socketd) { 
    /* Control de errores */
    if(socketd==NULL || !port) {
        return UDPERR_ARGS;
    }
    /* Creacion del socket */
    if ((*socketd=socket(AF_INET, SOCK_DGRAM, 0)) == -1 ) {  
        return UDPERR_SOCKET;
    }

    return UDPOK;
}

/**
  @brief Envia los datos a traves del socket UDP
  @param socketd: Descriptor del socket escuchado
  @param dst: direccion INET de destino
  @param port: puerto INET de destino
  @param data: puntero a los datos que se han de enviar
  @param len: tamano de los datos a enviar
  @return UDPOK si todo fue correcto
          UDPERR_ARGS/SEND en caso de error con estas funciones
*/
int udpsocket_snd(int socketd, char* dst, uint16_t port, void* data, size_t len) {
    struct sockaddr_in addr; 
    int sent, rest;
 
    /* Control de errores */
    if(socketd==-1 || dst==NULL || !strlen(dst) || !port || data==NULL || !len) {
        return UDPERR_ARGS;
    }

    /* Datos del destino */
    if (!inet_aton(dst, &addr.sin_addr)) {
        return UDPERR_ARGS;
    }
    addr.sin_family = AF_INET;         
    addr.sin_port = htons(port); 
    bzero(&addr.sin_zero,8); 

    /* Envia datos por el socket hasta que se acaban */
    do {
        sent=sendto(socketd,data,len,0,(struct sockaddr*)&addr,sizeof(addr)); 
        if(sent==-1) {
            return UDPERR_SEND;
        }
        rest=len-sent;
    } while(rest);
    return UDPOK;
}

/**
  @brief Recibe a traves del socket UDP
  @param socketd: Descriptor del socket escuchado
  @param src: direccion INET de origen
  @param port: puerto INET de origen
  @param data: puntero a donde se almacenan los datos
  @param max: tamaño de la zona de memoria
  @param len: puntero a la variable de longitud recibida
  @return UDPOK si todo fue correcto
          UDPERR_ARGS/RECV en caso de error con estas funciones
*/
int udpsocket_rcv(int socketd, char* src, uint16_t port, void* data, size_t max, size_t* len) {
    struct sockaddr_in addr; 
    size_t n;
    socklen_t addr_len;
    
    /* Control de errores */
    if(socketd==-1 || src==NULL || !strlen(src) || !port || data==NULL || !max || len==NULL) {
        return UDPERR_ARGS;
    }
    
    /* Datos del destino */
    if (!inet_aton(src, &addr.sin_addr)) {
        return UDPERR_ARGS;
    }
    addr.sin_family = AF_INET;         
    addr.sin_port = htons(port); 
    bzero(&addr.sin_zero,8); 

    /* Recepción de los datos */
    n=recvfrom(socketd,data,max,0,(struct sockaddr*)&addr,&addr_len);
    if(n==-1) {
        return UDPERR_RECV;
    }
    *len=n;
    return UDPOK;
}
