/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P2-rtp.c
  @brief Libreria de manejo de paquetes RTP
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/04/16
  */
#include <G-2301-01-P2-rtp.h>
#include <G-2301-01-P1-udp.h>
#include <stdio.h>          
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/**
  @brief Envia un paquete RTP
  @param socketd: Puntero al descriptor del socket
  @param dst: direccion INET de destino
  @param port: puerto INET de destino
  @param args: argumentos RTP
  @param data: puntero a los datos que se han de enviar
  @param len: tamano de los datos a enviar
  @return RTPOK si todo funciono correctamente
          RTPERR en caso de error
*/
int rtp_sndpkg(int socketd, char* dst, uint16_t port, rtpargs_t args, void* data, size_t len) {
    uint8_t* dgram;
    size_t dlen = RTP_HLEN+len;

    /* Control de errores */
    if(socketd==-1 || dst==NULL || !strlen(dst) || !port || data==NULL || !len) {
        return RTPERR_ARGS;
    }

    /* Rellenar datagrama UDP */
    dgram = malloc(dlen);
    if(dgram==NULL) {
        return RTPERR_MEM;
    }
    bzero(dgram,dlen);
    memcpy(dgram+RTP_OFFSET,&args,sizeof(args));
    memcpy(dgram+RTP_HLEN,data,len);

    /* Enviar por socket UDP */
    if(udpsocket_snd(socketd,dst,port,dgram,dlen)!=UDPOK) {
        free(dgram);
        return RTPERR_ARGS;
    }

    return RTPOK;
}

/**
  @brief Recibe un paquete RTP
  @param socketd: Puntero al descriptor del socket
  @param src: direccion INET de origen
  @param port: puerto INET de origen
  @param args: puntero a argumentos RTP
  @param data: puntero a donde se almacenan los datos
  @param len: puntero a la longitud recibida
  @return RTPOK si todo funciono correctamente
          RTPERR en caso de error
*/
int rtp_rcvpkg(int socketd, char* src, uint16_t port, rtpargs_t* args, void* data, size_t *len) {
    uint8_t dgram[RTP_MAXLEN+RTP_HLEN];
    size_t dlen;

    /* Control de errores */
    if(socketd==-1 || src==NULL || !strlen(src) || !port || data==NULL || len==NULL) {
        return RTPERR_ARGS;
    }

    /* Recibir por socket UDP */
    if(udpsocket_rcv(socketd,src,port,dgram,RTP_MAXLEN+RTP_HLEN,&dlen)!=UDPOK) {
        return RTPERR_ARGS;
    }
    *len=dlen-RTP_HLEN;

    /* Rellenar argumentos RTP */
    memcpy(args,dgram+RTP_OFFSET,sizeof(rtpargs_t));
    memcpy(data,dgram+RTP_HLEN,*len);

    return RTPOK;
}
