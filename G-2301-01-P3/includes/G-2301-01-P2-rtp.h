/* vim: set ts=4 sw=4 et: */
#ifndef _G_2301_01_P2_RTP_H
#define _G_2301_01_P2_RTP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Valores de retorno */
#define RTPOK 0
#define RTPERR_ARGS -1
#define RTPERR_MEM -2

/* Constantes */
#define RTP_MAXLEN 64984
#define RTP_HLEN 16
#define RTP_OFFSET 1

/* Estructuras */
typedef struct {
    uint8_t pt; //tipo de carga
    uint16_t seq; //numero de secuencia
    uint32_t ts; //marca de tiempo
    uint32_t ssrc; //campo de sincronizacion
} rtpargs_t;

/* Funciones */
int rtp_sndpkg(int socketd, char* dst, uint16_t port, rtpargs_t args, void* data, size_t len);
int rtp_rcvpkg(int socketd, char* src, uint16_t port, rtpargs_t* args, void* data, size_t *len);

#endif
