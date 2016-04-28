/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-tcp.c
  @brief Libreria de manejo de sockets TCP con capa SSL por encima
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/02/01
  */
#include "G-2301-01-P1-tcp.h"
#include "G-2301-01-P3-ssl.h"
#include <stdio.h>         
#include <stdlib.h>
#include <netdb.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>


SSL_CTX *sslctx;
typedef SSL* pSSL;
pSSL s_sockets[MAX_FD];
/**
  @brief Inicializa el nivel SSL
  @return SSLERR, SSLOK
  */
int inicializar_nivel_SSL() { 
    SSL_load_error_strings();
    SSL_library_init();
    //OpenSSL_add_all_algorithms();
}

/**
  @brief Inicializa el nivel SSL
  @return SSLERR, SSLOK
  */
int fijar_contexto_SSL(char* pk, char* cert) {
    sslctx = SSL_CTX_new( SSLv23_method());
    if(!sslctx) return SSL_NOCTX;
    ERR_print_errors_fp(stderr);
    if(!SSL_CTX_load_verify_locations(sslctx, FILE_CA_CERTIFICATE, PATH_CA_CERTIFICATE)) return SSL_VERLOCATION;
    ERR_print_errors_fp(stderr);
    SSL_CTX_set_default_verify_paths(sslctx);
    ERR_print_errors_fp(stderr);
    if(SSL_CTX_use_certificate_chain_file(sslctx, cert)!=1) return SSL_CERT;
    ERR_print_errors_fp(stderr);
    if(SSL_CTX_use_PrivateKey_file(sslctx, pk, SSL_FILETYPE_PEM) != 1) return SSL_PKEY;
    ERR_print_errors_fp(stderr);
    SSL_CTX_set_verify(sslctx,SSL_VERIFY_PEER, NULL);
    ERR_print_errors_fp(stderr);
    return 0;
}
/**
  @brief Inicializa el nivel SSL
  @return SSLERR, SSLOK
  */
int conectar_canal_seguro_SSL(int socketd) {
    s_sockets[socketd] = SSL_new(sslctx);
    if(SSL_set_fd(s_sockets[socketd], socketd)!=1) return SSL_FD;
    if(SSL_connect(s_sockets[socketd]) != 1) return SSL_FAIL;
    return 0;
}

int aceptar_canal_seguro_SSL(int socketd) {
    s_sockets[socketd] = SSL_new(sslctx);
    if(SSL_set_fd(s_sockets[socketd], socketd)!=1) return SSL_FD;
    if(SSL_accept(s_sockets[socketd]) != 1) return SSL_FAIL;
    return 0;
}

int evaluar_post_connectar_SSL(int socketd) {
    return SSL_get_peer_certificate(s_sockets[socketd]) && SSL_get_verify_result(s_sockets[socketd]);
}

int enviar_datos_SSL(int socketd, void* buf, int len) {
    if(!buf||len < 1) return -1;
    return SSL_write(s_sockets[socketd], buf, len);
}
int recibir_datos_SSL(int socketd, void* buf, int max_len, int* len) {
    *len = SSL_read(s_sockets[socketd], buf, max_len);
    if(*len<0) return TCPERR_RECV;
    return *len?TCPOK:TCPCONN_CLOSED;
}
int cerrar_canal_SSL(int socketd) {
}
