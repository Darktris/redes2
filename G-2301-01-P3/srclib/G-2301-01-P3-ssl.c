/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P3-ssl.c
  @brief Libreria de manejo de la capa SSL
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/04/21
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


SSL_CTX *sslctx=NULL;
typedef SSL* pSSL;
pSSL s_sockets[MAX_FD]={0};

/**
  @brief Inicializa el nivel SSL
*/
void inicializar_nivel_SSL() { 
    SSL_load_error_strings();
    SSL_library_init();
}

/**
  @brief Fija el contexto SSL
  @param pk: Clave privada
  @param cer: Certificado
  @return SSL_NOCTX, SSL_VERLOCATION, SSL_CERT, SSL_PKEY, SSLOK
*/
int fijar_contexto_SSL(char* pk, char* cert) {
    sslctx = SSL_CTX_new( SSLv23_method());
    if(!sslctx) {perror("No contex"); return SSL_NOCTX;}
    ERR_print_errors_fp(stderr);
    if(!SSL_CTX_load_verify_locations(sslctx, FILE_CA_CERTIFICATE, PATH_CA_CERTIFICATE)) {perror("Verify_locations"); return SSL_VERLOCATION;}
    ERR_print_errors_fp(stderr);
    SSL_CTX_set_default_verify_paths(sslctx);
    ERR_print_errors_fp(stderr);
    //if(SSL_CTX_use_certificate_chain_file(sslctx, cert)!=1) {perror("Certificate"); return SSL_CERT;}
    SSL_CTX_use_certificate_file(sslctx, cert, SSL_FILETYPE_PEM);
    ERR_print_errors_fp(stderr);
    if(SSL_CTX_use_PrivateKey_file(sslctx, pk, SSL_FILETYPE_PEM) != 1) {perror("Private Key"); return SSL_PKEY;}
    ERR_print_errors_fp(stderr);
    SSL_CTX_set_verify(sslctx,SSL_VERIFY_PEER, NULL);
    ERR_print_errors_fp(stderr);
    return 0;
}

/**
  @brief Inicia el handshake SSL en el lado del cliente
  @param socketd: El socket asociado a la conexion con la que se quiere conectar con SSL
  @return SSL_FAIL, SSL_FD, SSLOK
*/
int conectar_canal_seguro_SSL(int socketd) {
    s_sockets[socketd] = SSL_new(sslctx);
    if(SSL_set_fd(s_sockets[socketd], socketd)!=1) return SSL_FD;
    if(SSL_connect(s_sockets[socketd]) != 1) return SSL_FAIL;
    return 0;
}

/**
  @brief Inicia el handshake SSL en el lado del servidor
  @param socketd: El socket asociado a la conexion con la que se quiere conectar con SSL
  @return SSL_FAIL, SSL_FD, SSLOK
*/
int aceptar_canal_seguro_SSL(int socketd) {
    s_sockets[socketd] = SSL_new(sslctx);
    if(SSL_set_fd(s_sockets[socketd], socketd)!=1) return SSL_FD;
    if(SSL_accept(s_sockets[socketd]) != 1) return SSL_FAIL;
    return 0;
}

/**
  @brief Evalua si la conexion es segura (hay certificado y es valido)
  @param socketd: El socket asociado a la conexion con la que se quiere conectar con SSL
  @return SSL_FAIL, SSL_FD, SSLOK
*/
int evaluar_post_connectar_SSL(int socketd) {
    if(s_sockets[socketd] == NULL)  return 0;
    return SSL_get_peer_certificate(s_sockets[socketd]) && SSL_get_verify_result(s_sockets[socketd]);
}

/**
  @brief Envia un buffer por la capa SSL (cifrado)
  @param socketd: El socket asociado a la conexion 
  @param buf: El buffer que se quiere enviar
  @param len: La longitud del buffer
  @return SSL_FAIL, SSL_FD, SSLOK
*/
int enviar_datos_SSL(int socketd, void* buf, int len) {
    if(!buf||len < 1||!s_sockets[socketd]) return -1;
    return SSL_write(s_sockets[socketd], buf, len);
}

/**
  @brief Evalua si la conexion es segura (hay certificado y es valido)
  @param socketd: El socket asociado a la conexion
  @param buf: El buffer que se quiere llenar
  @param max_len: Longitud del buffer
  @param len: La longitud del buffer que ha sido llenada
  @return TCPERR_RECV, TCPCONN_CLOSED, TCPOK
*/
int recibir_datos_SSL(int socketd, void* buf, int max_len, int* len) {
    if(!s_sockets[socketd]) return TCPERR_RECV;
    bzero(buf, max_len);
    *len = SSL_read(s_sockets[socketd], buf, max_len);
    if(*len<0) return TCPERR_RECV;
    return *len?TCPOK:TCPCONN_CLOSED;
}
/**
  @brief Cierra la conexion SSL con el socketd
  @param socketd: El socket asociado a la conexion
*/
void cerrar_canal_SSL(int socketd) {
   if(!s_sockets[socketd]) return;
   SSL_shutdown(s_sockets[socketd]); 
   SSL_free(s_sockets[socketd]);
   s_sockets[socketd]=NULL;
}
/**
  @brief Libera las estructuras SSL
*/
void liberar_nivel_SSL() {
    SSL_CTX_free(sslctx);
    sslctx = NULL;
}


