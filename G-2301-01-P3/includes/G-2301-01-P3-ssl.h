#ifndef _SSL_H_
#define _SSL_H_

#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h> 
#define FILE_CA_CERTIFICATE "./cert/ca/rootcert.pem"
#define FILE_SERVER_CERTIFICATE "./cert/server/servercert.pem"
#define FILE_SERVER_PKEY "./cert/server/serverkey.pem"
#define FILE_CLIENT_CERTIFICATE "./cert/client.pem"
#define FILE_CLIENT_PKEY "./cert/client.pem"

#define PATH_CA_CERTIFICATE NULL

#define SSL_NOCTX -1
#define SSL_VERLOCATION -2
#define SSL_CERT -3
#define SSL_PKEY -4
#define SSL_FD -5
#define SSL_FAIL -6
#define MAX_FD 1024

int inicializar_nivel_SSL();
int fijar_contexto_SSL(char* pk, char* cert);
int conectar_canal_seguro_SSL(int socketd);
int aceptar_canal_seguro_SSL(int socketd);
int evaluar_post_connectar_SSL(int socketd);
int enviar_datos_SSL(int socketd, void* buf, int len);
int recibir_datos_SSL(int socketd, void* buf, int max_len, int* len);
int cerrar_canal_SSL(int socketd);
#endif
