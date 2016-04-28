/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-tools.c
  @brief Libreria de utilidades
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
size_t _strlen(const char* s) {
    if(s==NULL) return 0;
    #undef strlen
    return strlen(s);
    #define strlen _strlen
}

int _strcmp(const char* a, const char* b) {
    if(a==NULL || b==NULL) return 1;
    #undef strcmp
    return strcmp(a,b);
    #define strcmp _strcmp
}

void _free(void* a) {
return;
}
