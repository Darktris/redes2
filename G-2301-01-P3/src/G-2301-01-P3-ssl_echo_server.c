/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P3-ssl_echo_server.c
  @brief Servidor de echo SSL
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/04/28
*/
#include "G-2301-01-P3-ssl-server.h"
#include "G-2301-01-P3-ssl.h"
#include <G-2301-01-P1-daemon.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
/**
  @brief Funcion de atencion a las conexiones
  @param data: Datos recibidos y de la conexion
  @return Ningún valor definido, la función controla el error de manera interna
*/
void* echo(void* data) {
	conn_data* thread_data = (conn_data*) data;
	if(pthread_detach(pthread_self())!=0) {
		perror("");
	}
	//printf("Mensaje: %s\n",(char*) thread_data->msg);
	syslog(LOG_INFO, "Mensaje: %s",(char*) thread_data->msg);
	if(enviar_datos_SSL(thread_data->socketd, thread_data->msg, thread_data->len)<0) {
		perror("");
        syslog(LOG_INFO, "Error while sending");
	}
	connection_unblock_SSL(thread_data->socketd);
	free(thread_data->msg);
	free(thread_data);
	pthread_exit(0);
}

/**
  @brief Llamada principal del servidor
  @param argc: Num de argumentos
  @param argv: Argumentos
  @return 0
*/
int main(int argc, char** argv) {
	int ret;
    char* host;
	if(argc!=2 && argc!=3) {
        printf("%d", argc);
        printf("Use: %s port [--nodaemon]\n", argv[0]);
    }
    puts("Launching server"); 
	if(argc == 2 || strcmp(argv[2], "--nodaemon"))daemonize("echo_server");
	ret = server_launch_SSL(atoi(argv[1]), echo, NULL);
	printf("Retorno del servidor: %d\n",ret);
	syslog(LOG_INFO, "Retorno del servidor: %d",ret);
}
