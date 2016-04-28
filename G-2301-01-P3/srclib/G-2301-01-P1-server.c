/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-server.c
  @brief Libreria de manejo de un servidor de sockets
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/02/01
  */
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <G-2301-01-P1-tcp.h>
#include "G-2301-01-P1-server.h"

pthread_mutex_t mutex_conn;
fd_set connections, readable, blocked;
int loop;
char ips[FD_SETSIZE][16];
void(*handler_disconnection)(void*) = NULL;

/**
  @brief Añade una conexion al conjunto del select
  @param socketd: Descriptor del socket
  @return SERVOK
*/
int connection_add(int socketd) {
	pthread_mutex_lock(&mutex_conn);
	FD_SET(socketd, &connections);
	pthread_mutex_unlock(&mutex_conn);
	return SERVOK;
}

/**
  @brief Borra una conexion del conjunto del select
  @param socketd: Descriptor del socket
  @return SERVOK
*/
int connection_rmv(int socketd) {
	pthread_mutex_lock(&mutex_conn);
	FD_CLR(socketd, &connections);
	pthread_mutex_unlock(&mutex_conn);
	return SERVOK;
}

/**
  @brief Indica si hay una conexion abierta
  @param socketd: Descriptor del socket
  @return 0 si esta cerrada, cualquier valor en otro caso
*/
int is_connected(int socketd) {
	int i=0;
	pthread_mutex_lock(&mutex_conn);
	i=FD_ISSET(socketd, &connections);
	pthread_mutex_unlock(&mutex_conn);
	return i;
}

/**
  @brief Indica si hay una conexion que requiere atencion
  @param socketd: Descriptor del socket
  @return 0 si esta cerrada, cualquier valor en otro caso
*/
int is_readable(int socketd) {
	int i=0;
	pthread_mutex_lock(&mutex_conn);
	i=FD_ISSET(socketd, &readable);
	pthread_mutex_unlock(&mutex_conn);
	return i;
}

/**
  @brief Bloquea una conexion
  @param socketd: Descriptor del socket
  @return SERVOK
*/
int connection_block(int socketd) {
    pthread_mutex_lock(&mutex_conn);
    FD_SET(socketd, &blocked);
    pthread_mutex_unlock(&mutex_conn);
    return SERVOK;
}

/**
  @brief Desbloquea una conexion
  @param socketd: Descriptor del socket
  @return SERVOK
*/
int connection_unblock(int socketd) {
    pthread_mutex_lock(&mutex_conn);
    FD_CLR(socketd, &blocked);
    pthread_mutex_unlock(&mutex_conn);
    return SERVOK;
}

/**
  @brief Comprueba si una conexion esta bloqueada
  @param socketd: Descriptor del socket
  @return 0 si no esta bloqueada, otro valor si esta bloqueada
*/
int connection_isblocked(int socketd) {
    int i;
    pthread_mutex_lock(&mutex_conn);
    i=FD_ISSET(socketd, &blocked);
    pthread_mutex_unlock(&mutex_conn);
    return i;
}

/**
  @brief Devuelve la ip asociada a un socked
  @param socketd: Descriptor del socket
  @return La ip del socket en decimal
*/
char* get_ip_from_connection(int socketd) {
    return ips[socketd];
}


/**
  @brief Manejador de la señal 
  @param sig: señal recibido
  @return 0 si no esta bloqueada, otro valor si esta bloqueada
*/
void sigint_handler(int sig) {
    pthread_mutex_destroy(&mutex_conn);
    loop=0;
}

/**
  @brief Lanza un servidor que atiende cada mensaje recibido con la funcion handler
  @param port: Puerto en el que abrir el servidor
  @param handler: Rutina de atencion de los mensajes
  @param more: Parametros adicionales que se necesiten en la rutina de atencion
  @return SERVOK en caso de que el servidor termine correctamente
          un numero negativo en caso de error
*/
int server_launch(uint16_t port, void*(*handler)(void*), void* more) {
	int socketd;
	int set_size=1, i=0;
	tcpsocket_args args;
	char* data;
	size_t len;
    pthread_t t;
    conn_data* thread_data;
    struct timeval tv;
    /* Control de errores */
    if(port==0) {
        return SERVERR_ARGS;
    }

    /* Armar la señal */
    if(signal(SIGINT, sigint_handler)==SIG_ERR) {
        return SERVERR_SIGNAL;
    }

    /* Inicializacion del mutex */
	if(pthread_mutex_init(&mutex_conn, NULL)) {
        return SERVERR_PTHREAD; 
    }

    /* Abrir puerto del servidor */
	if(server_tcpsocket_open(port, &socketd) < 0) {
		return SERVERR_SOCKET;
	}

    /* Inicializacion de los conjuntos de descriptores de fichero */
	FD_ZERO(&connections);
    FD_ZERO(&blocked);
	FD_SET(socketd, &connections);
    loop=1;
	tv.tv_sec=3;
    tv.tv_usec=0;
    while(loop) {

        /* Se espera hasta que algun socket requiera atencion */
        readable = connections;
		if(select(FD_SETSIZE, &readable,NULL,NULL,&tv) < 0) {
            server_stop();
			return SERVERR_SELECT;
		}

		for(i=0; i < FD_SETSIZE; i++) {
			if(is_readable(i) && !connection_isblocked(i)) {

				/* Atencion a conexion entrante */
				if(i==socketd) {
					if(tcpsocket_accept(socketd,&args)) {
						return SERVERR_ACCEPT;
					}
                    strcpy(ips[args.acceptd], inet_ntoa(args.client.sin_addr));
					connection_add(args.acceptd);

				} 
				/* Atencion al resto de sockets */
				else {
                    thread_data = malloc(sizeof(conn_data));
                    if(thread_data==NULL) {
                        //liberar servidor
                        return SERVERR_MALLOC;
                    }
                    thread_data->msg = malloc(DATA_SIZE);
                    if(thread_data->msg == NULL) {
                        return SERVERR_MALLOC;
                    }
                    bzero(thread_data->msg,DATA_SIZE);
                    thread_data->socketd=i;

                    /* Se recibe el mensaje */
					switch(tcpsocket_rcv(i, thread_data->msg, DATA_SIZE, &thread_data->len)) {
						case TCPCONN_CLOSED:
							connection_rmv(i);
                            if(handler_disconnection) handler_disconnection(thread_data);
							tcpsocket_close(i);
							break;
						case TCPOK:
                            thread_data->more=more;

                            /* Se bloquea el socket y se lanza hilo de atencion al mensaje */
							connection_block(i);
                            if(pthread_create(&t, NULL, handler, thread_data)!=0) {
                                return SERVERR_PTHREAD;
                            }
							break;
					/*	case TCPERR_RECV:
							return SERVERR_RCV;*/
                        case TCPERR_ARGS:
                            return SERVERR_ARGS;
					}
				}
			}
		}
	}
    return 0;
}

/**
  @brief Para el servidor TCP
  @return SERVOK si el servidor se para, SERVERR_NRUN si no hay servidor
*/
int server_stop() {
    int i;
    if(!loop) {
        return SERVERR_NRUN;
    }
    for(i=0;i<FD_SETSIZE; i++) close(i); 
    pthread_mutex_destroy(&mutex_conn);
    return SERVOK;
}

/**
  @brief Para el servidor TCP
  @return SERVOK si el servidor se para, SERVERR_NRUN si no hay servidor
*/
int set_do_on_disconnect(void(*handler)(void*)) {
    handler_disconnection = handler;
    return SERVOK;
}
