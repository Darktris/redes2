/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-server.c
  @brief Libreria de manejo de un servidor de sockets SSL
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
#include <G-2301-01-P3-ssl.h>
#include "G-2301-01-P3-ssl-server.h"

pthread_mutex_t mutex_conn;
fd_set connections, readable, blocked;
int loop;
char ips[FD_SETSIZE][18];
void(*handler_disconnection_SSL)(void*) = NULL;

/**
  @brief Añade una conexion al conjunto del select
  @param socketd: Descriptor del socket
  @return SERVOK
*/
int connection_add_SSL(int socketd) {
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
int connection_rmv_SSL(int socketd) {
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
int is_connected_SSL(int socketd) {
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
int is_readable_SSL(int socketd) {
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
int connection_block_SSL(int socketd) {
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
int connection_unblock_SSL(int socketd) {
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
int connection_isblocked_SSL(int socketd) {
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
char* get_ip_from_connection_SSL(int socketd) {
    return ips[socketd];
}


/**
  @brief Manejador de la señal 
  @param sig: señal recibido
  @return 0 si no esta bloqueada, otro valor si esta bloqueada
*/
void sigint_handler_SSL(int sig) {
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
int server_launch_SSL(uint16_t port, void*(*handler)(void*), void* more) {
	int socketd;
	int set_size=1, i=0;
	tcpsocket_args args={0};
	char* data;
	size_t len;
    pthread_t t;
    conn_data* thread_data;
    struct timeval tv;

    /* Control de errores */
    if(port==0) {
        return SERVERR_ARGS;
    }

    /* Ignoramos posibles malas escrituras en los sockets */
    signal(SIGPIPE, SIG_IGN);

    /* Inicializacion del mutex */
	if(pthread_mutex_init(&mutex_conn, NULL)) {
        return SERVERR_PTHREAD; 
    }

    /* Abrir puerto del servidor */
	if(server_tcpsocket_open(port, &socketd) < 0) {
		return SERVERR_SOCKET;
	}

    inicializar_nivel_SSL();
    if(fijar_contexto_SSL(FILE_SERVER_PKEY, FILE_SERVER_CERTIFICATE)<0) {
        ERR_print_errors_fp(stdout);
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
        tv.tv_sec=3;
        tv.tv_usec=0;
		/*if(select(FD_SETSIZE, &readable,NULL,NULL,&tv) < 0) {
            server_stop();
			return SERVERR_SELECT;
		}*/
		select(FD_SETSIZE, &readable,NULL,NULL,&tv);

		for(i=0; i < FD_SETSIZE; i++) {
			if(is_readable_SSL(i) && !connection_isblocked_SSL(i)) {

				/* Atencion a conexion entrante */
				if(i==socketd) {
					if(tcpsocket_accept(socketd,&args)) {
						return SERVERR_ACCEPT;
					}
                    if(aceptar_canal_seguro_SSL(args.acceptd)) {
                        perror("Error");
                        printf("Error al abrir el canal seguro\n");
                        ERR_print_errors_fp(stdout);
                    }
    if(evaluar_post_connectar_SSL(socketd)) {
     
	printf("Error del certificador\n");
        ERR_print_errors_fp(stderr);
    }
 
                    strcpy(ips[args.acceptd], inet_ntoa(args.client.sin_addr));
					connection_add_SSL(args.acceptd);

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
					switch(recibir_datos_SSL(i, thread_data->msg, DATA_SIZE,(int*) &thread_data->len)) {
						case TCPCONN_CLOSED:
							connection_rmv_SSL(i);
                            if(handler_disconnection_SSL) {
                                connection_block_SSL(i);
                                handler_disconnection_SSL(thread_data);

                            }
							tcpsocket_close(i);
							cerrar_canal_SSL(i);
                            connection_unblock_SSL(i);
                            connection_rmv_SSL(i);
							break;
						case TCPOK:
                            connection_block_SSL(i);
                            thread_data->more=more;

                            /* Se bloquea el socket y se lanza hilo de atencion al mensaje */
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
int server_stop_SSL() {
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
int set_do_on_disconnect_SSL(void(*handler)(void*)) {
    handler_disconnection_SSL = handler;
    return SERVOK;
}
