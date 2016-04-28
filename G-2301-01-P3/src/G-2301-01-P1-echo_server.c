/* vim: set ts=4 sw=4 et: */
#include "G-2301-01-P1-server.h"
#include <G-2301-01-P1-daemon.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
void* echo(void* data) {
	conn_data* thread_data = (conn_data*) data;
	if(pthread_detach(pthread_self())!=0) {
		perror("");
	}
	printf("Mensaje: %s\n",(char*) thread_data->msg);
	syslog(LOG_INFO, "Mensaje: %s",(char*) thread_data->msg);
	if(tcpsocket_snd(thread_data->socketd, thread_data->msg, thread_data->len)<0) {
		perror("");
	}
	connection_unblock(thread_data->socketd);
	free(thread_data->msg);
	free(thread_data);
	pthread_exit(0);
}

int main(int argc, char** argv) {
	int ret;
	if(argc!=2) return -1;
	daemonize("echo_server");
	ret = server_launch(atoi(argv[1]), echo, NULL);
	printf("Retorno del servidor: %d\n",ret);
	syslog(LOG_INFO, "Retorno del servidor: %d",ret);
}
