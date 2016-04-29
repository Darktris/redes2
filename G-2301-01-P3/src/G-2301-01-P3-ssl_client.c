/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P3-ssl_client.c
  @brief Cliente de echo SSL
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/04/28
*/

#include <stdio.h>
#include <G-2301-01-P1-tcp.h>
#include <G-2301-01-P3-ssl.h>

/**
  @brief Muestra el uso del programa
*/
void show_use(){
}
/**
  @brief Llamada principal del servidor
  @param argc: Num de argumentos
  @param argv: Argumentos
  @return 0
*/
int main(int argc, char** argv) {
    unsigned long port;
    int socketd;
    char buf[8192];
    int len;
    if(argc<3) {
        show_use();
        return 0;
    }

    if(sscanf(argv[1], "%lu", &port) != 1) {
        show_use();
        return 0;
    }


    inicializar_nivel_SSL();
    if(fijar_contexto_SSL(FILE_CLIENT_CERTIFICATE, FILE_CLIENT_CERTIFICATE)<0) {
	printf("Error al inicializar el contexto\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    client_tcpsocket_open(port, &socketd, argv[2]);
//    tcpsocket_snd(socketd, "dsasjddsj\nsakjdsjd\n", strlen("dsasjddsj\nsakjdsjd\n"));
    conectar_canal_seguro_SSL(socketd);
    if(evaluar_post_connectar_SSL(socketd)) {
     
	printf("Error del certificador\n");
        ERR_print_errors_fp(stderr);
    }
    
        ERR_print_errors_fp(stderr);
    while(1) {
        fgets(buf, 8192, stdin);
        enviar_datos_SSL(socketd, buf, strlen(buf));
        bzero(buf, 8192);
        switch(recibir_datos_SSL(socketd, buf, 8191, &len)) {
            case TCPOK:
                puts(buf);
                break;
            case TCPCONN_CLOSED:
                cerrar_canal_SSL(socketd);
                liberar_nivel_SSL();
                puts("Conexion cerrada");
                return 0;
            default:
                perror("Error en la recpecion");
        }
    }
}

