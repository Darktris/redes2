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
void show_use(int argc, char** argv){
    printf("Use: %s host port\n", argv[0]);
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
        show_use(argc, argv);
        return 0;
    }

    if(sscanf(argv[2], "%lu", &port) != 1) {
        show_use(argc,argv);
        return 0;
    }

    puts("Inicializando nivel SSL");
    inicializar_nivel_SSL();
    puts("Fijando contexto SSL");
    if(fijar_contexto_SSL(FILE_CLIENT_CERTIFICATE, FILE_CLIENT_CERTIFICATE)<0) {
	printf("Error al inicializar el contexto\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    printf("Conectando a %s\n", argv[1]);
    if(client_tcpsocket_open(port, &socketd, argv[1])<0) {
        perror("Error al abrir la conexion");
    }
    puts("Iniciando handshake SSL");
    conectar_canal_seguro_SSL(socketd);
    if(evaluar_post_connectar_SSL(socketd)) {
        printf("Error del certificador\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    puts("Conexion satisfactoria. Iniciando shell de echo");
    ERR_print_errors_fp(stderr);
    while(1) {
        printf("> ");
        fgets(buf, 8192, stdin);
        enviar_datos_SSL(socketd, buf, strlen(buf));
        bzero(buf, 8192);
        switch(recibir_datos_SSL(socketd, buf, 8191, &len)) {
            case TCPOK:
                printf("< %s", buf);
                break;
            case TCPCONN_CLOSED:
                cerrar_canal_SSL(socketd);
                liberar_nivel_SSL();
                puts("Conexion cerrada");
                return 0;
            default:
                perror("Error en la recepcion");
        }
    }
}

