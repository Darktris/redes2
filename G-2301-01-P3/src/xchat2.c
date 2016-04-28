/**
  @file xchat2.c
  @brief Programa principal del cliente IRC
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/04/19
  */
#include <redes2/ircxchat.h>
#include <G-2301-01-P2-client.h>
#include <G-2301-01-P2-ucomm.h>
#include <G-2301-01-P2-ccomm.h>
#include <G-2301-01-P1-tools.h>
#include <G-2301-01-P1-tcp.h>
#include <G-2301-01-P2-rtp.h>
#include <G-2301-01-P3-ssl.h>
#include <syslog.h>

#include<sys/socket.h>
#include<netdb.h>
#include<ifaddrs.h>
#include<stdlib.h>
#include<unistd.h>

#define DOWN pthread_mutex_lock
#define UP pthread_mutex_unlock
#define TOKEN 1

/* Variables globales */
int socketd_client;
int socket_audio;
int flag=1;
int connected=0;
int timer=3;
int receiving = 1;
int playing = -1;

long port_dest;
char host_dest[NI_MAXHOST];
pthread_mutex_t mutexsnd;
pthread_mutex_t mutexrcv;
pthread_mutex_t maudio1;
pthread_mutex_t maudio2;
char buffrcv[2000];
char buffsnd[2000];
char host[NI_MAXHOST];
pthread_t t;
boolean ssl;

/**
  @brief Devuelve el nick del usuario. Requiere liberar memoria
  @return el nick
*/
char* get_unick() {
    char *mynick, *myuser, *myrealn, *pass, *myserver;
    char *nick, *user, *host, *server;
    int port, ssl;
    IRCInterface_GetMyUserInfo(&mynick, &myuser, &myrealn, NULL, &myserver, &port, &ssl);
    if(myuser) free(myuser);
    if(myrealn) free(myrealn);
    if(myserver) free(myserver);
    return mynick;
}

/**
  @brief Configura el host destino de la comunicacion de audio
  @param c: IP destino de la comunicacion
*/
void set_audio_host(char* c) {
    strcpy(host_dest, c);
}

/**
  @brief Configura el puerto destino de la comunicacion de audio
  @param c: puerto destino
*/
void set_audio_port(unsigned long p) {
    port_dest = p;
}

/**
  @brief Desbloquea el audio
*/
void unlock_audio() {
    UP(&maudio2);
}

/**
  @brief Devuelve la IP propia de la interfaz
  @return el host
*/
char* get_uhost() {
    FILE *f;
    char line[100] , *p , *c;
    int fm = AF_INET;
    struct ifaddrs *ifaddr, *ifa;
    int family , s;

    f = fopen("/proc/net/route" , "r");

    while(fgets(line , 100 , f)){
        p = strtok(line , " \t");
        c = strtok(NULL , " \t");

        if(p!=NULL && c!=NULL){
            if(strcmp(c , "00000000") == 0){
                printf("Default interface is : %s \n" , p);
                break;
            }
        }
    }
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL){
            continue;
        }
        family = ifa->ifa_addr->sa_family;
        if(strcmp( ifa->ifa_name , p) == 0) {
            if (family == fm) {
                s = getnameinfo( ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) , host , NI_MAXHOST , NULL , 0 , NI_NUMERICHOST);
                if (s != 0) {
                    printf("getnameinfo() failed: %s\n", gai_strerror(s));
                }
                printf("address: %s", host);
                return host;
            }
            printf("\n");
        }
    }
    freeifaddrs(ifaddr);
    return 0;
}


/**
  @brief Envia el comando del cliente. Es segura para concurrencia
  @param msg El mensaje IRC
  @return Ningun valor concreto
*/
int _client_socketsnd(char * msg) {
    DOWN(&mutexsnd);
    if(ssl) enviar_datos_SSL(socketd_client, msg, strlen(msg));
    else tcpsocket_snd(socketd_client, msg, strlen(msg));
    UP(&mutexsnd);
    syslog(LOG_INFO, "Sending: %s", msg);
}

/**
  @brief Recibe el comando en msg
  @param msg El mensaje IRC
  @param size El tamaño maximo de recepcion
  @return Ningun valor concreto
*/
int _client_socketrcv(char* msg, size_t size) {
    size_t len=0;
    DOWN(&mutexrcv);
    if(ssl) recibir_datos_SSL(socketd_client, msg, size, (int*) &len);
    else tcpsocket_rcv(socketd_client, msg, size, &len);
    UP(&mutexrcv);
    //syslog(LOG_INFO, "Receiving: %s", msg);
}

/**
  @brief Envia el comando del cliente. Es segura para concurrencia
  @param msg El mensaje IRC
  @return Ningun valor concreto
*/
int client_socketsnd(char *msg) {
    if(strlen(msg) > 2) IRCInterface_PlaneRegisterOutMessage(msg);
    _client_socketsnd(msg);
}

/**
  @brief Envia el comando del cliente. Es segura para concurrencia y es la version para ser llamada desde hilos
  @param msg El mensaje IRC
  @return Ningun valor concreto
*/
int client_socketsnd_thread(char *msg) {
    if(strlen(msg) > 2) IRCInterface_PlaneRegisterOutMessageThread(msg);
    _client_socketsnd(msg);
}

/**
  @brief Recibe el comando en msg
  @param msg El mensaje IRC
  @param size El tamaño maximo de recepcion
  @return Ningun valor concreto
*/
int client_socketrcv(char* msg, size_t size) {
    _client_socketrcv(msg, size); 
    msg[size-1]=0;
    timer=3;
    if(strlen(msg) > 2) IRCInterface_PlaneRegisterInMessage (msg);
}

/**
  @brief Recibe el comando en msg
  @param msg El mensaje IRC
  @param size El tamaño maximo de recepcion
  @return Ningun valor concreto
*/
int client_socketrcv_thread(char* msg, size_t size) {
    _client_socketrcv(msg, size);
    msg[size-1]=0;
    timer=3;
    printf("rcv[%d]: %s", (int) strlen(msg), msg);
}
/** 
 * \defgroup IRCInterfaceCallbacks Callbaks del interfaz
 *
 */

/** 
 * \addtogroup IRCInterfaceCallbacks
 * Funciones que van a ser llamadas desde el interface y que deben ser implementadas por el usuario.
 * Todas estas funciones pertenecen al hilo del interfaz.
 *
 * El programador puede, por supuesto, separar todas estas funciones en múltiples ficheros a
 * efectos de desarrollo y modularización.
 *
 * <hr>
 */

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ActivateProtectTopic IRCInterface_ActivateProtectTopic
 *
 * @brief Llamada por el botón de activación de la protección de tópico.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ActivateProtectTopic (char * channel)
 * 
 * @description 
 * Llamada por el botón de activación de la protección de tópico.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_ActivateProtectTopic(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+t", NULL);
    client_socketsnd(comm);
    free(comm);
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DeactivateProtectTopic IRCInterface_DeactivateProtectTopic
 *
 * @brief Llamada por el botón de desactivación de la protección de tópico.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DeactivateProtectTopic (char * channel)
 * 
 * @description 
 * Llamada por el botón de desactivación de la protección de tópico.
 * 
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_DeactivateProtectTopic(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-t", NULL);
    client_socketsnd(comm);
    free(comm);
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ActivateExternalMessages IRCInterface_ActivateExternalMessages
 *
 * @brief Llamada por el botón de activación de la recepción de mensajes externos.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ActivateExternalMessages (char * channel)
 * 
 * @description 
 * Llamada por el botón de activación de la recepción de mensajes externos.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_ActivateExternalMessages(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+n", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DeactivateExternalMessages IRCInterface_DeactivateExternalMessages
 *
 * @brief Llamada por el botón de desactivación de la recepción de mensajes externos.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DeactivateExternalMessages (char * channel)
 * 
 * @description 
 * Llamada por el botón de desactivación de la recepción de mensajes externos.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_DeactivateExternalMessages(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-n", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ActivateSecret IRCInterface_ActivateSecret
 *
 * @brief Llamada por el botón de activación de canal secreto.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ActivateSecret (char * channel)
 * 
 * @description 
 * Llamada por el botón de activación de canal secreto.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_ActivateSecret(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+s", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DeactivateSecret IRCInterface_DeactivateSecret
 *
 * @brief Llamada por el botón de desactivación de canal secreto.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DeactivateSecret (char * channel)
 * 
 * @description 
 * Llamada por el botón de desactivación de canal secreto.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_DeactivateSecret(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-s", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ActivateInvite IRCInterface_ActivateInvite
 *
 * @brief Llamada por el botón de activación de canal de sólo invitación.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ActivateInvite (char * channel)
 * 
 * @description 
 * Llamada por el botón de activación de canal de sólo invitación.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_ActivateInvite(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+i", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DeactivateInvite IRCInterface_DeactivateInvite
 *
 * @brief Llamada por el botón de desactivación de canal de sólo invitación.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DeactivateInvite (char * channel)
 * 
 * @description 
 * Llamada por el botón de desactivación de canal de sólo invitación.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_DeactivateInvite(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-i", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ActivatePrivate IRCInterface_ActivatePrivate
 *
 * @brief Llamada por el botón de activación del modo privado.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ActivatePrivate (char * channel)
 * 
 * @description 
 * Llamada por el botón de activación del modo privado.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_ActivatePrivate(char * channel)
{
    char *comm;
    IRCInterface_WriteChannel(channel, "AVISO", "En algunos servidores el modo +p descrito en el RFC1459 se considera obsoleto y puede que no sea detectado");
    IRCMsg_Mode (&comm, NULL, channel, "+p", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DeactivatePrivate IRCInterface_DeactivatePrivate
 *
 * @brief Llamada por el botón de desactivación del modo privado.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DeactivatePrivate (char * channel)
 * 
 * @description 
 * Llamada por el botón de desactivación del modo privado.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_DeactivatePrivate(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-p", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ActivateModerated IRCInterface_ActivateModerated
 *
 * @brief Llamada por el botón de activación de la moderación del canal.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ActivateModerated (char * channel)
 * 
 * @description 
 * Llamada por el botón de activación de la moderación del canal.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_ActivateModerated(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+m", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DeactivateModerated IRCInterface_DeactivateModerated
 *
 * @brief Llamada por el botón de desactivación  de la moderación del canal.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DeactivateModerated (char * channel)
 * 
 * @description 
 * Llamada por el botón de desactivación  de la moderación del canal.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_DeactivateModerated(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-m", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ActivateChannelKey IRCInterface_ActivateChannelKey
 *
 * @brief Llamada por el botón de activación de la clave del canal.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ActivateChannelKey (char * channel, char * key)
 * 
 * @description 
 * Llamada por el botón de activación de la clave del canal. El segundo parámetro es
 * la clave del canal que se desea poner. Si es NULL deberá impedirse la activación
 * con la función implementada a tal efecto.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_ActivateChannelKey(char * channel, char *key)
{  
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+k", key);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DeactivateChannelKey IRCInterface_DeactivateChannelKey
 *
 * @brief Llamada por el botón de desactivación de la clave del canal.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DeactivateChannelKey (char * channel)
 * 
 * @description 
 * Llamada por el botón de desactivación de la clave del canal.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_DeactivateChannelKey(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-k", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ActivateNicksLimit IRCInterface_ActivateNicksLimit
 *
 * @brief Llamada por el botón de activación del límite de usuarios en el canal.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ActivateNicksLimit (char * channel, int * limit)
 * 
 * @description 
 * Llamada por el botón de activación del límite de usuarios en el canal. El segundo es el
 * límite de usuarios que se desea poner. Si el valor es 0 se sobrentiende que se desea eliminar
 * este límite.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_ActivateNicksLimit(char * channel, int limit)
{
    char *comm;
    char l[200];
    sprintf(l, "%d", limit);
    IRCMsg_Mode (&comm, NULL, channel, "+l", l);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DeactivateNicksLimit IRCInterface_DeactivateNicksLimit
 *
 * @brief Llamada por el botón de desactivación de la protección de tópico.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DeactivateNicksLimit (char * channel)
 * 
 * @description 
 * Llamada por el botón de desactivación  del límite de usuarios en el canal.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */
void IRCInterface_DeactivateNicksLimit(char * channel)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-l", NULL);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_NewTopicEnter IRCInterface_NewTopicEnter
 *
 * @brief Llamada cuando se pulsa la tecla ENTER en el campo de tópico.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_NewTopicEnter (char * topicdata)
 * 
 * @description 
 * Llamada cuando se pulsa la tecla ENTER en el campo de tópico.
 * Deberá intentarse cambiar el tópico del canal.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_NewTopicEnter(char *topicdata)
{
    char *comm;
    IRCMsg_Topic (&comm, NULL, IRCInterface_ActiveChannelName(), topicdata);
    client_socketsnd(comm);
    free(comm);

}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_NewCommandText IRCInterface_NewCommandText
 *
 * @brief Llamada la tecla ENTER en el campo de texto y comandos.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_NewCommandText (char * command)
 * 
 * @description 
 * Llamada de la tecla ENTER en el campo de texto y comandos. El texto deberá ser
 * enviado y el comando procesado por las funciones de "parseo" de comandos de
 * usuario.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_NewCommandText(char *command)
{
    long ret;
    char *comm; 
    ret = IRCUser_CommandQuery (command);
    syslog(LOG_INFO, "Command text: %s", command);
    if(ret == IRCERR_NOUSERCOMMAND) {
        syslog(LOG_INFO, "Command text: MSG");
        IRCInterface_WriteChannel(IRCInterface_ActiveChannelName(), get_unick(), command);   
        IRCMsg_Privmsg(&comm, NULL, IRCInterface_ActiveChannelName(), command);
        client_socketsnd(comm);
        free(comm);
    } else if(ret < 0) {
        //ERROR
        syslog(LOG_INFO, "Command text: ERROR");
    } else {
        ucommands[ret](command);
        syslog(LOG_INFO, "Command text: COMM");
    }
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_GiveOp IRCInterface_GiveOp
 *
 * @brief Llamada por el botón "Op".
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_GiveOp (char * channel, char *nick)
 * 
 * @description 
 * Llamada por el botón "Op". Previamente debe seleccionarse un nick del
 * canal para darle "op" a dicho usuario.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_GiveOp(char *channel, char *nick)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+o", nick);
    client_socketsnd(comm);
    free(comm);
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_TakeOp IRCInterface_TakeOp
 *
 * @brief Llamada por el botón "Quitar Op". 
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_TakeOp (char *channel, char *nick)
 * 
 * @description 
 * Llamada por el botón "Quitar Op". Previamente debe seleccionarse un nick del
 * canal para quitarle "op" a dicho usuario.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_TakeOp(char *channel, char *nick)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-o", nick);
    client_socketsnd(comm);
    free(comm);
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_GiveVoice IRCInterface_GiveVoice
 *
 * @brief Llamada por el botón "Dar voz".
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_GiveVoice (char * channel, char *nick)
 * 
 * @description 
 * Llamada por el botón "Dar voz". Previamente debe seleccionarse un nick del
 * canal para darle voz a dicho usuario.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_GiveVoice(char *channel, char *nick)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+v", nick);
    client_socketsnd(comm);
    free(comm);
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_TakeVoice IRCInterface_TakeVoice
 *
 * @brief Llamada por el botón "Quitar voz". 
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_TakeVoice (char * channel, char *nick)
 * 
 * @description 
 * Llamada por el botón "Quitar voz". Previamente debe seleccionarse un nick del
 * canal para darle voz a dicho usuario.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_TakeVoice(char *channel, char *nick)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "-v", nick);
    client_socketsnd(comm);
    free(comm);


}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_BanNick IRCInterface_BanNick
 *
 * @brief Llamada por el botón "Banear".
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_BanNick (char * channel, char *nick)
 * 
 * @description 
 * Llamada por el botón "Banear". Previamente debe seleccionarse un nick del
 * canal para darle voz a dicho usuario.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

void IRCInterface_BanNick(char *channel, char *nick)
{
    char *comm;
    IRCMsg_Mode (&comm, NULL, channel, "+b", nick);
    client_socketsnd(comm);
    free(comm);


}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_KickNick IRCInterface_KickNick
 *
 * @brief Llamada por el botón "Echar".
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_KickNick (char * channel, char *nick)
 * 
 * @description 
 * Llamada por el botón "Echar". Previamente debe seleccionarse un nick del
 * canal para darle voz a dicho usuario.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * No devuelve ningún valor ni código de error.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */
void IRCInterface_KickNick(char *channel, char *nick)
{
    char *comm;
    IRCMsg_Kick(&comm, NULL, channel, nick, "Kicked");
    client_socketsnd(comm);
    free(comm);
}

typedef struct {
    int sockfd;
    char* data;
    unsigned long l;
} _thread_file;


/**
  @brief El hilo del envio de fichero
  @param d: argumentos del hilo
  @return NULL
*/
void* fileThread(void* d) {
    tcpsocket_args args={0};
    _thread_file* s = (_thread_file*) d;

    printf("Waiting for connection\n");
    tcpsocket_accept(s->sockfd,&args);
    printf("Sending\n");
    tcpsocket_snd(args.acceptd, s->data, s->l);

    printf("End of connection\n");
    close(s->sockfd);
    free(s);
    return NULL;
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_SendFile IRCInterface_SendFile
 *
 * @brief Llamada por el botón "Enviar Archivo".
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_SendFile (char * filename, char *nick, char *data, long unsigned int length)
 * 
 * @description 
 * Llamada por el botón "Enviar Archivo". Previamente debe seleccionarse un nick del
 * canal para darle voz a dicho usuario. Esta función como todos los demás callbacks bloquea el interface
 * y por tanto es el programador el que debe determinar si crea un nuevo hilo para enviar el archivo o
 * no lo hace.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * Devuelve TRUE si se ha establecido la comunicación y FALSE en caso contrario.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */
boolean IRCInterface_SendFile(char *filename, char *nick, char *data, long unsigned int length)
{
    char comm[512];
    pthread_t t2;
    struct sockaddr_in my_addr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    listen(sockfd, 1); // se pone a la escucha el socket, máximo 1 cliente
    socklen_t slen = sizeof(my_addr);
    getsockname(sockfd, (struct sockaddr*)&my_addr, &slen);
    printf("puerto asignado: %d\n", ntohs(my_addr.sin_port));

    _thread_file* news = malloc(sizeof(_thread_file));
    news->sockfd = sockfd;
    news->data = data;
    news->l = length;
    pthread_create(&t2, NULL, fileThread, (void*) news);



    sprintf(comm, "NOTICE %s :%cFSEND %s %s %s %d %lu\r\n", nick, TOKEN, get_unick(), filename, get_uhost(), ntohs(my_addr.sin_port), length);
    printf("%s", comm);
    client_socketsnd(comm);

    return TRUE;

}


/**
  @brief Graba y envia audio para la funcionalidad de chat de voz
  @param d: Nada
  @return NULL
*/
void* audiosnd_t(void* d) {
    rtpargs_t rargs;
    rargs.pt = IRCSound_RecordFormat(PA_SAMPLE_S16BE, 2);

    DOWN(&maudio1);
    DOWN(&maudio2);
    UP(&maudio2);
    UP(&maudio1);
    while(flag) {
        //printf("Sending %s %p\n", host_dest, port_dest);
        if(playing) {
          rtp_sndpkg(socket_audio, host_dest, port_dest, rargs, buffsnd, 900);
          IRCSound_RecordSound(buffsnd, 900); //8000KB/s * 20 ms = 160B
        }
    }
}

/**
  @brief Recibe y reproduce audio para la funcionalidad de chat de voz
  @param d: Nada
  @return NULL
*/
void* audiorcv_t(void* d) {
    rtpargs_t rargs;
    size_t len;

    IRCSound_PlayFormat(PA_SAMPLE_S16BE,2);
    DOWN(&maudio1);
    DOWN(&maudio2);
    UP(&maudio2);
    UP(&maudio1);
    while(flag) {
        if(playing) {
          rtp_rcvpkg(socket_audio, host_dest, port_dest, &rargs, buffrcv, &len);
          //printf("Received %s %p\n", host_dest, port_dest);
          IRCSound_PlaySound(buffrcv, len); //8000KB/s * 20 ms = 160B
        }
    }
}


/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_StartAudioChat IRCInterface_StartAudioChat
 *
 * @brief Llamada por el botón "Iniciar" del diálogo de chat de voz.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_StartAudioChat (char *nick)
 * 
 * @description 
 * Llamada por el botón "Iniciar" del diálogo de chat de voz. Previamente debe seleccionarse un nick del
 * canal para darle voz a dicho usuario. Esta función como todos los demás callbacks bloquea el interface
 * y por tanto para mantener la funcionalidad del chat de voz es imprescindible crear un hilo a efectos
 * de comunicación de voz.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * Devuelve TRUE si se ha establecido la comunicación y FALSE en caso contrario.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */
boolean IRCInterface_StartAudioChat(char *nick)
{
    struct sockaddr_in add;
    struct sockaddr_in my_addr;
    char comm[512];
    pthread_t t;
    socklen_t slen = sizeof(my_addr);
    if(playing == 0) {playing = 1; return TRUE;}
    socket_audio = socket(AF_INET, SOCK_DGRAM, 0);

    add.sin_family = AF_INET;
    add.sin_port = 0;
    add.sin_addr.s_addr = INADDR_ANY;
    bzero(&add.sin_zero, 8);

    
    bind(socket_audio, (struct sockaddr *)&add, sizeof(add));
    getsockname(socket_audio, (struct sockaddr*)&my_addr, &slen);
    printf("puerto asignado: %d\n", htons(my_addr.sin_port));

    sprintf(comm, "NOTICE %s :%cAUDIOCHAT %s %s %d\r\n", nick, TOKEN, get_unick(), get_uhost(), htons(my_addr.sin_port)); 

    client_socketsnd(comm);

    UP(&maudio1);

    playing = 1;

    pthread_create(&t, NULL, audiosnd_t, NULL);
    pthread_create(&t, NULL, audiorcv_t, NULL);

    return TRUE;
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_StopAudioChat IRCInterface_StopAudioChat
 *
 * @brief Llamada por el botón "Parar" del diálogo de chat de voz.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_StopAudioChat (char *nick)
 * 
 * @description 
 * Llamada por el botón "Parar" del diálogo de chat de voz. Previamente debe seleccionarse un nick del
 * canal para darle voz a dicho usuario. Esta función sólo para la comunicación que puede ser reiniciada. 
 * Evidentemente tiene que actuar sobre el hilo de chat de voz.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * Devuelve TRUE si se ha parado la comunicación y FALSE en caso contrario.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

boolean IRCInterface_StopAudioChat(char *nick)
{
  playing = 0;
  return TRUE;
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_ExitAudioChat IRCInterface_ExitAudioChat
 *
 * @brief Llamada por el botón "Cancelar" del diálogo de chat de voz.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_ExitAudioChat (char *nick)
 * 
 * @description 
 * Llamada por el botón "Parar" del diálogo de chat de voz. Previamente debe seleccionarse un nick del
 * canal para darle voz a dicho usuario. Esta función cierrala comunicación. Evidentemente tiene que
 * actuar sobre el hilo de chat de voz.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * Devuelve TRUE si se ha cerrado la comunicación y FALSE en caso contrario.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */
boolean IRCInterface_ExitAudioChat(char *nick)
{
    flag=0;
    playing = -1;
    //DOWN(&maudio1);
    //DOWN(&maudio2);
   
    return TRUE;
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_DisconnectServer IRCInterface_DisconnectServer
 *
 * @brief Llamada por los distintos botones de desconexión.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_DisconnectServer (char * server, int port)
 * 
 * @description 
 * Llamada por los distintos botones de desconexión. Debe cerrar la conexión con el servidor.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * Devuelve TRUE si se ha cerrado la conexión y FALSE en caso contrario.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

boolean IRCInterface_DisconnectServer(char *server, int port)
{
    client_socketsnd("QUIT\r\n");

    disconnect_client();
    return TRUE;
}

/**
 * \ingroup IRCInterfaceCallbacks
 *
 * @page IRCInterface_Connect IRCInterface_Connect
 *
 * @brief Llamada por los distintos botones de conexión.
 *
 * @synopsis
 *	#include <redes2/ircxchat.h>
 *
 * 	void IRCInterface_Connect (char *nick, char * user, char * realname, char * password, char * server, int port, boolean ssl)
 * 
 * @description 
 * Llamada por los distintos botones de conexión. Si implementará la comunicación completa, incluido
 * el registro del usuario en el servidor.
 *
 * En cualquier caso sólo se puede realizar si el servidor acepta la orden.
 *
 * Esta función debe ser implementada por el alumno.
 *
 * @return
 * Devuelve IRC_OK si todo ha sido correcto, IRCERR_NOSSL
 * si el valor de SSL es TRUE y no se puede activar la conexión SSL pero sí una conexión no protegida.
 * Devolverá IRCERR_NOCONNECT en caso de que no se pueda realizar la comunicación.
 *
 * @author
 * Eloy Anguiano (eloy.anguiano@uam.es)
 *
 *<hr>
 */

long IRCInterface_Connect(char *nick, char *user, char *realname, char *password, char *server, int port, boolean s)
{
    char* comm;
    if(!nick || !user || !realname || !server || port < 0) return IRCERR_NOCONNECT;
    ssl = s; 

    if(client_tcpsocket_open(port, &socketd_client, server) < 0) {
        return IRCERR_NOCONNECT;
    }


    if(ssl) {
        /* Handshake SSL */
        inicializar_nivel_SSL();
        if(fijar_contexto_SSL(FILE_CLIENT_CERTIFICATE, FILE_CLIENT_CERTIFICATE)<0) {
            printf("Error al inicializar el contexto\n");
            ERR_print_errors_fp(stderr);
            //return 0;
        }
        conectar_canal_seguro_SSL(socketd_client);
        if(evaluar_post_connectar_SSL(socketd_client)) {
            printf("Error del certificador\n");
            ERR_print_errors_fp(stderr);
        }

        ERR_print_errors_fp(stderr);
    }
    receiving = 1;
    pthread_mutex_init(&mutexsnd, NULL);
    pthread_mutex_init(&mutexrcv, NULL);
    UP(&mutexsnd);

    pthread_create(&t, NULL, rcv_thread, NULL);

    if(password && strlen(password) > 0) {
        IRCMsg_Pass(&comm, NULL, password);
        client_socketsnd(comm); 
        free(comm);
    }

    IRCMsg_Nick(&comm, NULL, nick, NULL);
    client_socketsnd(comm); 
    free(comm);

    IRCMsg_User(&comm, NULL, user, "1", realname);
    client_socketsnd(comm); 
    free(comm);

    UP(&mutexrcv);
    connected = 1;
    return IRC_OK;
}

/**
  @brief Recibe y atiende comandos IRC
  @param d: Nada
  @return NULL
*/
void* rcv_thread(void *d) {
    char *msg, *comm, *next, *command;
    long ret;
    msg = malloc(8192*sizeof(char));
    while(receiving) {
        client_socketrcv_thread(msg, 8191);
        next = IRC_UnPipelineCommands (msg, &command, NULL);
        do { 
            syslog(LOG_INFO,"%s", command);
            if(strlen(msg) > 2) IRCInterface_PlaneRegisterInMessageThread(command);
            ret = IRC_CommandQuery (command);
            switch(ret) {
                case IRCERR_NOCOMMAND:
                    syslog(LOG_INFO, "Not a valid IRC command");
                    break;
                case IRCERR_UNKNOWNCOMMAND:
                    cdefault(command);
                    break;
                default:
                    ccommands[ret](command);
            }
            if(command!=NULL) free(command); //??
            next = IRC_UnPipelineCommands(NULL, &command, next);
        } while(next!=NULL);
    }
}

/**
  @brief Desconecta el cliente
  @param d: Nada
  @return NULL
*/
void disconnect_client() {
    receiving = 0;
    tcpsocket_close(socketd_client);
    pthread_mutex_destroy(&mutexsnd);
    pthread_mutex_destroy(&mutexrcv);
    IRCInterface_RemoveAllChannels();
    IRCInterface_ChangeConectionSelected();
}

/**
  @brief Hilo de timeout
  @param d: Nada
  @return NULL
*/
void* timeout_t(void * a) {
    while(1) {
        if(connected) {
            if(timer==1) {  
                disconnect_client();
            }
            if(timer==2) {
                client_socketsnd_thread("PING LAG1234567\r\n"); 
            }
            timer--;
        }
        sleep(20);
    }
}

/***************************************************************************************************/
/***************************************************************************************************/
/**                                                                                               **/
/** MMMMMMMMMM               MMMMM           AAAAAAA           IIIIIII NNNNNNNNNN          NNNNNN **/
/**  MMMMMMMMMM             MMMMM            AAAAAAAA           IIIII   NNNNNNNNNN          NNNN  **/
/**   MMMMM MMMM           MM MM            AAAAA   AA           III     NNNNN NNNN          NN   **/
/**   MMMMM  MMMM         MM  MM            AAAAA   AA           III     NNNNN  NNNN         NN   **/
/**   MMMMM   MMMM       MM   MM           AAAAA     AA          III     NNNNN   NNNN        NN   **/
/**   MMMMM    MMMM     MM    MM           AAAAA     AA          III     NNNNN    NNNN       NN   **/
/**   MMMMM     MMMM   MM     MM          AAAAA       AA         III     NNNNN     NNNN      NN   **/
/**   MMMMM      MMMM MM      MM          AAAAAAAAAAAAAA         III     NNNNN      NNNN     NN   **/
/**   MMMMM       MMMMM       MM         AAAAA         AA        III     NNNNN       NNNN    NN   **/
/**   MMMMM        MMM        MM         AAAAA         AA        III     NNNNN        NNNN   NN   **/
/**   MMMMM                   MM        AAAAA           AA       III     NNNNN         NNNN  NN   **/
/**   MMMMM                   MM        AAAAA           AA       III     NNNNN          NNNN NN   **/
/**  MMMMMMM                 MMMM     AAAAAA            AAAA    IIIII   NNNNNN           NNNNNNN  **/
/** MMMMMMMMM               MMMMMM  AAAAAAAA           AAAAAA  IIIIIII NNNNNNN            NNNNNNN **/
/**                                                                                               **/
/***************************************************************************************************/
/***************************************************************************************************/


/**
  @brief: Funcion principal del programa 
  @param argc: numero de argumentos
  @param argv: parametros
  @return 0
*/
int main (int argc, char *argv[])
{
    pthread_t t, tt;

#ifdef NDEBUG
    close(0);
    close(1);
    close(2);
#endif
    
    IRCSound_OpenRecord();
    IRCSound_OpenPlay();
    pthread_mutex_init(&maudio1, NULL);
    pthread_mutex_init(&maudio2, NULL);
    DOWN(&mutexrcv);
    DOWN(&mutexsnd);

    DOWN(&maudio1);
    DOWN(&maudio2);

    init_ucomm();
    init_ccomm();


    pthread_create(&t, NULL, timeout_t, NULL);

    /* La función IRCInterface_Run debe ser llamada al final      */
    /* del main y es la que activa el interfaz gráfico quedándose */
    /* en esta función hasta que se pulsa alguna salida del       */
    /* interfaz gráfico.                                          */
    IRCInterface_Run(argc, argv);

    return 0;
}
