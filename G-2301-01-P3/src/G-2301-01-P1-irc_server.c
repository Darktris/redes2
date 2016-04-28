/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-irc_server.c
  @brief Servidor IRC
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/02/10
  */
#include "G-2301-01-P1-server.h"
#include <G-2301-01-P3-ssl-server.h>
#include "G-2301-01-P1-irc_server.h"
#include <G-2301-01-P1-irc.h>
#include <G-2301-01-P1-tools.h>
#include <G-2301-01-P1-daemon.h>
#include <G-2301-01-P3-ssl.h>
#include <redes2/irc.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
typedef int(*comm_t)(char*, void*);
int s_ssl;
comm_t commands[NCOMMANDS];

char** users;
char** nicks;
char* timeout;

char running=1;
char path_motd[256]="/tmp/irc_tmp";
pthread_t t_timeout;
pthread_mutex_t m_users;
pthread_mutex_t m_nicks;
pthread_mutex_t m_timeout;

void repair_command(char* command) {
    char* i=command;
    while(*i!='\r'&&*(i+1)!='\n') i++;
    i+=2;
    *i='\0';
}
#define tcpsocket_snd __ssl_bridge_snd
int __ssl_bridge_snd(int socketd, char* buf, size_t len) {
    if(s_ssl) enviar_datos_SSL(socketd, buf, len);
#undef tcpsocket_snd
    else tcpsocket_snd(socketd, buf, len);
#define tcpsocket_snd __ssl_bridge_snd
}
/**
  @brief Devuelve el path del MOTD
  @return Dicho path al fichero
  */
char* get_motd_path() {
    return path_motd;
}
/**
  @brief Asocia a un socketd el usuario
  @param socketd: Socket del usuario
  @param user: Nombre del usuario
  @return IRCSVROK en caso adecuado, IRCSVERR (<0) en otro caso
  */
int set_user(int socketd, char* user) {
    pthread_mutex_lock(&m_users);
    if(user==NULL) {
        if(users[socketd]) free(users[socketd]);  
        users[socketd]=NULL;
        pthread_mutex_unlock(&m_users);
        return IRCSVROK;
    } 
    if(strlen(user)>MAX_USERNAME) {
        pthread_mutex_unlock(&m_users);
        return IRCSVRERR_MAXLEN;
    }
    if(users[socketd]==NULL) {
        users[socketd]=malloc(sizeof(MAX_USERNAME));
        if(users[socketd]==NULL) {
            pthread_mutex_unlock(&m_users);
            return IRCSVRERR_MALLOC;
        } 
    }
    syslog(LOG_INFO,"set_user: socketd=%d user=%s", socketd, user);
    strcpy(users[socketd], user);
    pthread_mutex_unlock(&m_users);
    return IRCSVROK;
}

/**
  @brief Asocia a un socketd el nick
  @param socketd: Socket del usuario
  @param user: Nick del usuario
  @return IRCSVROK en caso adecuado, IRCSVERR (<0) en otro caso
*/
int set_nick(int socketd, char* nick) {
    pthread_mutex_lock(&m_nicks);
    if(nick==NULL) {
        if(nicks[socketd]) free(nicks[socketd]);
        nicks[socketd]=NULL;
        pthread_mutex_unlock(&m_nicks);
        return IRCSVROK; 
    }

    if(strlen(nick)>MAX_NICK) {
        pthread_mutex_unlock(&m_nicks);
        return IRCSVRERR_MAXLEN;
    }
    if(nicks[socketd]==NULL) {
        nicks[socketd]=malloc(sizeof(MAX_NICK)+1);
        if(nicks[socketd]==NULL) {
            pthread_mutex_unlock(&m_nicks);
            return IRCSVRERR_MALLOC;
        } 
    }
    pthread_mutex_unlock(&m_nicks);
    strcpy(nicks[socketd], nick);
    return IRCSVROK;
}

/**
  @brief Asocia a un socketd el nick
  @param socketd: Socket del usuario
  @param user: Nick del usuario
  @return IRCSVROK en caso adecuado, IRCSVERR (<0) en otro caso
*/
int get_socketd_byuser(char* user) {
    int i;
    if(user==NULL) return 0;
    pthread_mutex_lock(&m_users);
    /* Zona critica */
    syslog(LOG_INFO, "get_socketd=%s", user);
    for(i=0;i<MAX_USERS;i++) {
        if(users[i]!=NULL) {
            if(strcmp(user, users[i]) == 0) {
                pthread_mutex_unlock(&m_users);
                return i;
            }
        }
    }
    pthread_mutex_unlock(&m_users);
    return 0;

}

/**
  @brief Busca el socket de un usuario por nick
  @param nick: Nick del usuario
  @return el socket del usuario
*/
int get_socketd_bynick(char* nick) {
    int i;
    if(nick==NULL) return 0;
    pthread_mutex_lock(&m_nicks);
    syslog(LOG_INFO, "get_socketd=%s", nick);
    for(i=0;i<MAX_USERS;i++) {
        if(nicks[i]!=NULL) {
            if(strcmp(nick, nicks[i]) == 0) {
                pthread_mutex_unlock(&m_nicks);
                return i;
            }
        }
    }
    pthread_mutex_unlock(&m_nicks);
    return 0;

}

/**
  @brief Devuelve el nick de un usuario
  @param socketd: El socket del usuario
  @return El nick del usuario
*/
char* get_nick(int socketd) {
    char* ret;
    pthread_mutex_lock(&m_nicks);
    ret = nicks[socketd];
    pthread_mutex_unlock(&m_nicks);
    return ret;
}

/**
  @brief Devuelve el user de un usuario
  @param socketd: El socket del usuario
  @return El user del usuario
*/
char* get_user(int socketd) {
    char* ret;
    pthread_mutex_lock(&m_users);
    ret = users[socketd];
    pthread_mutex_unlock(&m_users);
    return ret;
}

/**
  @brief Actualiza el contador de timeout de un socketd
  @param socketd: El socket del usuario
  @return IRCSVROK
*/
int update_timeout(int socketd) {
    pthread_mutex_lock(&m_timeout);
    timeout[socketd]=0;
    pthread_mutex_unlock(&m_timeout);
    return IRCSVROK;
}
/**
  @brief Manejador de las conexiones
  @param data: Datos de la conexion y el mensaje TCP
  @return IRCSVR_OK
*/
void* handler(void* data) {
    conn_data* thread_data = (conn_data*) data;
    char* command="im not empty";
    char* next;
    pthread_detach(pthread_self());
    update_timeout(thread_data->socketd);
    syslog(LOG_INFO, "Mensaje: [%s], len=%lu",(char*) thread_data->msg, strlen(thread_data->msg));
    next = IRC_UnPipelineCommands (thread_data->msg, &command, NULL);
    repair_command(command);
    syslog(LOG_INFO, "unpipelined: %s, len=%lu", command, strlen(command));
    do { 
        repair_command(command);
        if(strlen(command)>1) {
            process_command(command, data);
        }
        next = IRC_UnPipelineCommands(NULL, &command, next);
    } while(next!=NULL);
    
    
    s_ssl?connection_unblock_SSL(thread_data->socketd):connection_unblock(thread_data->socketd);
    free(thread_data->msg);
    free(thread_data);
    return IRCSVROK;    
}

void do_on_disconnect(void* data) {
    conn_data* thread_data = (conn_data*) data;
    quit("QUIT\r\n", data);
}
/**
  @brief Inicializa las llamadas de atencion de los comandos
*/
int init_commands() {
    int i=0;
    for(i=0;i<NCOMMANDS;i++)
        commands[i]=no_command;
    commands[NICK]=nick;
    commands[USER]=user;
    commands[LIST]=list;
    commands[PING]=ping;
    commands[PONG]=pong;
    commands[JOIN]=join;
    commands[PRIVMSG]=privmsg;
    commands[PART]=part;
    commands[NAMES]=names;
    commands[TOPIC]=topic;
    commands[QUIT]=quit;
    commands[MOTD]=motd;
    commands[AWAY]=away;
    commands[WHOIS]=whois;
    commands[MODE]=mode;
    commands[KICK]=kick;
    commands[VERSION]=version;
    commands[TIME]=time_c;
    commands[NOTICE]=notice;
}

/**
  @brief Inicializa las estructuras
*/
int init_memspace() {
    users=malloc(sizeof(char*)*MAX_USERS);
    if(users==NULL) 
        return IRCSVRERR_MALLOC;
    nicks=malloc(sizeof(char*)*MAX_USERS);
    if(nicks==NULL) {
        free(users);
        return IRCSVRERR_MALLOC;
    }
    timeout=malloc(sizeof(char)*MAX_USERS);
    if(timeout==NULL) {
        free(users);
        free(nicks);
        return IRCSVRERR_MALLOC;
    }
    bzero(users, sizeof(char*)*MAX_USERS);
    bzero(nicks, sizeof(char*)*MAX_USERS);
    bzero(timeout, sizeof(char)*MAX_USERS);
    if(pthread_mutex_init(&m_users, NULL)) {
        free(users);
        free(nicks);
        free(timeout);
        return IRCSVRERR_MALLOC;
    }
    if(pthread_mutex_init(&m_nicks, NULL)) {
        free(users);
        free(nicks);
        free(timeout);
        pthread_mutex_destroy(&m_users);
        return IRCSVRERR_MALLOC;
    } 
    if(pthread_mutex_init(&m_users, NULL)) {
        free(users);
        free(nicks);
        free(timeout);
        pthread_mutex_destroy(&m_users);
        pthread_mutex_destroy(&m_nicks);
        return IRCSVRERR_MALLOC;
    }
    return IRCSVROK;
}

/**
  @brief Borra las estructuras auxiliares del servidor
*/
int free_memspace() {
    int i;
    for(i=0;i<MAX_USERS;i++) {
        if(users[i]) free(users[i]);
        if(nicks[i]) free(nicks[i]);
    }
    free(users);
    free(nicks);
    free(timeout);
    pthread_mutex_destroy(&m_timeout);
    pthread_mutex_destroy(&m_nicks);
    pthread_mutex_destroy(&m_nicks);
}

/**
  @brief Procesa un comando
  @param command: El comando
  @param data: Datos de las conexion
  @return IRCSVROK en caso adecuado, IRCSVERR (<0) en otro caso
*/
int process_command(char* command, void* data) {
    long ret;
    int i;
    syslog(LOG_INFO, "Command: [%s]", command);
    conn_data* d = (conn_data*) data;
    if(command==NULL) return -1;
    ret = IRC_CommandQuery (command);
    if(ret==IRCERR_NOCOMMAND||ret==IRCERR_UNKNOWNCOMMAND) {
        char *comm, type[12]={0};
        sscanf(command, "%s %*[^\r]\r\n", type);
        syslog(LOG_INFO, "No command: %s", command);
        IRCMsg_ErrUnKnownCommand (&comm, IRCSVR_NAME, get_nick(d->socketd), type);
        tcpsocket_snd(d->socketd, comm, strlen(comm));
        free(comm);

        syslog(LOG_INFO,"Unknown command: Go call Eloy");
        return -1;
    }

    return commands[ret](command, data);
}

/**
  @brief Hilo de desconexion por timeout
  @param data: NULL
  @return No devuelve ningun valor
*/
void* timeout_thread(void* data) {
    int i;
    conn_data d;
    char ping_msg[]="PING LAG1234567890\r\n";
    while(running) {
        pthread_mutex_lock(&m_timeout);
        
        for(i=0;i<MAX_USERS;i++) {
            if((timeout[i]==1)&&get_user(i)) {
                s_ssl?connection_block_SSL(i):connection_block(i);
                tcpsocket_snd(i, ping_msg, strlen(ping_msg));
                s_ssl?connection_unblock_SSL(i):connection_unblock(i);
            }

            if((timeout[i]==2)&&get_user(i)) { 
                d.socketd=i;
                quit("QUIT :Timeout\r\n", &d);
            }
            (timeout[i])++;
        }
        pthread_mutex_unlock(&m_timeout);
        sleep(IRCSVR_TIMEOUT);
    }
}

int read_channels() {
    FILE* f;
    char line[512], *p;
    char channel[20], mode[10], pass[20], topic[100];
    char *mode_c, *pass_c, *topic_c;
    int limit, i;
    char f_chan, f_pass, f_mode, f_topic;
 
    f = fopen(IRCSVR_CHANFILE, "r");
    if(!f) return 0;
    fgets(line, 511, f);
    line[511]=0;
    if(!(line[0]='%')) {
    }

    while(fgets(line, 511, f)) {
        line[511]=0;
        p = strtok(line," \t\n");
        i=0;
        topic[0]=0;
        f_chan = f_mode = f_pass = limit = 0;
        while(p) {
           if(i==0) if(sscanf(p, "%s", channel)==1) f_chan=1; 
           if(i==1) if(sscanf(p, "%s", mode)==1) f_mode=1; 
           if(i==2) if(sscanf(p, "%s", pass)==1) f_pass=1;
           if(i==3) limit = atoi(p);
           if(i==4) strcat(topic, p);
           i++; p = strtok(NULL, " \t\n");
        }
        f_topic = strlen(topic);
        if(!f_chan) continue;
        if(!f_mode) {mode_c = NULL;}else{mode_c = mode;} 
        if(!f_pass) {pass_c = NULL;}else{pass_c = pass;} 
        if(!f_topic) {topic_c = NULL;}else{topic_c = topic;} 
        if(!strcmp(pass_c, "%")) pass_c=NULL;
        if(!strcmp(topic_c, "%")) topic_c=NULL;
        IRCTADChan_Add(channel, mode_c, NULL, pass_c, limit, topic_c);
    }
}
/**
  @brief Llamada principal del servidor
  @param argc: Num de argumentos
  @param argv: Argumentos
  @return 0
*/
int main(int argc, char** argv) {
    int ret;
    char sh_comm[512];
    unsigned long port;
    if(argc!=3 && argc!=2) {
        printf("Use: %s <Port> [-ssl]", argv[0]);
        return 0;
    }

    if(sscanf(argv[1],"%lu", &port)!=1) {
        printf("Use: %s <Port> [-ssl]", argv[0]);
        return 0;
    }

    if(argc > 3 && strcmp(argv[2], "-ssl")==0) s_ssl=1;
    else s_ssl=0;

    s_ssl = 1;
    printf(COLOR_YELLOW "\t\tWelcome to %s\n" COLOR_RESET, IRCSVR_NAME);
    printf(COLOR_YELLOW "\tWe destroyed Alderaan due to a bug with QUIT\n" COLOR_RESET);
    init_commands();   
    
    printf(COLOR_GREEN "<<Setting up environment>>\n" COLOR_RESET);
    if(init_memspace()<0) {
        printf(COLOR_RED "Critical error initializing structures\n" COLOR_RESET);
        return -2;
    }
    set_do_on_disconnect_SSL(do_on_disconnect);
    read_channels();
    printf(COLOR_GREEN "<<Copying conf files in temporal files. Please be sure the directory /tmp/ exists>>\n" COLOR_RESET);
    if(fork()==0) {
        sprintf(sh_comm, "cp %s %s", IRCSVR_MOTDFILE, path_motd);
        system(sh_comm);
        return 0;
    }
    if(pthread_create(&t_timeout, NULL, timeout_thread, NULL)!=0) {
        printf(COLOR_RED "Critical error initializing structures\n" COLOR_RESET);
        return -2;
    }
    printf(COLOR_GREEN "<<Launching server in daemon mode>>\n" COLOR_RESET);
    sleep(2);
    //daemonize("G-2301-01-irc");
    ret = s_ssl? server_launch_SSL(port, handler, NULL):server_launch(port, handler, NULL);
    perror("ERROR");
    printf("Retorno del servidor: %d\n",ret);
    syslog(LOG_INFO, "Retorno del servidor: %d",ret);
    s_ssl?server_stop_SSL():server_stop();
    running = 0;
    free_memspace();
}
