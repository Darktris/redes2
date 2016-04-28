/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-irc.c
  @brief Libreria de manejo de mensajes IRC 
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/02/10
  */
#include <G-2301-01-P1-irc.h>
#include <redes2/irc.h>
#include <syslog.h>
#include <G-2301-01-P1-server.h>
#include <G-2301-01-P1-tools.h>
#include "G-2301-01-P1-irc_server.h" 
#include <G-2301-01-P3-ssl.h>
extern int s_ssl;
#define tcpsocket_snd _ssl_bridge_snd
int _ssl_bridge_snd(int socketd, char* buf, int len) {
    if(s_ssl) enviar_datos_SSL(socketd, buf, len);
#undef tcpsocket_snd
    else tcpsocket_snd(socketd, buf, len);
#define tcpsocket_snd _ssl_bridge_snd
}

/**
  @brief Atiende el comando NICK
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int nick(char* command, void* more) {
    char* prefix, *nick, comm[512]={0}, *prefix2, *msg, *comm2;
    conn_data* data = (conn_data*) more;
    IRCParse_Nick (command,&prefix,&nick, &msg);

    /* Primer Nick */
    if(get_user(data->socketd)==NULL) {    
        set_nick(data->socketd, nick);
        if(nick) free(nick);
        if(prefix) free(prefix);
        if(msg) free(msg);
    }else {
        /* Cambio de nick */
        switch(IRCTADUser_SetNickByUser (nick, get_user(data->socketd))) {
            case IRCERR_INVALIDNICK:
                syslog(LOG_INFO, "nick: invalid nick");
                IRCMsg_ErrNickNameInUse (&comm2, IRCSVR_NAME, get_nick(data->socketd), nick);
                tcpsocket_snd(data->socketd, comm2, strlen(comm2));
                free(comm2);
                break;
            case IRC_OK:
                IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
                sprintf(comm, ":%s NICK :%s\r\n", prefix2, nick);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                set_nick(data->socketd, nick);
                if(prefix2) free(prefix2);
                break;
            default: 
                syslog(LOG_INFO, "nick: invalid user");
                break;
        }
        if(nick) free(nick);
        if(prefix) free(prefix);
        if(msg) free(msg);
    }
}

/**
  @brief Atiende el comando USER
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int user(char* command, void*more) {
    char* prefix, *user, *modehost, *server, *realname,  *comm=NULL, *nick;
    conn_data* data = (conn_data*) more;
    char *msg;
    nick = get_nick(data->socketd);
    IRCParse_User (command, &prefix, &user, &modehost, &server, &realname);
    if(get_user(data->socketd)) { /* Already reg. */
        IRCMsg_ErrAlreadyRegistred(&comm, IRCSVR_NAME, nick==NULL?"default_nick":nick);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        free(comm);
    } else {
        switch(IRCTADUser_Add(user, nick, realname, NULL, server, get_ip_from_connection(data->socketd))) {
            case IRC_OK:
                set_user(data->socketd,user);
                IRCMsg_RplWelcome (&comm,IRCSVR_NAME, nick,nick, user, server);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                if(comm) free(comm);
                motd("motd\r\n", more);
                syslog(LOG_INFO, "user: User successfully added user=%s",user);
                break;
            case IRCERR_USERUSED: 
                syslog(LOG_INFO, "user: user being used user=%s",user);
            case IRCERR_REALNAMEUSED:
                syslog(LOG_INFO, "user: realn being used");
            case IRCERR_NICKUSED:
                syslog(LOG_INFO, "user: invalid nick");
                IRCMsg_ErrNickNameInUse (&comm, IRCSVR_NAME, get_nick(data->socketd), nick);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                free(comm);
                break;
            default:
                IRCMsg_ErrUnavailResource (&comm, IRCSVR_NAME, nick, nick);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                free(comm);
        }
    }
    if(prefix) free(prefix);
    if(user) free(user);
    if(modehost) free(modehost);
    if(server) free(server);
    if(realname) free(realname);
}

/**
  @brief Atiende el comando LIST
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
  */
int list(char* command, void* more) {
    char* prefix, *channel, *target;
    char** list;
    long n, i, u, mode;
    char* topic;
    conn_data* data = (conn_data*) more;
    char comm[512], *comm2;
    time_t ts;
    IRCParse_List (command, &prefix, &channel, &target);
    IRCTADChan_GetList (&list, &n, NULL);
    /* Para cada canal */
    for(i=0;i<n;i++) {
        /* Modo busqueda de un canal en particular */
        if(channel!=NULL) {
            if(strcmp(channel,list[i])==0) {
                topic = IRCTADChan_GetTopic(channel, &ts);
                u = IRCTADChan_GetNumberOfUsers(channel);
                sprintf(comm, ":%s 322 %s %s %ld :%s\r\n", IRCSVR_NAME, get_nick(data->socketd), list[i],u, topic?topic:""); 
                tcpsocket_snd(data->socketd, comm, strlen(comm));
            }
        } else {
            /* Modo listado de todos los canales */
            mode = IRCTADChan_GetMode(list[i]);

            if(!(mode&IRCMODE_SECRET)) { /* Ocultar canales secretos */
                topic = IRCTADChan_GetTopic(list[i], &ts);
                u = IRCTADChan_GetNumberOfUsers(list[i]);
                sprintf(comm, ":%s 322 %s %s %ld :%s\r\n", IRCSVR_NAME, get_nick(data->socketd), list[i],u, topic?topic:""); 
                tcpsocket_snd(data->socketd, comm, strlen(comm));
            }
        }
    }

    IRCMsg_RplListEnd(&comm2, IRCSVR_NAME,get_nick(data->socketd));   
    tcpsocket_snd(data->socketd, comm2, strlen(comm2));
    if(comm2) free(comm2);
    if(prefix) free(prefix);
    if(channel) free(channel);
    if(target) free(target);

}
/**
  @brief Atiende el comando PING
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int ping(char* command, void* more) {
    conn_data* data = (conn_data*) more;
    char *msg, comm[512]={0}, *prefix, *server, *server2;
    IRCParse_Ping (command, &prefix, &server, &server2, &msg);
    sprintf(comm, ":%s PONG %s :%s\r\n", IRCSVR_NAME, IRCSVR_NAME,  server); 
    tcpsocket_snd(data->socketd, comm, strlen(comm));
    if(prefix) free(prefix);
    if(server) free(server);
    if(server2) free(server2);
}

/**
  @brief "Atiende" el comando PONG
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int pong(char* command, void* more) {
    return 0;
}

/**
  @brief Atiende el comando JOIN
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int join(char* command, void* more) {
    conn_data* data = (conn_data*) more;
    char* prefix, *prefix2, *channel, *key, *msg, *comm, *comm3;
    char* topic;
    char comm2[512], l[50]={0};
    long n,i, umode, cmode;
    char ** list;
    IRCParse_Join (command, &prefix, &channel, &key, &msg);
    IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
    if(channel==NULL) {
        syslog(LOG_INFO, "join: no channel");
        sprintf(comm2, ":%s 461 %s %s :Needed more parameters\r\n", IRCSVR_NAME, get_nick(data->socketd), "JOIN");
        syslog(LOG_INFO, "join: rply=%s",comm2);
        tcpsocket_snd(data->socketd, comm2 ,strlen(comm2));
        if(prefix) free(prefix);
        if(key) free(key);
        if(msg) free(msg);
    } else {
        switch(IRCTAD_JoinChannel(channel,get_user(data->socketd),"w", key)) {
            case IRCERR_NOVALIDUSER:
                syslog(LOG_INFO, "join: novaliduser");
                break;
            case IRCERR_NOVALIDCHANNEL:
                syslog(LOG_INFO, "join: novalidchannel");
                break;
            case IRCERR_USERSLIMITEXCEEDED:
                syslog(LOG_INFO, "join: usrlimit");
                IRCMsg_ErrChannelIsFull (&comm, IRCSVR_NAME, get_nick(data->socketd),channel);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                free(comm);
                syslog(LOG_INFO, "join: usrlimit");
                break;
            case IRCERR_NOENOUGHMEMORY:
                syslog(LOG_INFO, "join: nomem");
                break;
            case IRCERR_INVALIDCHANNELNAME:
                syslog(LOG_INFO, "join: invalidchannelname");
                break;
            case IRCERR_NAMEINUSE:
                syslog(LOG_INFO, "join: nameinuse");
                break;
            case IRCERR_BANEDUSERONCHANNEL:
                syslog(LOG_INFO, "join: banned");
                break;
            case IRCERR_NOINVITEDUSER:
                syslog(LOG_INFO, "join: noinviteuser");
                break;
            case IRCERR_FAIL:
                syslog(LOG_INFO, "join: passwd failed");
                IRCMsg_ErrBadChannelKey (&comm, prefix2, get_nick(data->socketd), channel);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                break;
            default:
                syslog(LOG_INFO, "join: unknown error but joining");
            case IRC_OK:
                /* Devolver mensaje Join con prefix el prefix del usuario */
                // prefijo complejo  + mensaje join + rpl_topic + rpl_namereply
                syslog(LOG_INFO, "join: joined successfully");
                IRCMsg_Join (&comm3, prefix2, NULL, NULL, channel);
                tcpsocket_snd(data->socketd, comm3, strlen(comm3));
                time_t t;
                topic = IRCTADChan_GetTopic(channel, &t);
                if (topic!=NULL) {
                    IRCMsg_RplTopic(&comm, prefix2,get_nick(data->socketd) , channel,topic);
                    tcpsocket_snd(data->socketd, comm, strlen(comm));
                    free(comm);
                }
                l[0]=0; 
                if(IRCTAD_ListUsersOnChannel (channel, &list, &n)!=IRCERR_NOVALIDCHANNEL) {
                    for(i=0;i<n;i++) {
                        umode = IRCTAD_GetUserModeOnChannel(channel, list[i]);
                        if((umode&IRCUMODE_OPERATOR)==IRCUMODE_OPERATOR) strcat(l, "@");
                        else if((umode&IRCUMODE_VOICE)==IRCUMODE_VOICE) strcat(l, "+");
                        strcat(l, IRCTADUser_GetNickByUser(list[i]));
                        strcat(l, " ");
                        
                    }
                } 
                if(strlen(l)) IRCMsg_RplNamReply (&comm, IRCSVR_NAME, get_nick(data->socketd), "=", channel, l);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                if(comm) free(comm);
                IRCMsg_RplEndOfNames (&comm, IRCSVR_NAME, get_nick(data->socketd), channel);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                if(comm3) free(comm3);
                if(comm) free(comm);
                if(prefix) free(prefix);
                if(key) free(key);
                if(msg) free(msg);
                if(channel) free(channel);
                if(prefix2) free(prefix2);
                break; 

        }
    }
}

/**
  @brief Atiende el comando PRIVMSG
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int privmsg(char* command, void* more) {
    conn_data* data = (conn_data*) more;
    char* prefix, *target, *msg, *prefix2, *comm, comm2[512];
    char* away;
    char** list;
    long n, i;
    int socketd;

    IRCParse_Privmsg (command, &prefix, &target, &msg);
    IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
    IRCMsg_Privmsg (&comm, prefix2,target,msg);
    if(target==NULL) {
        sprintf(comm2, ":%s 461 %s %s :Needed more parameters\r\n", IRCSVR_NAME, get_nick(data->socketd), "PRIVMSG");
        syslog(LOG_INFO, "join: rply=%s",comm2);
        tcpsocket_snd(data->socketd, comm2 ,strlen(comm2));
    } else {
        if(IRCTAD_ListUsersOnChannel (target, &list, &n)!=IRCERR_NOVALIDCHANNEL) {
            for(i=0;i<n;i++) {
                socketd = get_socketd_byuser(list[i]);
                if(socketd!=data->socketd) {
                    connection_block(socketd);
                    tcpsocket_snd(socketd, comm, strlen(comm));
                    connection_unblock(socketd);
                }
            }
        } else {
            if(get_socketd_bynick(target)!=0) {
                syslog(LOG_INFO,"privmsg: to user");
                away = IRCTAD_GetAway(target);
                if(away!=NULL) {
                    IRCMsg_RplAway(&comm, IRCSVR_NAME, get_nick(data->socketd), target, away);
                    tcpsocket_snd(data->socketd, comm, strlen(comm));
                    free(comm);
                }
                tcpsocket_snd(get_socketd_bynick(target), comm, strlen(comm));
            } else {
                syslog(LOG_INFO, "privmsg: no such nick");
                free(comm);
                IRCMsg_ErrNoSuchNick (&comm, prefix2, get_nick(data->socketd), target);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
            }
        }
    }
}
/**
  @brief Atiende el comando MODE
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
  */
int mode(char* command, void* more) {
    conn_data* data = (conn_data*) more;
    char* prefix, *channel, *mode, *user;
    char* prefix2, *comm, strmode[10]="+";
    long umode, cmode;
    IRCParse_Mode(command, &prefix, &channel, &mode, &user);
    syslog(LOG_INFO,"mode: channel=%s mode=%s user=%s", channel, mode, user);
    if(mode==NULL) {/* Get Mode TODO*/
        if(channel) {
            if(user) { 
                umode=IRCTAD_GetUserModeOnChannel(channel, get_user(data->socketd));
                if((umode&IRCUMODE_OPERATOR)==IRCUMODE_OPERATOR) strcat(strmode, "o");

                if((umode&IRCUMODE_LOCALOPERATOR)==IRCUMODE_LOCALOPERATOR) strcat(strmode, "O");
                if((umode&IRCUMODE_SERVERNOTICES)==IRCUMODE_SERVERNOTICES) strcat(strmode, "s");

                if((umode&IRCUMODE_INVISIBLE)==IRCUMODE_INVISIBLE) strcat(strmode, "i");
                if((umode&IRCUMODE_VOICE)==IRCUMODE_VOICE) strcat(strmode, "v");
                if((umode&IRCUMODE_RECEIVEWALLOPS)==IRCUMODE_RECEIVEWALLOPS) strcat(strmode, "w");

                IRCMsg_RplChannelModeIs (&comm, IRCSVR_NAME, get_nick(data->socketd), channel, strmode);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                if(comm) free(comm);
            }
            else {
                /* Get mode channel */
                cmode = IRCTADChan_GetMode(channel);
                if((cmode&IRCMODE_PERMANENT)==IRCMODE_PERMANENT) strcat(strmode, "P");
                if((cmode&IRCMODE_ANONYMOUS)==IRCMODE_ANONYMOUS) strcat(strmode, "a");
                if((cmode&IRCMODE_INVITEONLY)==IRCMODE_INVITEONLY) strcat(strmode, "i");
                if((cmode&IRCMODE_MODERATED)==IRCMODE_MODERATED) strcat(strmode, "m");
                if((cmode&IRCMODE_NOOUTMESSAGES)==IRCMODE_NOOUTMESSAGES) strcat(strmode, "n");
                if((cmode&IRCMODE_QUIET)==IRCMODE_QUIET) strcat(strmode, "q");
                if((cmode&IRCMODE_PRIVATE)==IRCMODE_PRIVATE) strcat(strmode, "p");
                if((cmode&IRCMODE_SECRET)==IRCMODE_SECRET) strcat(strmode, "s");
                if((cmode&IRCMODE_REOP)==IRCMODE_REOP) strcat(strmode, "r");
                if((cmode&IRCMODE_TOPICOP)==IRCMODE_TOPICOP) strcat(strmode, "t");
                IRCMsg_RplChannelModeIs (&comm, IRCSVR_NAME, get_nick(data->socketd), channel, strmode);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                if(comm) free(comm);
            }
        }
        else {
            return 0;
        }
    } else {
        if(get_socketd_byuser(channel)) {
                
        } else {
            umode=IRCTAD_GetUserModeOnChannel(channel, get_user(data->socketd));
            if(umode&IRCUMODE_OPERATOR) {
                switch(IRCTADChan_SetMode(channel, mode) ){
                    case IRCERR_INVALIDCHANNELNAME:
                        break;
                    case IRC_OK:
                        switch(mode[1]) {
                            case '+':
                                switch (mode[2]) {
                                    case 'k':
                                        IRCTADChan_SetPassword (channel, user);
                                        break;
                                    default:
                                        break;
                                }
                                break;
                            case '-':
                                break;
                        } 
                        IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
                        IRCMsg_Mode (&comm, prefix2,channel, mode, get_user(data->socketd));
                        tcpsocket_snd(data->socketd, comm, strlen(comm));
                        if(comm) free(comm);
                        if(prefix2) free(prefix2);
                } 
            }
        }
    }
}

/**
  @brief Atiende el comando PART
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int part(char* command, void* more) {
    conn_data* data = (conn_data*) more;
    char*comm, *prefix, *prefix2, *channel, *msg;
    char comm2[512]={0};
    char **list;
    long n, i;
    int socketd;
    IRCParse_Part(command, &prefix, &channel, &msg);
    switch(IRCTAD_PartChannel (channel, get_user(data->socketd))) {
        case IRCERR_INVALIDUSER:
            syslog(LOG_INFO, "part: invalid user");
            break;
        case IRCERR_NOVALIDCHANNEL:
            sprintf(comm2, ":%s 403 %s %s :No such channel\r\n", IRCSVR_NAME, get_nick(data->socketd) ,channel);
            tcpsocket_snd(data->socketd, comm2, strlen(comm2));
            syslog(LOG_INFO,"part: novalidchannel");
            break;
        default:
            IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
            IRCMsg_Part (&comm, prefix2, channel, msg);
            tcpsocket_snd(data->socketd, comm, strlen(comm));
            if(IRCTAD_ListUsersOnChannel (channel, &list, &n)!=IRCERR_NOVALIDCHANNEL) {
                for(i=0;i<n;i++) {
                    socketd = get_socketd_byuser(list[i]);
                    connection_block(socketd);
                    tcpsocket_snd(socketd, comm, strlen(comm));
                    connection_unblock(socketd);
                }             
            }else {
                syslog(LOG_INFO,"part: invalid list");
            }

    }
}

/**
  @brief Atiende el comando NAMES
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int names(char* command, void* more) {
    conn_data* data = (conn_data*) more;
    char *prefix, *channel, *target, *comm;
    char** list, **chans;
    long i, n, umode, num_c, j;
    char l[450]={0};
    IRCParse_Names (command, &prefix, &channel, &target);
    if(channel==NULL) { 
        IRCTADChan_GetList (&chans, &num_c, NULL);
        for(j=0;j<num_c;j++) {
            if(IRCTAD_ListUsersOnChannel (chans[i], &list, &n)!=IRCERR_NOVALIDCHANNEL) {
                for(i=0;i<n;i++) {
                    umode = IRCTAD_GetUserModeOnChannel(chans[i], list[i]);
                    if((umode&IRCUMODE_OPERATOR)==IRCUMODE_OPERATOR) strcat(l, "@");
                    else if((umode&IRCUMODE_VOICE)==IRCUMODE_VOICE) strcat(l, "+");
                    strcat(l, IRCTADUser_GetNickByUser(list[i]));
                    strcat(l, " ");
                }
                if(strlen(l)) IRCMsg_RplNamReply (&comm, IRCSVR_NAME, get_nick(data->socketd), "=", channel, l);
            if(n) IRCTAD_FreeListUsersOnChannel (list, n);
            tcpsocket_snd(data->socketd, comm, strlen(comm));
            list=NULL; n=0;
            }
        }
        IRCMsg_RplEndOfNames (&comm, IRCSVR_NAME, get_nick(data->socketd), channel);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
   } else {


        if(IRCTAD_ListUsersOnChannel (channel, &list, &n)!=IRCERR_NOVALIDCHANNEL) {
            for(i=0;i<n;i++) {
                umode = IRCTAD_GetUserModeOnChannel(channel, list[i]);
                if((umode&IRCUMODE_OPERATOR)==IRCUMODE_OPERATOR) strcat(l, "@");
                else if((umode&IRCUMODE_VOICE)==IRCUMODE_VOICE) strcat(l, "+");
                strcat(l, IRCTADUser_GetNickByUser(list[i]));
                strcat(l, " ");
            }
        }
        if(n) IRCTAD_FreeListUsersOnChannel (list, n);
        if(strlen(l)) IRCMsg_RplNamReply (&comm, IRCSVR_NAME, get_nick(data->socketd), "=", channel, l);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        IRCMsg_RplEndOfNames (&comm, IRCSVR_NAME, get_nick(data->socketd), channel);
        tcpsocket_snd(data->socketd, comm, strlen(comm));

        if(prefix) free(prefix);
        if(channel) free(channel);
        if(target) free(target);
    } 
}

/**
  @brief Atiende comandos desconocidos 
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int no_command(char* command, void* more) {
    conn_data* data = (conn_data*) more;
    char *comm, type[12]={0};
    sscanf(command, "%s %*[^\r]\r\n", type);
    syslog(LOG_INFO, "No command: %s", command);
    IRCMsg_ErrUnKnownCommand (&comm, IRCSVR_NAME, get_nick(data->socketd), type);
    tcpsocket_snd(data->socketd, comm, strlen(comm));
    free(comm);
    return 0;
}

/**
  @brief Atiende el comando TOPIC
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int topic(char* command, void* more) {
    char* prefix, *channel, *topic;
    char* prefix2, *comm;
    long mode, cmode;
    conn_data* data = (conn_data*) more;
    IRCParse_Topic (command, &prefix, &channel, &topic);
    mode = IRCTAD_GetUserModeOnChannel (channel, get_user(data->socketd));
    IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
    /* Set topic */
    if(topic) {
        cmode = IRCTADChan_GetMode (channel);
        if(cmode & IRCMODE_TOPICOP) {
            /* Topic protected */
            if(mode&IRCUMODE_OPERATOR) {
                IRCTADChan_SetTopic (channel,topic);
                IRCMsg_Topic(&comm, prefix2, channel,topic);
                syslog(LOG_INFO, "topic: rply=%s", comm);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
            }else {
                /* No op */
                IRCMsg_ErrChanOPrivsNeeded (&comm, IRCSVR_NAME, get_nick(data->socketd), channel);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                syslog(LOG_INFO, "topic: no permss");
            } 
        } else {
            /* Topic NOT protected */
            IRCTADChan_SetTopic (channel,topic);
            IRCMsg_Topic(&comm, prefix2, channel,topic);
            syslog(LOG_INFO, "topic: rply=%s", comm);
            tcpsocket_snd(data->socketd, comm, strlen(comm));
        }
    } else { /*Get topic */
        time_t t;
        topic = IRCTADChan_GetTopic(channel, &t);
        if(topic==NULL) {
            IRCMsg_RplNoTopic (&comm, IRCSVR_NAME, get_nick(data->socketd), channel, "No hay Topic definido para el canal");

        }else {


            IRCMsg_RplTopic(&comm, prefix2,get_nick(data->socketd) , channel,topic);
        }
        syslog(LOG_INFO, "topic: rply=%s", comm);
        tcpsocket_snd(data->socketd, comm, strlen(comm));

    }
}

/**
  @brief Atiende el comando WHOIS
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int whois(char* command, void* more) {
    char* prefix2, *comm, nick2[20]={0};
    long mode;
    conn_data* data = (conn_data*) more;
    char l[400]={0}, *maskarray;
    long n=1, i;
    char** list;
    char* away;
    sscanf(command,"%*s %s", nick2);
    syslog(LOG_INFO, "whois: nick2=%s mask=%s", nick2, maskarray);
    if(strlen(nick2)<1) {
        IRCMsg_ErrNoNickNameGiven(&comm, IRCSVR_NAME, get_nick(data->socketd));
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        free(comm);
    } else {
        if(IRCTADUser_GetUserByNick(nick2)==NULL) {
            IRCMsg_ErrNoSuchNick (&comm, IRCSVR_NAME, get_nick(data->socketd), nick2);
            tcpsocket_snd(data->socketd, comm, strlen(comm));
            free(comm);
        }else {
            IRCMsg_RplWhoIsUser(&comm, IRCSVR_NAME, get_nick(data->socketd), nick2, IRCTADUser_GetUserByNick(nick2), IRCTADUser_GetHostByNick(nick2), IRCTADUser_GetRealnameByNick(nick2));
            tcpsocket_snd(data->socketd, comm, strlen(comm));
            syslog(LOG_INFO, "whois: rply=%s", comm);
            if(comm) free(comm);

            IRCMsg_RplWhoIsServer(&comm, IRCSVR_NAME, get_nick(data->socketd), nick2, IRCSVR_NAME, IRCSVR_INFO);
            tcpsocket_snd(data->socketd, comm, strlen(comm));
            syslog(LOG_INFO, "whois: rply=%s", comm);
            if(comm) free(comm);

            IRCTAD_ListChannelsOfUser(IRCTADUser_GetUserByNick(nick2), &list, &n);    
            for(i=0;i<n;i++) {
                mode=IRCTAD_GetUserModeOnChannel(list[i], IRCTADUser_GetUserByNick(nick2));
                if(mode&IRCUMODE_OPERATOR) strcat(l, "@");
                strcat(l, list[i]);
                strcat(l, " ");
            }
            IRCMsg_RplWhoIsChannels(&comm, IRCSVR_NAME, get_nick(data->socketd), nick2, l, NULL); 
            syslog(LOG_INFO, "whois: n=%ld l=%s", n, l);
            tcpsocket_snd(data->socketd, comm, strlen(comm));
            syslog(LOG_INFO, "whois: rply=%s", comm);
            if(comm) free(comm);

            away = IRCTAD_GetAway(nick2);
            if(away!=NULL) {
                IRCMsg_RplAway(&comm, IRCSVR_NAME, get_nick(data->socketd), nick2, away);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
                free(comm);
            }
        }
        IRCMsg_RplEndOfWhoIs(&comm, IRCSVR_NAME, get_nick(data->socketd), nick2);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        syslog(LOG_INFO, "whois: rply=%s", comm);
        if(comm) free(comm);

    }
}

/**
  @brief Atiende el comando QUIT
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int quit(char* command, void* more) {
    char* prefix, *msg;
    char* prefix2, *comm;
    char** list=NULL, **users=NULL;
    long n, u, i, j;
    int socketd;

    conn_data* data = (conn_data*) more;
    IRCParse_Quit (command, &prefix, &msg);
    if(get_user(data->socketd)==NULL) return 0;
    if(msg==NULL) msg="Como he venido, me voy.";
    IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
    IRCMsg_Quit (&comm, prefix2, msg);
    syslog(LOG_INFO, "quit: rply=%s, user=%s", comm, get_user(data->socketd));
    IRCTAD_ListChannelsOfUser(get_user(data->socketd), &list, &n);
    /*if(list) {
        for(i=0;i<n;i++) {
            syslog(LOG_INFO, "quit: list[i]=%s", list[i]);
            IRCTAD_ListUsersOnChannel (list[i], &users, &u);
              for(j=0;j<u;j++) {
              socketd = get_socketd_byuser(users[j]);
              if(socketd!=data->socketd) {
              connection_block(socketd);
              tcpsocket_snd(socketd, comm, strlen(comm));
              connection_unblock(socketd);
              }
              }
              if(users) IRCTAD_FreeListUsersOnChannel (users, u);
              
            if(IRCTADChan_GetNumberOfUsers(list[i])==1) {
                IRCTADChan_Delete(list[i]);
            }
        }
        if(list) IRCTAD_FreeListChannelsOfUser(list, n);
    }*/
    free(comm);
    IRCMsg_Error (&comm, IRCSVR_NAME, "Terminating");
    tcpsocket_snd(data->socketd, comm, strlen(comm));
    if(IRCTAD_Quit(get_user(data->socketd))<0) 
        syslog(LOG_INFO, "quit: no possible");

    set_user(data->socketd, NULL);
    set_nick(data->socketd, NULL);
    syslog(LOG_INFO, "quit: getuser=%s getnick=%s", get_user(data->socketd), get_nick(data->socketd));
    connection_rmv(data->socketd);
    tcpsocket_close(data->socketd);

}

/**
  @brief Atiende el comando MOTD
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int motd(char* command, void* more) {
    char* prefix, *comm;
    conn_data *data = (conn_data*) more;
    FILE* f_msg;
    char msg[256], *nick;
    nick = get_nick(data->socketd);
    f_msg = fopen(IRCSVR_MOTD, "r");

    if(f_msg == NULL) {
        IRCMsg_RplMotdStart(&comm, IRCSVR_NAME, get_nick(data->socketd), IRCSVR_NAME);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        free(comm);
        IRCMsg_RplMotd (&comm, IRCSVR_NAME, nick, "Simple MOTD. Ask the admin for a cooler msg");
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        free(comm);
        IRCMsg_RplEndOfMotd(&comm, IRCSVR_NAME, nick);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        free(comm);
    } else {
        IRCMsg_RplMotdStart(&comm, IRCSVR_NAME, get_nick(data->socketd), IRCSVR_NAME);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        free(comm);
        while(fgets(msg,256,f_msg)) {
            msg[strlen(msg)-1]=0;
            IRCMsg_RplMotd (&comm, IRCSVR_NAME, nick, msg);
            tcpsocket_snd(data->socketd, comm, strlen(comm));
            free(comm);
        }
        fclose(f_msg);
        IRCMsg_RplEndOfMotd(&comm, IRCSVR_NAME, nick);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        free(comm);
    }

}

/**
  @brief Atiende el comando AWAY
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int away(char* command, void*more) {
    char* prefix, *comm, *msg, *away;
    conn_data *data = (conn_data*) more;

    IRCParse_Away(command, &prefix, &msg);
    away = IRCTAD_GetAway(get_user(data->socketd));
    if(away) {
        IRCTAD_DeleteAway(get_user(data->socketd));
        IRCMsg_RplUnaway (&comm, IRCSVR_NAME, get_nick(data->socketd));
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        free(comm);
    } else {
        IRCMsg_RplNowAway(&comm, IRCSVR_NAME, get_nick(data->socketd));
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        IRCTAD_SetAway(get_user(data->socketd), msg);
        free(comm);
    }
}

/**
  @brief Atiende el comando KICK
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int kick(char* command, void* more) {
    char* prefix, *comm, *msg, *channel, *user, *comment, *prefix2;
    conn_data *data = (conn_data*) more;
    long n, i, mode;
    int socketd;
    char** list;
    IRCParse_Kick (command, &prefix, &channel, &user, &comment);
    mode = IRCTAD_GetUserModeOnChannel (channel, get_user(data->socketd));
    IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
    syslog(LOG_INFO, "kick: user=%s channel=%s", user, channel);
    if(mode&IRCUMODE_OPERATOR) {
        switch(IRCTAD_KickUserFromChannel (channel, user)) {
            default:
                IRCMsg_Kick (&comm, prefix2, channel, user, comment);
                syslog(LOG_INFO, "kick: rply=%s", comm);
                if(IRCTAD_ListUsersOnChannel (channel, &list, &n)!=IRCERR_NOVALIDCHANNEL) {
                    for(i=0;i<n;i++) {
                        socketd = get_socketd_byuser(list[i]);
                        connection_block(socketd);
                        tcpsocket_snd(socketd, comm, strlen(comm));
                        connection_unblock(socketd);
                    }                
                }
                tcpsocket_snd(get_socketd_byuser(user), comm, strlen(comm));
                if(comm) free(comm);
        }
    } else {
        IRCMsg_ErrChanOPrivsNeeded (&comm, IRCSVR_NAME, get_nick(data->socketd), channel);
        tcpsocket_snd(data->socketd, comm, strlen(comm));
        if(comm) free(comm);
    }
}

/**
  @brief Atiende el comando TIME
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int time_c(char* command, void* more) {
    char *comm;
    conn_data *data = (conn_data*) more;
    time_t ts = time(NULL);
    IRCMsg_RplTime(&comm, IRCSVR_NAME, get_nick(data->socketd), ctime(&ts)); 
    tcpsocket_snd(data->socketd, comm, strlen(comm));
    free(comm);
}

/**
  @brief Atiende el comando VERSION
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int version(char* command, void* more) {
    conn_data *data = (conn_data*) more;
    char *comm;
    IRCMsg_RplVersion (&comm,IRCSVR_NAME, get_nick(data->socketd), IRCSVR_VERS, IRCSVR_NAME, IRCSVR_VERSCOMM);
    tcpsocket_snd(data->socketd, comm, strlen(comm));
    free(comm);
}

/**
  @brief Atiende el comando NOTICE
  @param command: El comando recibido
  @param more: Puntero a estructura conn_data auxiliar
  @return Ningún valor definido, la función controlan el error de manera interna
*/
int notice(char* command, void* more) {
    conn_data* data = (conn_data*) more;
    char* prefix, *target, *msg, *prefix2, *comm, comm2[512];
    char* away;
    char** list;
    long n, i;
    int socketd;

    IRCParse_Notice (command, &prefix, &target, &msg);
    IRC_ComplexUser1459 (&prefix2, get_nick(data->socketd), get_user(data->socketd), IRCTADUser_GetHostByUser(get_user(data->socketd)), NULL);
    IRCMsg_Notice (&comm, prefix2,target,msg);
    if(target==NULL) {
        sprintf(comm2, ":%s 461 %s %s :Needed more parameters\r\n", IRCSVR_NAME, get_nick(data->socketd), "NOTICE");
        syslog(LOG_INFO, "notice: rply=%s",comm2);
        tcpsocket_snd(data->socketd, comm2 ,strlen(comm2));
    } else {
        if(IRCTAD_ListUsersOnChannel (target, &list, &n)!=IRCERR_NOVALIDCHANNEL) {
            for(i=0;i<n;i++) {
                socketd = get_socketd_byuser(list[i]);
                if(socketd!=data->socketd) {
                    connection_block(socketd);
                    tcpsocket_snd(socketd, comm, strlen(comm));
                    connection_unblock(socketd);
                }
            }
        } else {
            if(get_socketd_bynick(target)!=0) {
                syslog(LOG_INFO,"notice: to user");
                tcpsocket_snd(get_socketd_bynick(target), comm, strlen(comm));
                free(comm);
            } else {
                syslog(LOG_INFO, "notice: no such nick");
                free(comm);
                IRCMsg_ErrNoSuchNick (&comm, prefix2, get_nick(data->socketd), target);
                tcpsocket_snd(data->socketd, comm, strlen(comm));
            }
        }

    }
    if(prefix) free(prefix);
    if(prefix2) free(prefix2);
    if(target) free(target);
    if(msg) free(msg);
}

