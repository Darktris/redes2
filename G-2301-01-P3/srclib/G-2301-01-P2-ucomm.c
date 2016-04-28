/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P2-ucomm.c
  @brief Libreria de manejo de comandos de usuario
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/02/10
  */
#include <redes2/irc.h>
#include <redes2/ircxchat.h>
#include <syslog.h>
#include <G-2301-01-P1-tools.h>
#include <G-2301-01-P2-client.h>
#define UCOMM_NEXTERN
#include <G-2301-01-P2-ucomm.h>

ucomm_t ucommands[UCOMM_LEN];

/**
  @brief Atiende el comando de usuario JOIN
  @param command: El comando recibido
*/
void uJoin(char* command) {
    char *channel, *pass, *comm;
    char com2[512]; 
    IRCUserParse_Join(command, &channel, &pass);
    syslog(LOG_INFO, "ujoin: parsing");

    IRCMsg_Join (&comm, NULL, channel, pass, NULL);
    client_socketsnd(comm);
    if(comm) free(comm);
    if(pass) free(pass);
    if(channel) free(pass);
} 

/**
  @brief Atiende el comando de usuario LIST
  @param command: El comando recibido
*/
void uList(char* command) {
    char *channel, *st, *comm;

    IRCUserParse_List (command, &channel, &st);

    IRCMsg_List(&comm, NULL, channel, NULL);
    client_socketsnd(comm);
    if(comm) free(comm);

    if(channel) free(channel);
    if(st) free(st);
}

/**
  @brief Atiende el comando de usuario NICK
  @param command: El comando recibido
*/
void uNick(char* command) {
    char* nick, *comm;
    IRCUserParse_Nick (command, &nick);

    IRCMsg_Nick(&comm, NULL, nick, NULL);
    client_socketsnd(comm);
    if(comm) free(comm);

    if(nick) free(nick);
}
 
void udefault(char* command) {
    syslog(LOG_INFO, "udef: ERROR no command");    
}

/**
  @brief Atiende el comando de usuario NAMES
  @param command: El comando recibido
*/
void uNames(char* command) {
    char* channel, *tar, *comm;
    IRCUserParse_Names(command, &channel, &tar);
    
    IRCMsg_Names(&comm, NULL, channel?channel:IRCInterface_ActiveChannelName(), tar);
    client_socketsnd(comm);

    if(comm) free(comm);
    if(channel) free(channel);
    if(tar) free(tar);
}

/**
  @brief Atiende el comando de usuario WHOIS
  @param command: El comando recibido
*/
void uWhoIs(char* command) {
    char* nick, *comm;
    IRCUserParse_Whois(command, &nick);
    IRCMsg_Whois (&comm, NULL, NULL, nick);
    client_socketsnd(comm);

    if(comm) free(comm);
    if(nick) free(nick);
}

/**
  @brief Atiende el comando de usuario PING
  @param command: El comando recibido
*/
void uPing(char* command) {
    IRCInterface_WriteSystem ("AVISO", "El comando PING solo soporta el envío de un PING al servidor conectado para comprobar la conexión");
    client_socketsnd("PING 0001234567890\r\n"); 
}

/**
  @brief Atiende el comando de usuario TOPIC
  @param command: El comando recibido
*/
void uTopic(char* command) {
    char *comm, *topic;
    IRCUserParse_Topic (command, &topic);
    IRCMsg_Topic(&comm, NULL, IRCInterface_ActiveChannelName(), topic); 
    client_socketsnd(comm);
    if(topic) free(topic);
    if(comm) free(comm);
} 

/**
  @brief Atiende el comando de usuario UWHO
  @param command: El comando recibido
  */
void uWho(char* command) {
    char *mask, *chan, *comm;
    IRCUserParse_Who(command, &mask); 
    if(mask) {
       IRCMsg_Who (&comm, NULL, mask, NULL);
    } else {
        chan = IRCInterface_ActiveChannelName();
        IRCMsg_Who (&comm, NULL, strcmp(chan,"System")==0?"0":chan, NULL);
    }
    
    client_socketsnd(comm);
    if(comm) free(comm);
    if(mask) free(mask);
}

/**
  @brief Atiende el comando de usuario UPART
  @param command: El comando recibido
  */
void uPart(char* command) {
    char *msg, *comm;
    IRCUserParse_Part(command, &msg);
    IRCMsg_Part(&comm, NULL, IRCInterface_ActiveChannelName(), msg?msg:"Saliendo :)"); 
    client_socketsnd(comm);
    if(comm) free(comm);
    if(msg) free(msg);
}
 
/**
  @brief Atiende el comando de usuario UAWAY
  @param command: El comando recibido
  */
void uAway(char* command) {
    char* reason, *comm;
    IRCUserParse_Away (command, &reason);
    IRCMsg_Away (&comm,NULL, reason);
    client_socketsnd(comm);
    if(comm) free(comm);
    if(reason) free(reason);
}

/**
  @brief Atiende el comando de usuario UINVITE
  @param command: El comando recibido
  */
void uInvite(char* command) {
    char *nick,*channel, *comm; 
    IRCUserParse_Invite (command, &nick, &channel);
    IRCMsg_Invite (&comm, NULL, nick, channel?channel:IRCInterface_ActiveChannelName());
    client_socketsnd(comm);
    if(comm) free(comm);
    if(nick) free(nick);
    if(channel) free(channel);
}

/**
  @brief Atiende el comando de usuario UKICK
  @param command: El comando recibido
  */
void uKick(char* command) {
    char* n, *m;
    char *comm;
    IRCUserParse_Kick (command, &n, &m);

    IRCMsg_Kick(&comm, NULL, IRCInterface_ActiveChannelName(), n, m?m:"Kicked from the channel");
    client_socketsnd(comm);
    if(comm) free(comm);
    if(n) free(n);
    if(m) free(m);
}

/**
  @brief Atiende el comando de usuario UNOTICE
  @param command: El comando recibido
  */
void uNotice(char* command) {
    char *msg, * tar;
    char* comm;
    IRCUserParse_Notice(command, &tar, &msg);
    IRCInterface_WriteSystem("AVISO", "Los mensajes NOTICE se utilizan muchas veces para intercambiar información de administración. Se desaconseja su uso como mensajes de proposito general, para ello se dispone de PRIVMSG o MSG (llama a PRIVMSG), aunque se pueden usar con este propósito si el usuario así lo decide.");
    IRCMsg_Notice(&comm, NULL, tar?tar:IRCInterface_ActiveChannelName(), msg);
    client_socketsnd(comm);
    if(msg) free(msg);
    if(comm) free(comm);

}

void uMode(char* command) {
    char* mode=NULL, *f=NULL;
    char* comm;
    IRCUserParse_Mode(command, &mode, &f);
    //sscanf(command, "/mode %ms %ms", mode, f);
    IRCMsg_Mode (&comm, NULL, IRCInterface_ActiveChannelName(), mode, f);

    client_socketsnd(comm);
}

/**
  @brief Atiende el comando de usuario UHELP
  @param command: El comando recibido
  */
void uHelp(char* command) {
    IRCInterface_WriteSystem(NULL, 
 "UNAMES, UHELP, ULIST, UJOIN, UPART, ULEAVE, UQUIT, UNICK, UAWAY, UWHOIS, UINVITE, UKICK, UTOPIC, UMSG, UQUERY, UNOTICE, UPING, UWHO, UCYCLE, UMOTD, UMODE, UPARTALL");
}
 
/**
  @brief Atiende el comando de usuario UCYCLE
  @param command: El comando recibido
  */
void uCycle(char* command) {
    char **channels;
    int numchannels;
    int i;
    char* comm;
    char text[500];
    IRCUserParse_Cycle (command, &channels, &numchannels);
    for(i=0;i<numchannels;i++) {
        sprintf(text, "PART %s\r\nJOIN %s\r\n", channels[i], channels[i]);
        client_socketsnd(text);
    }
    printf("numchannels %d \n", numchannels);
    if(numchannels==0) {
        sprintf(text, "PART %s\r\nJOIN %s\r\n", IRCInterface_ActiveChannelName(), IRCInterface_ActiveChannelName());
        client_socketsnd(text);
    }
}

/**
  @brief Atiende el comando de usuario UQUERY
  @param command: El comando recibido
  */
void uQuery(char* command) {
    char* tar, *msg;
    char *comm=NULL;
    IRCUserParse_Query (command, &tar, &msg);
    if(!IRCInterface_QueryChannelExist (tar)) IRCInterface_AddNewChannel(tar, IRCInterface_ModeToIntMode("+")); 
    if(msg) IRCInterface_WriteChannel(tar, get_unick(), msg);

    IRCMsg_Privmsg (&comm, NULL, tar, msg);
    client_socketsnd(comm);
    if(tar) free(tar);
    if(msg) free(msg);
    if(comm) free(comm);
}

/**
  @brief Atiende el comando de usuario UPRIV
  @param command: El comando recibido
  */
void uPriv(char* command) {
    char* tar, *msg;
    char *comm=NULL;
    IRCUserParse_Priv (command, &tar, &msg);

    IRCMsg_Privmsg (&comm, NULL, tar, msg);
    client_socketsnd(comm);
    if(tar) free(tar);
    if(msg) free(msg);
    if(comm) free(comm);
}

/**
  @brief Atiende el comando de usuario UPRIV
  @param command: El comando recibido
  */
void uMsg(char* command) {
    char* tar, *msg;
    char *comm=NULL;
    IRCUserParse_Msg (command, &tar, &msg);

    IRCMsg_Privmsg (&comm, NULL, tar, msg);
    client_socketsnd(comm);
    if(tar) free(tar);
    if(msg) free(msg);
    if(comm) free(comm);
}

void uMotd(char* command) {
    client_socketsnd("MOTD\r\n");
} 

/**
  @brief Atiende el comando de usuario UQUIT
  @param command: El comando recibido
  */
void uQuit(char* command) {
    char *msg;
    char *comm=NULL;
    IRCUserParse_Quit(command, &msg);
    //IRCInterface_ChangeConectionSelected();
    IRCMsg_Quit(&comm, NULL,  msg);

    client_socketsnd(comm);
    disconnect_client();
    if(msg) free(msg);
    if(comm) free(comm);
}

/**
  @brief Atiende el comando de usuario UPARTALL
  @param command: El comando recibido
  */
void uPartAll(char* command) {
    client_socketsnd("JOIN 0\r\n");
}
void init_ucomm() {
    int i;
    //UNAMES, UHELP, ULIST, UJOIN, UPART, ULEAVE, UQUIT, UNICK, UAWAY, UWHOIS, UINVITE, UKICK, UTOPIC, UME, UMSG, UQUERY, UNOTICE, UNOTIFY, UIGNORE, UPING, UWHO, UWHOWAS, UISON, UCYCLE, UMOTD, URULES, ULUSERS, UVERSION, UADMIN, UUSERHOST, UKNOCK, UVHOST, UMODE, UTIME, UBOTMOTD, UIDENTIFY, UDNS, UUSERIP, USTATS, UCTCP, UDCC, UMAP, ULINKS, USETNAME, ULICENSE, UMODULE, UPARTALL, UCHAT
    for(i=0;i<UCOMM_LEN; i++) {
        ucommands[i]=udefault;
    }
    ucommands[UNAMES] = uNames;
    ucommands[UJOIN] = uJoin;
    ucommands[ULIST] = uList;
    ucommands[UNICK] = uNick;
    ucommands[UWHOIS] = uWhoIs;
    ucommands[UPING] = uPing;
    ucommands[UTOPIC] = uTopic;
    ucommands[UWHO] = uWho;
    ucommands[UPART] = uPart;
    ucommands[UAWAY] = uAway;
    ucommands[UINVITE] = uInvite;
    ucommands[UKICK] = uKick;
    ucommands[UMODE] = uMode;
    ucommands[UQUERY] = uQuery;
    //ucommands[UPRIV] = uPriv;
    ucommands[UMSG] = uMsg;
    ucommands[UQUIT] = uQuit;
    ucommands[UCYCLE] = uCycle;
    ucommands[UMOTD] = uMotd;
    ucommands[UNOTICE] = uNotice;
    ucommands[UPARTALL] = uPartAll;
}
