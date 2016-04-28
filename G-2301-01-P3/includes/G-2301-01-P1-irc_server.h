/* vim: set ts=4 sw=4 et: */
#ifndef _IRC_SVR_H
#define _IRC_SVR_H

#define NCOMMANDS 300
#define MAX_USERS 100
#define MAX_USERNAME 20
#define MAX_NICK 20
#define MAX_USERS_INCHAN 20
#define IRCSVROK 0
#define IRCSVRERR_MALLOC -1
#define IRCSVRERR_MAXLEN -2
#define IRCSVRERR_ARGS -3


#define IRCSVR_MOTDFILE "motd"
#define IRCSVR_CHANFILE "channels"
#define IRCSVR_MOTD get_motd_path()
#define IRCSVR_TIMEOUT 40
#define IRCSVR_NAME "deathStar.empire.sw"
#define IRCSVR_INFO "Best IRC Server in the whole Empire"
#define IRCSVR_VERS "0.0.1"
#define IRCSVR_VERSCOMM "Alpha release"

int process_command(char* command, void* data);
int set_user(int socketd, char* user);
int set_nick(int socketd, char* nick);
int get_socketd_bynick(char* nick);
int get_socketd_byuser(char* user);
char* get_motd_path();
char* get_user(int socketd); 
char* get_nick(int socketd); 
#endif
