/* vim: set ts=4 sw=4 et: */
#ifndef _MYIRC_H
#define _MYIRC_H

int nick(char* command, void* more);
int user(char* command, void* more);
int ping(char* command, void* more);
int pong(char* command, void* more);
int list(char* command, void* more);
int join(char* command, void* more);
int privmsg(char* command, void* more);
int part(char* command, void* more);
int topic(char* command, void* more);
int names(char* command, void* more);
int quit(char* command, void* more);
int motd(char* command, void* more);
int away(char* command, void* more);
int whois(char* command, void* more);
int kick(char* command, void* more);
int mode(char* command, void* more);
int version(char* command, void* more);
int time_c(char* command, void* more);
int notice(char* command, void* more);
int no_command(char* command, void* more);

#endif 
