#ifndef _CLIENT_H
#define _CLIENT_H

void* rcv_thread(void* d);
int client_socketsnd(char*);
int client_socketsnd_thread(char *msg);

int client_socketrcv(char* msg, size_t size);
int client_socketrcv_thread(char* msg, size_t size);
char* get_unick();
char* get_uhost();
void set_audio_host(char *host);
void unlock_audio();
void set_audio_port(unsigned long p);
void disconnect_client();
#endif 
