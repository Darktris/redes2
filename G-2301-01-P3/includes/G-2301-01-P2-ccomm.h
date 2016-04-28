#ifndef _CCOMM_H
#define _CCOMM_H

#define CCOMM_LEN 10000
void cdefault(char* command);
void cRplMotd(char* command);
typedef void(*ccomm_t)(char*);
void init_ccomm();
#ifndef CCOMM_NEXTERN
extern ccomm_t ccommands[CCOMM_LEN];
#endif
#endif 
