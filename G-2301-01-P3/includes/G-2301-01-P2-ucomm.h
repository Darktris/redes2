#ifndef _MYIRC_H
#define _MYIRC_H

#define UCOMM_LEN 400
void udefault(char* command);
void init_ucomm();
typedef void(*ucomm_t)(char*);
#ifndef UCOMM_NEXTERN
extern ucomm_t ucommands[UCOMM_LEN];
#endif
#endif 
