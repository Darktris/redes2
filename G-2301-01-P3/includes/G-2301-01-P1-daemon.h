/* vim: set ts=4 sw=4 et: */
#ifndef _DAEMON_H
#define _DAEMON_H

#define DMNOK 0
#define DMNERR_ID -1
#define DMNERR_FORK -2
#define DMNERR_SID -3
#define DMNERR_CWD -4

#define DMN_SRVCID_MAX 16

int daemonize(char* srvcid);

#endif 
