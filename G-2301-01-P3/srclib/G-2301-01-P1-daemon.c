/* vim: set ts=4 sw=4 et: */
/**
  @file G-2301-01-P1-daemon.c
  @brief Libreria de creacion de un daemon
  @author Sergio Fuentes  <sergio.fuentesd@estudiante.uam.es>
  @author Daniel Perdices <daniel.perdices@estudiante.uam.es>
  @date 2016/02/10
  */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "G-2301-01-P1-daemon.h"

/**
  @brief Crea un servicio daemon identificado
  @param srvcid: Identificacion del daemon
  @return DMNOK o DMNERR_* en caso de error
*/
int daemonize(char* srvcid) {
    pid_t pid;
    char buf[DMN_SRVCID_MAX+2];

    if(!srvcid || strlen(srvcid)>DMN_SRVCID_MAX) return DMNERR_ID;

    pid = fork();
    if(pid<0) return DMNERR_FORK;
    if(pid>0) exit(0); /* Cerramos el proceso */

    umask(0);
    setlogmask(LOG_UPTO(LOG_INFO));
    sprintf(buf,"[%s]:",srvcid);
    openlog(buf,LOG_CONS | LOG_NDELAY, LOG_LOCAL3);
    syslog(LOG_INFO, "Service started!");

    if(setsid()<0) {
        syslog(LOG_ERR, "Error creating session.");
        return DMNERR_SID;
    }

    if(chdir("/")<0) {
        syslog(LOG_ERR, "Error changing working directory.");
        return DMNERR_CWD;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return DMNOK;
}
