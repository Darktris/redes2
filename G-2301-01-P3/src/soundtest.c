#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <redes2/ircsound.h>
#include <G-2301-01-P1-udp.h>
#include <G-2301-01-P2-rtp.h>

#define N 10
#define BUFF_SIZE N*RTP_MAXLEN
#define LOCALHOST "127.0.0.1"
#define PORT 8123

void main() {
	pid_t pid;
	int sockfd;
	rtpargs_t args;
	char buff[BUFF_SIZE];
	short i;
	long total, len;

	pid = fork();
	if(pid==-1) {
		perror("tenedor");
		exit(EXIT_FAILURE);
	}
	if(!pid) {
		IRCSound_OpenRecord();
		args.pt = IRCSound_RecordFormat(PA_SAMPLE_ULAW,1);
		IRCSound_RecordSound(buff, BUFF_SIZE);
		IRCSound_CloseRecord();

		client_udpsocket_open(PORT,&sockfd);

		args.seq=0;
		args.ts=0;
		args.ssrc=0;
		for(i=0;i<N;i++) rtp_sndpkg(sockfd,LOCALHOST,PORT,args,buff+i*RTP_MAXLEN,RTP_MAXLEN);
		exit(EXIT_SUCCESS);
	} else {
		server_udpsocket_open(8123,&sockfd);
		bzero(buff,BUFF_SIZE);
		for(total=0,len=0;total<BUFF_SIZE;total+=len) {
			rtp_rcvpkg(sockfd,LOCALHOST,PORT,&args,buff+total,&len);
			printf("Received %ld bytes (%ld/%ld)\n",len,total+len,BUFF_SIZE);
		}
		printf("Press any key to play\n");
		getchar();
		IRCSound_OpenPlay();
		IRCSound_PlayFormat(PA_SAMPLE_ULAW,1);
		IRCSound_PlaySound(buff, BUFF_SIZE);
		IRCSound_ClosePlay();
		exit(EXIT_SUCCESS);
	}
}
