
//Reference: https://www.bbsmax.com/A/D854VAPvzE/
//Reference: https:www.binarytides.com/hostname-to-ip-address-c-sockets-linux/

#include <stdio.h> //printf
#include <stdlib.h> //exit
#include <string.h> //memset
#include <signal.h> //gettimeofday
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <pthread.h>
#define PACKET_SIZE     4096
#define MAX_WAIT_TIME   5
#define MAX_NO_PACKETS  20
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
int sockfd,datalen=56;
int nsend=0,nreceived=0;
struct sockaddr_in dest_addr;
pid_t pid;
struct sockaddr_in from;
struct timeval tvrecv;
void statistics(int signo);
unsigned short cal_chksum(unsigned short *addr,int len);
int pack(int pack_no);
void *send_packet(void *args);
void *recv_packet(void *args);
int unpack(char *buf,int len);
void tv_sub(struct timeval *out,struct timeval *in);
void statistics(int signo){
	printf("\n--------------------PING statistics-------------------\n");
	printf("%d packets transmitted, %d received , %%%d lost\n",nsend,nreceived,                        (nsend-nreceived)/nsend*100);
    close(sockfd);
    exit(1);
}

/* this function generates header checksums */
unsigned short cal_chksum(unsigned short *addr,int len){
    int nleft=len;
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;
    while(nleft>1) {
    	sum+=*w++;
        nleft-=2;        	
    }      
    if( nleft==1) {
    	*(unsigned char *)(&answer)=*(unsigned char *)w;
    	sum+=answer;
    }        
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return answer;
}

/*set ICMP header*/
int pack(int pack_no){
    int packsize;
    struct icmp *icmp;
    struct timeval *tval;
    icmp=(struct icmp*)sendpacket;
    icmp->icmp_type=ICMP_ECHO;
    icmp->icmp_code=0;
    icmp->icmp_cksum=0;
    icmp->icmp_seq=pack_no;
    icmp->icmp_id=pid;
    packsize=8+datalen;
    tval= (struct timeval *)icmp->icmp_data;
    gettimeofday(tval,NULL);
    /*record sending time*/
    icmp->icmp_cksum=cal_chksum( (unsigned short *)icmp,packsize);
 	/*call check sum algorithm*/
    return packsize;
}


/*send 3 ICMP packets*/
void *send_packet(void *args){
    int packetsize;
    pid=getpid();
    /*get process id to set ICMP id*/
    while( nsend<MAX_NO_PACKETS)        {
    	nsend++;
        packetsize=pack(nsend);
 /*set ICMP header*/
        if( sendto(sockfd,sendpacket,packetsize,0,    (struct sockaddr *)&dest_addr,sizeof(dest_addr) )<0  )     {
       		perror("sendto error");
            continue;
        } 
        sleep(1);
 /*emit requests with a periodic delay*/
        }
    return 0;
}

/*receive all ICMP packet*/
void *recv_packet(void *args){
	int n;
	unsigned int fromlen;
    extern int errno;
    signal(SIGALRM,statistics);
    fromlen=sizeof(from);
    while( nreceived<MAX_NO_PACKETS)  {
    	alarm(MAX_WAIT_TIME);
        if( (n=recvfrom(sockfd,recvpacket,sizeof(recvpacket),0,                                (struct sockaddr *)&from,&fromlen)) <0){
       		if(errno==EINTR)continue;
            perror("recvfrom error");
            continue;
        }
        gettimeofday(&tvrecv,NULL);
  /*record receiving time*/
        if(unpack(recvpacket,n)==-1)continue;
        	nreceived++;
        }
    return 0;
}
/*unpack ICMP header*/
int unpack(char *buf,int len){
	int iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;
    ip=(struct ip *)buf;
    iphdrlen=ip->ip_hl<<2;
    /* get length of ip header -> 4 times the header length in the header*/
    icmp=(struct icmp *)(buf+iphdrlen);
  /*point to ICMP header*/
    len-=iphdrlen;
    /* length of ICMP header and ICMP datagram*/
    if( len<8)    /* invalid length*/
    {
    	printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }        
    /* make sure that we receive the ICMP_ECHOREPLY with our pid*/
    if( (icmp->icmp_type==ICMP_ECHOREPLY) && (icmp->icmp_id==pid) )        {
       tvsend=(struct timeval *)icmp->icmp_data;
       tv_sub(&tvrecv,tvsend);
  /*time of receiving the reply*/
    rtt=tvrecv.tv_sec*1000+tvrecv.tv_usec/1000;
  	/*calculate rtt in milliseconds*/
	/*show the information*/
    printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",                        len,  inet_ntoa(from.sin_addr),                        icmp->icmp_seq,                        ip->ip_ttl,   rtt);
    return 0;
        } 
        else
        return -1;
}


int main(int argc,char *argv[]){
    struct hostent *host;
    struct protoent *protocol;
    unsigned long inaddr=0l;
    //int waittime=MAX_WAIT_TIME;
    int size=50*1024;
    if(argc<2)        {
    	printf("usage:%s hostname/IP address\n",argv[0]);
            exit(1);
        }
    protocol=getprotobyname("icmp");
    if( protocol == NULL)        {
       	perror("getprotobyname");
        exit(1);
    }        
    /*generate raw socket*/
    if( (sockfd=socket(AF_INET,SOCK_RAW,protocol->p_proto) )<0)        {
    	perror("socket error");
        exit(1);
    }        
    setuid(getuid());
        
        
    setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size) );
    bzero(&dest_addr,sizeof(dest_addr));
    dest_addr.sin_family=AF_INET;
    inaddr=inet_addr(argv[1]);
    host=gethostbyname(argv[1]);
    if( inaddr==INADDR_NONE)        { /*hostname*/
    	if(host==NULL)
        {
       		perror("gethostbyname error");
            exit(1);
        }                
        memcpy( (char *)&dest_addr.sin_addr,host->h_addr,host->h_length);
        }        
    else    /*ip address*/
        memcpy( (char *)&dest_addr,(char *)&inaddr,host->h_length);
        
    // pid=getpid();
    printf("PING %s(%s): %d bytes data in ICMP packets.\n",argv[1],                        				inet_ntoa(dest_addr.sin_addr),datalen);
    
    
    pthread_t tids_send, tids_recv;
    int ret = pthread_create(&tids_send, NULL, send_packet, NULL);
    if (ret != 0) {
        printf("pthread_create error: error_code = %d\n", ret);
    }
    ret = pthread_create(&tids_recv, NULL, recv_packet, NULL);
	if (ret != 0) {
		printf("pthread_create error: error_code = %d\n", ret);
	}
    pthread_join(tids_send, NULL);
    pthread_join(tids_recv, NULL);  
    
    statistics(SIGALRM);
 /**/
    return 0;
}
/*sub of two timeval structure */
void tv_sub(struct timeval *out,struct timeval *in){
       if( (out->tv_usec-=in->tv_usec)<0)        {
       --out->tv_sec;
                out->tv_usec+=1000000;
        }        out->tv_sec-=in->tv_sec;
}
