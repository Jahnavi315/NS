#include<stdio.h>
#include<sys/socket.h>	
#include<arpa/inet.h>	
#include<string.h>	
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/sockios.h>
#include<sys/ioctl.h>
#include<linux/if_ether.h>
#include<netinet/ether.h>
#include<linux/if_packet.h>
#include<sys/wait.h>
#include<unistd.h>
#include<stdlib.h>

int sfd;
char* saddr = "127.0.0.1";
char* daddr = "127.0.0.2";
int sport = 8089;
int dport = 8076;
int seq_num = 323398483;

struct pseudohdr {
	unsigned int saddr;
	unsigned int daddr;
	unsigned char reserved;
	unsigned char protocol;
	unsigned short tcp_len;
};

void printTcpHdr(struct tcphdr* tcp){
	
    	printf("\n********TCP HEADER********\n\n");
    	printf("\t|-Source Port      : %u\n",ntohs(tcp->source));
    	printf("\t|-Destination Port : %u\n",ntohs(tcp->dest));
    	printf("\t|-Sequence Number    : %u\n",ntohl(tcp->seq));
    	printf("\t|-Acknowledge Number : %u\n",ntohl(tcp->ack_seq));
    	printf("\t|-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp->doff,(unsigned int)tcp->doff*4);
    	printf("\t\t|-Urgent Flag          : %d\n",(unsigned int)tcp->urg);
    	printf("\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcp->ack);
    	printf("\t\t|-Push Flag            : %d\n",(unsigned int)tcp->psh);
    	printf("\t\t|-Reset Flag           : %d\n",(unsigned int)tcp->rst);
    	printf("\t\t|-Synchronise Flag     : %d\n",(unsigned int)tcp->syn);
    	printf("\t\t|-Finish Flag          : %d\n",(unsigned int)tcp->fin);
    	printf("\t|-Window         : %d\n",ntohs(tcp->window));
    	printf("\t|-Checksum       : %d\n",ntohs(tcp->check));
    	printf("\t|-Urgent Pointer : %d\n",tcp->urg_ptr);
        
}

void printIpHdr(struct iphdr* ip){

	printf("\n********IP HEADER********\n\n");
	struct sockaddr_in source,dest;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;
	printf("\t|-Version : %d\n" ,(unsigned int)ip->version);
	printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n ",(unsigned int)ip->ihl,(((unsigned int)(ip->ihl))*4));
	printf("\t|-Type Of Service : %d\n ",(unsigned int)ip->tos);
	printf("\t|-Total Length : %d Bytes\n ",ntohs(ip->tot_len));
	printf("\t|-Identification : %d\n ",ntohs(ip->id));
	printf("\t|-Time To Live : %d\n ",(unsigned int)ip->ttl);
	printf("\t|-Protocol : %d\n ",(unsigned int)ip->protocol);
	printf("\t|-Header Checksum : %d\n ",ntohs(ip->check));
	printf("\t|-Source IP : %s\n ", inet_ntoa(source.sin_addr));
	printf("\t|-Destination IP : %s\n ",inet_ntoa(dest.sin_addr));
	fflush(stdout);
	
}

unsigned short checksum(unsigned short* buff, int _16bitword)
{
	unsigned long sum;
	for(sum=0;_16bitword>0;_16bitword--)
	sum+=htons(*(buff)++);
	sum = ((sum >> 16) + (sum & 0xFFFF));
	sum += (sum>>16);
	return (unsigned short)(~sum);
}

unsigned short tcp_checksum(struct iphdr* ip,struct tcphdr* tcp,int tcplen){	
	
	struct pseudohdr* pseudo = malloc(sizeof(struct pseudohdr));
	
	pseudo->saddr = ip->saddr;
	pseudo->daddr = ip->daddr;
	pseudo->reserved = 0;
	pseudo->protocol = 6;
	pseudo->tcp_len = htons(tcplen);
	
	int pseudo_size = sizeof(*pseudo) + tcplen;
	
	unsigned short* pseudo_packet = malloc(pseudo_size);
	
	memcpy(pseudo_packet,pseudo,sizeof(*pseudo));
	memcpy(pseudo_packet + (sizeof(*pseudo))/2,tcp,tcplen);
	
	unsigned short result = checksum(pseudo_packet,pseudo_size/2);
	free(pseudo_packet);
	
	return result;
}


void sendPacket(){

	char buff[1024];
	memset(buff,0,sizeof buff);
	
	int total_len = 0;
	
	struct iphdr* ip = (struct iphdr*)(buff);
	
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->id = htons(10201);
	ip->ttl = 64;
	ip->protocol = 6;
	ip->check = 0;
	ip->saddr = inet_addr(saddr);
	ip->daddr = inet_addr(daddr); 
	
	total_len += sizeof(struct iphdr);
	
	
	struct tcphdr* tcp = (struct tcphdr*)(buff + total_len);
	
	tcp->source = htons(sport);
	tcp->dest = htons(dport);
	tcp->seq = htonl(seq_num);
	tcp->doff = 6;
	tcp->syn = 1;
	tcp->window = htons(65535);
	tcp->check = 0; 
	
	total_len += (unsigned int)tcp->doff*4;
	
	ip->tot_len = htons(total_len);
	
	ip->check = htons(checksum((unsigned short*)ip,ip->ihl*2));
	tcp->check = htons(tcp_checksum(ip,tcp,sizeof(struct tcphdr)));
	
	printIpHdr(ip);
	
	printTcpHdr(tcp);
	
	struct sockaddr_in addr;
	memset(&addr,0,sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	int sz = sendto(sfd,buff,total_len,0,(struct sockaddr*)&addr,sizeof addr);
	if(sz < 0){
		perror("send ");
	}else if(sz == total_len){
		printf("successfully sent SYN packet to X terminal\n");
	}
}

int main(){
	sfd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
	if(sfd == -1){
		perror("socket ");
	}
	sendPacket();
}
