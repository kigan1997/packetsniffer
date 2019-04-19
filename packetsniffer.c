#define _POSIX_SOURCE
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/if_ether.h>  //For ETH_P_ALL
#include <net/ethernet.h>  //For ether_header


void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
         
    // printf("\n");
    printf("<TCP Header>\n");
    printf("Source Port          : %u\n",ntohs(tcph->source));
    printf("Destination Port     : %u\n",ntohs(tcph->dest));
    printf("Sequence Number      : %u\n",ntohl(tcph->seq));
    printf("Acknowledge Number   : %u\n",ntohl(tcph->ack_seq));
    printf("Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //printf("CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf("ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("Window               : %d\n",ntohs(tcph->window));
    printf("Checksum             : %d\n",ntohs(tcph->check));
    printf("Urgent Pointer       : %d\n",tcph->urg_ptr);
    printf("\n");                    
    printf("\n###########################################################\n");
}

void print_udp_packet(unsigned char *Buffer, int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
           
    printf("<UDP Header>\n");
    printf("Source Port      : %d\n" , ntohs(udph->source));
    printf("Destination Port : %d\n" , ntohs(udph->dest));
    printf("UDP Length       : %d\n" , ntohs(udph->len));
    printf("UDP Checksum     : %d\n" , ntohs(udph->check));
     
    printf("\n");
    printf("\n###########################################################\n");
}

void print_icmp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
             
    printf("\n");
         
    printf("<ICMP Header>\n");
    printf("Type     : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
        printf("(TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
        printf("(ICMP Echo Reply)\n");
     
    printf("Code     : %d\n",(unsigned int)(icmph->code));
    printf("Checksum : %d\n",ntohs(icmph->checksum));
    //printf("ID       : %d\n",ntohs(icmph->id));
    //printf("Sequence : %d\n",ntohs(icmph->sequence));
    printf("\n");
    printf("\n###########################################################\n");
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
    unsigned int ip;        
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    printf("\n");
    printf("<IP Header>\n");
    printf("IP Version        : %d\n",(unsigned int)iph->version);
    printf("IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("Identification    : %d\n",ntohs(iph->id));
    //printf("Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //printf("Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //printf("More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf("TTL               : %d\n",(unsigned int)iph->ttl);
    printf("Protocol          : %d\n",(unsigned int)iph->protocol);
    printf("Checksum          : %d\n",ntohs(iph->check));
    ip = ntohl(iph->saddr);
    printf("Source IP         : %d.%d.%d.%d\n",(ip>>24)&0x00ff,(ip>>16)&0x00ff,(ip>>8)&0x00ff,(ip>>0)&0x00ff);
    ip = ntohl(iph->daddr);
    printf("Destination IP    : %d.%d.%d.%d\n",(ip>>24)&0x00ff,(ip>>16)&0x00ff,(ip>>8)&0x00ff,(ip>>0)&0x00ff);
	switch (iph->protocol)
	    {
	        case 1:  //ICMP Protocol
	            print_icmp_packet(Buffer, Size);
	            break;
	         
	        case 2:  //IGMP Protocol
	            break;
	         
	        case 6:  //TCP Protocol
	            print_tcp_packet(Buffer,Size);
	            break;
	         
	        case 17: //UDP Protocol
	            print_udp_packet(Buffer,Size);
	            break;
	         
	        default: //Some Other Protocol like ARP etc.
	        	printf("others\n");
	        	printf("\n###########################################################\n");
	            break;
	    }    
}


void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    printf("\n");
    printf("<Ethernet Header>\n");
    printf("Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("Protocol            : %X \n",ntohs(eth->h_proto));
    if(ntohs(eth->h_proto) == 0x0800)	print_ip_header(Buffer,Size);
    else printf("ARP frame...\n###########################################################\n");
}

void myfunc(int sd){
	close(sd);
	exit(1);
}

int main(int argc, char **argv)
{
	signal(SIGINT,myfunc);
    unsigned char * buf = (unsigned char *)malloc(65536);
    memset(buf,0,65536); 
	int sd,datasize = 0,c = 10;

	sd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(sd >= 0)
		printf("Socket descriptor: %d\n",sd);
	else perror("Failed\n");

	while(c--){
		datasize = recvfrom(sd,buf,65536,0,NULL,NULL);
		print_ethernet_header(buf,datasize);
		memset(buf,0,65536);
	}
	close(sd);
}