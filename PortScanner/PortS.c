#include<stdio.h>   
#include<stdint.h>
#include<string.h>  
#include<math.h>
#include<stdlib.h>    
#include<getopt.h>
#include<unistd.h>

#include<sys/types.h>
#include<sys/ioctl.h>
#include<sys/wait.h>
#include<sys/socket.h>

#include<netinet/in.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>    
#include<netinet/udp.h>
#include<netinet/ether.h>
#include<netinet/ip_icmp.h>

#include<arpa/inet.h>

#include<signal.h>
#include<endian.h>

#include<netdb.h>
#include<net/if.h>

#include<pcap/pcap.h>

#define TIME_OUT 500
#define PORT_NO 5467


void get_task();
void parseargs(int argc,char * argv[]) ;  
void start_work() ;
void classify_porttype(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) ;
pcap_t * pcap_filter(int src_port, int read_timeout);
char *  make_packet(char *dst_ip, int dst_port, char *src_ip, int src_port, int scan_type);

typedef struct tasks
{  	char ip[16];
    int  port;
	int type_of_scan;
} task_i;

struct checksum_header 
{	unsigned int source;
	unsigned short tcp_length;
	unsigned char instance;
	unsigned char protocol;
	unsigned int destination;
	struct tcphdr tcp;};
	
	//GLOBAL VARIABLES
	pcap_t * pcap_session; 
	task_i *taskprepare[100];
	struct hostent *IP_i;
	FILE *fp;
	size_t len;
	ssize_t gather;

	int option;
	int index_to_option;
	int prefixpart;
	int sortedports[100];
	int i;
	int j;
		
	char * source_ip;
	char Prefix[100];
	char * IPline;
	char * pch;
	char *ippart;
	char sortedscan[5];
	char *sortedip[100];
	char *givenports;
	char *givenip[100];
	char givenprefix[100];
	char givenscan[100];
	char * inst;
	
// METHODS

int main (int argc, char **argv)
{  parseargs(argc,argv);
   get_task();
   start_work();
   return 0;
}
	
void parseargs(int argc,char * argv[])
{   static struct option long_options[] = {	{"help", no_argument, 0, 'h'},
			{"ports", required_argument, 0, 'p'},
			{"ip", required_argument, 0, 'i'},
			{"prefix", required_argument, 0, 'e'},
			{"file", required_argument, 0, 'f'},
			{"speedup", required_argument, 0, 't'},
			{"scan", required_argument, 0, 's'},
			{0, 0, 0, 0}};
			
	while ((option = getopt_long(argc, argv, "",long_options, &index_to_option)) != -1)
	{     switch (option) 
		{   
			case 'h':	printf("PortScanner [OPTIONS]\n" );
						printf("  --ports Port numbers \n");
						printf("  --ip 	  IP_i addresses \n");
						printf("  --prefix IP_i prefix to scan\n");
						printf("  --file File which has IP_i addresses \n");
						printf("  --speedup  No of thgathers\n");
						printf("  --scan  SYN/NULL/FIN/XMAS/ACK/UDP \n");
						exit(1);
			case 'p': 	printf("Ports to be scanned are %s\n",optarg);
						while(optarg!=NULL)
						{ 	givenports=optarg;
							if(strstr(givenports,"-")!=NULL && strtok(givenports,",")!=NULL)
							{	if(strtok(givenports,",")!=NULL)
								{ 	char *pch = strtok (givenports,",");
									while (pch != NULL)
									{	sortedports[i]=pch;
										//printf ("%d\n",sortedports[i]);
										pch = strtok (NULL, ",");
										i++;
									}
								}
								if(strstr(givenports,"-")!=NULL)
								{
									char *pos = strstr(givenports,"-");
									char *pch = strtok(givenports,"-");
									int initialVal = atoi(pch);
									int finalVal = atoi(++pos);
									//printf("test initialVal : %d finalVal : %d\n", initialVal,finalVal);
									for(j=initialVal;j<=finalVal;j++)
									{	sortedports[i]=j;
										//printf("%d\n",sortedports[i]);
										i++;
									}
								}
										
							}
							else if(strstr(givenports,"-")!=NULL)
							{
								char *pos = strstr(givenports,"-");
								int initialVal = atoi(givenports);
								int finalVal = atoi(++pos);
								//printf("test initialVal : %d finalVal : %d\n", initialVal,finalVal);
								for(j=initialVal;j<=finalVal;j++)
								{ 	sortedports[i]=j;
									//printf("%d\n",sortedports[i]);
									i++;
								}
							}
					
					else if(strstr(givenports,",")!=NULL)
					{	char *pch;
			            pch	= strtok (givenports,",");
						while (pch != NULL)
						{	
						//printf("12");
						for(i=0;i<strlen(givenports);i++)
						{ //printf("%s\n",strlen(givenports));
 						sortedports[i]=pch;
						//printf ("%d\n",sortedports[i]);
						pch = strtok (NULL, ",");
						}
						
						}
					}
					break;
					}
					break;
			case 'i':	printf("IP_i address is :%s\n",optarg);
					sortedip[0] = (char *)malloc(strlen(optarg) + 1);
					strcpy(sortedip[0],optarg);
					printf("Sorted:%s\n",sortedip[0]);
					break;
			case 'e':	strcpy(givenports,optarg); 
					pch = strtok (givenports,"/"); 
					int i=0;
					while (pch != NULL)
					{
						if(i==0)
						{
					ippart=pch;
						}
					else if(i==1)
						{
					prefixpart=atoi(pch);
						}
					pch = strtok (NULL, "/");
					}

					int ip[]= {0,0,0,0};
					pch=strtok(ippart,".");
					while(pch!=NULL)
					{
					for(i=0;i<4;i++)
					{
					ip[i]=atoi((char *)pch);
					pch=strtok(NULL,".");
					}
					}
					
					int incrementor;
					incrementor= (int)((pow(2,(double)(32 - prefixpart))));
					int ip_new = 0;
					char newIPAddress[INET_ADDRSTRLEN];
					int netmask[4] = {255,255,255,255};
					int   byte = 0;
					int bit=0;
					int prefixcount=32-prefixpart-1;
					for(i=prefixcount;i>=0;i--)
					{	byte=(int)((32-i)/8);
						if(i==0)
						byte--;
						else if((i>0)&(i%8==0))
						byte=byte-(int)(i/8);
					}
										
					uint8_t addrhost[4] = {255,255,255,255};
					uint8_t addr_new[4]= {0,0,0,0};
					for(i=0;i<incrementor;i++)
					{
					addrhost[i] = ip[i] & netmask[i];
					addr_new[i] = addrhost[i];
					}
					for(i = 1; i <= incrementor; i++)
					{
					memcpy(&ip_new,addrhost,sizeof(uint32_t));
					ip_new=htole32(ip_new)| htobe32((uint32_t)i);
					memcpy(addr_new,&ip_new,sizeof(uint32_t));
					if(i==4||i == 1||i==2||i==3||i == incrementor)
					printf("addrhost of %d : %d.%d.%d.%d \n",i,addr_new[0],addr_new[1],addr_new[2],addr_new[3]);
					}
					break;
						
			case 'f':	fp=fopen(optarg,"r");
					while((gather=getline(&IPline,&len,fp))!=-1)
					{
					for(i=0;i<20;i++)
					{
					printf("%s\n",IPline);
					}
					}					
					break;
			case 's'://	printf("Scans to be done are %s\n",optarg );
					strcpy(givenscan,optarg);
					bzero(sortedscan,5);
					for (i = index_to_option; i < argc; i++)
					{	strcat(givenscan,";");
						strcat(givenscan,argv[i]);
					}
						char *token;
						for(token = strtok(givenscan, ";"), i=0;
						(token && i < 7);
						token = strtok(NULL,";"), i++)
						{	if (strcmp(token,"SYN") == 0)
							sortedscan[0] = 1;
							else if (strcmp(token,"NULL") == 0)
							sortedscan[1] = 2;
							else if (strcmp(token,"FIN") == 0)
							sortedscan[2] = 3;
							else if (strcmp(token,"XMAS") == 0)
							sortedscan[3] = 4;
							else if (strcmp(token,"ACK") == 0)
							sortedscan[4] = 5;
						}
						break;
		}
    }
}

void get_task()
{
int i=1;
int tasknumber=100;
int p,q,r;
int h=0;
for(p=0;p<=1;p++)
	{  	if (sortedip[p]==0)
		break;
		for(q=0;q<=100;q++)
			{ if (sortedports[q]==0)
			  break;	
				for(r=0;r<5;r++)
				{ if(sortedscan[r]!=0)
					{ 	taskprepare[h]= (task_i *)malloc(sizeof(task_i));
						strcpy(taskprepare[h]->ip,sortedip[p]);
						//printf("Tasks ip %s\n",taskprepare[h]->ip);
						taskprepare[h]->type_of_scan=sortedscan[r];
						//printf("Tasks scan %d\n",taskprepare[h]->scan_type);
						taskprepare[h]->port=sortedports[q];
						//printf("Tasks port %d\n",taskprepare[h]->port);
						h++;
					}		
				}
			}
	}
}


void start_work()
{	task_i *currentTask = NULL;

	char *pkt = NULL;
	
	int first = 1;
	int pktlen = 0;
	const int *val = &first;
	int incrementor = 0;
	int sockfd = -1;
	int time = TIME_OUT;
	int returnvalue;
	struct sockaddr_in sin;
	struct sigaction act;
	struct iphdr *ip_header = NULL;	
	struct hostent *rmtht;
	struct in_addr **addr_list;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	
	for(i=0;i<100;i++)
	{
	rmtht = gethostbyname(taskprepare[i]->ip);
	if ((rmtht) != NULL)
	{
		addr_list = (struct in_addr **)rmtht->h_addr_list;
	}
	else
	{return; }
	//Self IP CAL
	int fd;
	struct ifreq ifr;
	char iface[] = "eth0";
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	source_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	printf("Source IP%s\n",source_ip);
	
	
	pcap_session = pcap_filter(PORT_NO,0); 
	incrementor = 0;
		sin.sin_family = AF_INET; 
		inet_pton(AF_INET, taskprepare[i]->ip, &sin.sin_addr);
		sin.sin_port = htons(taskprepare[i]->port);
		pkt = make_packet(taskprepare[i]->ip,taskprepare[i]->port, source_ip, PORT_NO, taskprepare[i]->type_of_scan);
		
			if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
			{
				perror("Socket NOT created ");
				exit(1);
			}
		
	ip_header = (struct iphdr *)pkt;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (first)) < 0)
	fprintf(stderr, "Warning: Cannot set HDRINCL for ip  port \n");
	pktlen = ip_header->tot_len;

	
		do{

			if (sendto(sockfd, pkt, pktlen, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
				printf("Error \n" );
				break;
			}
			
			sigaction (SIGALRM, &act, 0);
			alarm(time);
			returnvalue = pcap_dispatch(pcap_session,1, classify_porttype, (u_char *)taskprepare[i]);
			//printf("returnvalue is %d\n",returnvalue);
			
			alarm(0);

			if (returnvalue == -2)
			{	incrementor++;
				if(incrementor == 3)
				{
					printf("maximum retries reached\n"); //skeleton
				}
			}
			else
				{break; }
		}while (incrementor < 3);
   }  
    close(sockfd);
	free(pkt);
	pcap_close(pcap_session);
	return;
 }

unsigned short checksum(uint16_t *ptr,int pktlen)
{	uint32_t chck_sum = 0;
	while(pktlen>1) {
		chck_sum += *ptr++;
		pktlen-=2;
	}
	if(pktlen==1) 
	{chck_sum += *(uint8_t *)ptr;}
	
	chck_sum = (chck_sum>>16) + (chck_sum & 0xffff);
	chck_sum = chck_sum + (chck_sum>>16);
	return((short)~chck_sum);
}

char *  make_packet(char *dst_ip, int dst_port, char *src_ip, int src_port, int scan_type)
{
	struct iphdr *ip_header = NULL;	
	struct tcphdr *tcp_header = NULL;
	struct ifreq ifr;
	char *dgm = (char*)malloc(4096);
	ip_header = (struct iphdr *) dgm;
	tcp_header = (struct tcphdr *) (dgm + sizeof (struct ip));
	struct checksum_header psh;
	memset (dgm, 0, 4096); 
	ip_header->ihl = 5;
	ip_header->version = 4;
	ip_header->tos = 0;
	ip_header->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	ip_header->id = htons(54321); 
	ip_header->frag_off = htons(0);
	ip_header->ttl = 64;
	ip_header->protocol = IPPROTO_TCP;
	ip_header->check = 0;
	ip_header->saddr = inet_addr("129.79.247.86");
	ip_header->daddr = inet_addr(dst_ip);
	ip_header->check = checksum((uint16_t *) dgm, ip_header->tot_len >> 1);

	tcp_header->source = htons(src_port);
	tcp_header->dest = htons(dst_port);
	tcp_header->seq = htonl(7654321);
	tcp_header->ack_seq = 0;
	tcp_header->doff = sizeof(struct tcphdr)/4;
	tcp_header->fin=0;
	tcp_header->syn=0;
	tcp_header->rst=0;
	tcp_header->psh=0;
	tcp_header->ack=0;
	tcp_header->urg=0;
	tcp_header->window = htons(14600);
	tcp_header->check = 0;
	tcp_header->urg_ptr = 0;

	switch(scan_type)
	{
	case 1:
		tcp_header->syn=1;
		break;
	case 2:
		break;
	case 3:
		tcp_header->fin=1;
		break;
	case 4:
		tcp_header->fin=1;
		tcp_header->psh=1;
		tcp_header->urg=1;
		break;
	case 5:
		tcp_header->ack=1;  
				break;
	}
	psh.tcp_length = htons( sizeof(struct tcphdr) );
	psh.source = inet_addr("129.79.247.86");
	psh.instance = 0;
	psh.destination = inet_addr ( dst_ip );
	psh.protocol = IPPROTO_TCP;
	
	memcpy(&psh.tcp , tcp_header , sizeof (struct tcphdr));
	tcp_header->check = checksum((uint16_t*)&psh ,sizeof(struct checksum_header));
	return dgm;
}

pcap_t * pcap_filter(int src_port, int gather_timeout)
{
	pcap_t *pHandle;
	struct in_addr addr;
	int snaplen = 1518; 
	int promisc = 0; 
	bpf_u_int32 deviceip;
	bpf_u_int32 netmask;
	char * ip;
	char * mask;
	struct bpf_program fp;		
	char filterExpression[50];
	char *device;
	char errormsg[PCAP_ERRBUF_SIZE];
		

	sprintf(filterExpression,"dst port %d or ip proto \\icmp",src_port); // filter the traffic based on src port

	device = pcap_lookupdev(errormsg);
	
	if (device == NULL) {
		printf("Din't find default device: %s\n", errormsg);
		exit (1);
	}
	
	if (pcap_lookupnet(device, &deviceip, &netmask, errormsg) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", device);
		deviceip = 0;
		netmask = 0;
	}
	addr.s_addr = deviceip;
	ip = inet_ntoa(addr);
	addr.s_addr = netmask;
	mask = inet_ntoa(addr);


	pHandle = pcap_open_live(device,snaplen,promisc,gather_timeout,errormsg);

	if (pHandle == NULL) {
		printf("Cannot open device %s: %s\n", device, errormsg);
		exit (1);
	}
	
	if (pcap_compile(pHandle, &fp, filterExpression, netmask) == -1) {
		fprintf (stderr, "Cant parse filter %s: %s \n ", filterExpression, pcap_geterr(pHandle));
		exit (1);
	}

	if (pcap_setfilter(pHandle, &fp) == -1) {
		fprintf (stderr, "Cant install filter %s: %s\n", filter_exp, pcap_geterr(pHandle));
		exit (1);
	}
	return pHandle;
 }


void classify_porttype(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt) 
{
    task_i *currentTask = (task_i *)args;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct icmphdr *icmph;
	

	int iph_len;
	int tcph_len;
	char ipadd[INET_ADDRSTRLEN];
	int ethernet_size = 0;
    uint8_t src[4];
	
	if(header != NULL)
	ethernet_size = 14;

	//Get the IP Header part of this pkt , excluding the Ethernet header
	iph = (struct iphdr*)(pkt + ethernet_size);
	iph_len = (iph->ihl)* 4;
	if (iph_len < 20) {
		printf("Invalid IP header length: %u bytes\n", iph_len);
		return;
	}

	memcpy(&src,&iph->saddr,4);
	
	switch (iph->protocol) 
	{
	case 1:  
		printf("ICMP pkt\n");
		icmph = (struct icmphdr*) (pkt + ethernet_size + iph_len);
		printf("icmph->type %d\n",icmph->type);
		printf("icmph->code %d\n",icmph->code);
		if (icmph->type == 3)
		{
			switch (icmph->code) {
			case 1:
			case 2:
			case 3:  printf("Destination Unreachable - Port Opn Filtered \n");
					 break;
			case 9:
			case 10:
			case 13: printf("Destination Unreachable - Port Filtered\n");
					 break;
			
		}			
		break;			

	case 6: printf("TCP pkt\n");
		tcph = (struct tcphdr*)(pkt + ethernet_size + iph_len);
		tcph_len = tcph->doff * 4;

		if (tcph_len < 20) {
			printf("Invalid TCP header length: %u bytes\n", tcph->doff);
			return;
		}

		if (((tcph->syn) == 1) && (tcph->ack) == 1) //SYN SCAN
		{
			printf ("TCP port %d open \n",ntohs(tcph->source));
		}

		if ((tcph->rst) == 1)
		{
			if (currentTask->type_of_scan == 5)
			{	printf ("TCP port %d unfiltered\n",ntohs(tcph->source));
			}
			else
			{
				printf("TCP Port %d closed\n",ntohs(tcph->source));
			}
		}
	break;
}}}





