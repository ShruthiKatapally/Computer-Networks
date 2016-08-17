#include <stdio.h>     
#include <stdlib.h>    
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <endian.h>
#include <math.h>
#include <netdb.h>

void parseargs(int argc,char * argv[]) ;  
int main (int argc, char **argv)
{
parseargs(argc,argv);
}
void parseargs(int argc,char * argv[])
{   int option;
   	char Prefix[100];
	int index_to_option=0;
	FILE *fp;
	char * IPline = NULL;
	size_t len = 0;
	struct hostent *IP_i;
	ssize_t read;char str[100];
	char * pch;
	char *ippart;
	int prefixpart=0;
	
		
	static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"ports", required_argument, 0, 'p'},
			{"ip", required_argument, 0, 'i'},
			{"prefix", required_argument, 0, 'e'},
			{"file", required_argument, 0, 'f'},
			{"speedup", required_argument, 0, 't'},
			{"scan", required_argument, 0, 's'},
			{0, 0, 0, 0}
    };
	while ((option = getopt_long(argc, argv, "",long_options, &index_to_option)) != -1)
	{
        switch (option) {
		
		case 'h':	printf("PortScanner [OPTIONS]\n" );
			printf("  --ports        Port numbers \n");
			printf("  --ip 	   	  IP_i addresses \n");
			printf("  --prefix       IP_i prefix to scan\n");
			printf("  --file         File which has IP_i addresses \n");
			printf("  --speedup      No of threads\n");
			printf("  --scan         SYN/NULL/FIN/XMAS/ACK/UDP \n");
			exit(1);
		case 'p': 	printf("Ports to be scanned are %s\n",optarg);
					break;
		case 'i':	printf("IP_i address is :%s\n",optarg);
					break;
		case 'e':	strcpy(str,optarg);
					puts(str);
					pch = strtok (str,"/");
					int i=0;
					while (pch != NULL)
{					
					for( i=0;i<3;i++)
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
					
					int count;
					count= (int)((pow(2,(double)(32 - prefixpart))));
											
		
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
	
				for(i=0;i<count;i++)
					{
					addrhost[i] = ip[i] & netmask[i];
					addr_new[i] = addrhost[i];
					}
					
					for(i = 1; i <= count; i++)
					{
		memcpy(&ip_new,addrhost,sizeof(uint32_t));
		ip_new=htole32(ip_new)| htobe32((uint32_t)i);
		memcpy(addr_new,&ip_new,sizeof(uint32_t));
	
	if(i==4||i == 1||i==2||i==3||i == count)
		printf("addrhost of %d : %d.%d.%d.%d \n",i,addr_new[0],addr_new[1],addr_new[2],addr_new[3]);
	
	}
			break;
						
		case 'f':	fp=fopen(optarg,"r");
					while((read=getline(&IPline,&len,fp))!=-1)
					{
					IP_i=gethostbyname(IPline);
					printf("%s",IPline);
					}					
					break;
		case 't':	printf("Threads to be initialised are %s\n",optarg );
					break;
		case 's':	printf("Scans to be done are %s\n",optarg );
					break;
		}
    }
}