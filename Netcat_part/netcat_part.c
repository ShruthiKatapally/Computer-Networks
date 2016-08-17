#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h> 			//add -lssl to compile

#define BUF_LEN 1024				
#define KEYLEN 16

static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e };

typedef struct nc_args
{
  struct sockaddr_in destaddr; 		//destination address
  unsigned short port; 				//destination port
  unsigned short listen; 			//listen flag
  int n_bytes; 						//number of bytes to be sent
  int offset; 						//offset of file
  int verbose; 						//verbose output 
  int message_mode; 				//message mode activation
  int n_bytes_mode;					//number of bytes to be read
  int offset_mode;					//offset 
  char * message; 					//array to store the message if message mode is activated
  char * filename; 					//stores filename
}nc_args_t;

void usage(FILE * file)
{
	  fprintf(file,"netcat_part [OPTIONS]  dest_ip [file] \n"
        "\t -h           	\t\t Print this help screen\n"
        "\t -v           	\t\t Verbose output\n"
	   "\t  -m \"MSG\"   	\t\t Send the message specified on the 					command line. \n"
	   "\t\t Warning: if you specify this option, you do not 					  specify a file. \n"
        "\t -p port      	\t\t Set the port to connect on (dflt: 					    6767)\n"
        "\t -n bytes     	\t\t Number of bytes to send, defaults 					    whole file\n"
        "\t -o offset    	\t\t Offset into file to start sending						\n"
        "\t -l           	\t\t Listen on port instead of 							connecting and write output to file\n"
        "                	\t\t and dest_ip refers to which ip to 					 bind to (dflt: localhost)\n");
}



void parse_args(nc_args_t * nc_args, int argc, char * argv[])
{
  int ch; 
  struct hostent * hostinfo;
  //default values
  nc_args->n_bytes = 0;
  nc_args->offset = 0;
  nc_args->listen = 0;
  nc_args->port = 6767;
  nc_args->verbose = 0;
  nc_args->message_mode = 0;
  nc_args->n_bytes_mode=0;
  nc_args->offset_mode=0;
  printf("In Parse_args\n");
  while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1) 
  {
	switch (ch) 
	{
    case 'h': 
		usage(stdout);
		printf("Help option");
		exit(0);
    break;
    case 'l': 
		nc_args->listen = 1;
		printf("l option\n");
	break;
    case 'p': 
		nc_args->port = atoi(optarg);
		printf("p option\n");
    break;
    case 'o':
		nc_args->offset_mode =1;
		nc_args->offset = atoi(optarg);
		printf("o option\n");     
	break;
    case 'n':	
		nc_args->n_bytes_mode = 1;
		nc_args->n_bytes = atoi(optarg);
		printf("n option\n");      
	break;
    case 'v':
		nc_args->verbose = 1;
		printf("V option\n");      
	break;
    case 'm':
		nc_args->message_mode = 1;
		nc_args->message = malloc(strlen(optarg)+1);
		strncpy(nc_args->message, optarg, strlen(optarg)+1);
		printf("M option\n");      
	break;
    default:
		fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
		usage(stdout);
		exit(1);
    }
  }
 
  argc -= optind;
  argv += optind;
 
  if (argc < 2 && nc_args->message_mode == 0)
  {
    fprintf(stderr, "ERROR: Require ip and file\n\n");
    usage(stderr);
    exit(1);
  } 
  else if (argc != 1 && nc_args->message_mode == 1)
  {
    fprintf(stderr, "ERROR: Require ip send/recv from when in message mode\n\n");
    usage(stderr);
    exit(1);
  }
 
  if(!(hostinfo = gethostbyname(argv[0])))
  {
    fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
    usage(stderr);
    exit(1);
  }

  nc_args->destaddr.sin_family = hostinfo->h_addrtype;
  bcopy((char *) hostinfo->h_addr,
        (char *) &(nc_args->destaddr.sin_addr.s_addr),
        hostinfo->h_length);
   
  nc_args->destaddr.sin_port = htons(nc_args->port);
   
 if (nc_args->message_mode == 0)
{	
	nc_args->filename = malloc(strlen(argv[1])+1);
	strncpy(nc_args->filename,argv[1],strlen(argv[1])+1);
}
	printf("Parse args end\n");
	return;
}

//Function initialize_client

void initialize_client(int socketfd,nc_args_t *nc_args)
	{       
		int n,l;	
     	struct sockaddr_in destaddr;
		//Create socket
		socketfd=socket(AF_INET,SOCK_STREAM,0);
	if(socketfd<0)
	{
		printf("Socket not created \n");
		exit(1);
	}
	if(nc_args->verbose)
	{
		printf("Socket creation is successful \n");
	}
	//Connection establishment
	if(connect(socketfd,(struct sockaddr *)(&nc_args->destaddr), 	sizeof(nc_args->destaddr))<0)
	{
		printf("Server is not connected \n");
		exit(1);
	}
	if(nc_args->verbose)
	{
		printf("socket is connection is successful \n");
	}
	printf("Before Sending \n");
	l=strlen(nc_args->message);
	printf("Size of message is %d \n",l);
	n=send(socketfd,nc_args->message,strlen(nc_args->	message),0);
	printf("number of bytes sent is %d \n",n);
	printf("String %s sent to server \n",nc_args->message);
    	//Closing the socket
	close(socketfd);
	} // end of initialize_client function

	//Function initialize_clientfile
void initialize_clientfile(int socketfd,nc_args_t *nc_args)
	{	
	int n;
   	struct sockaddr_in destaddr;
	FILE * clientfile; // Creating a file pointer
	char inputbuf[BUF_LEN];	
	socketfd=socket(AF_INET,SOCK_STREAM,0);
	if(socketfd<0)
		{
			printf("socket not created \n");
			exit(1);
		}
	if(nc_args->verbose)
		{
			printf("socket creation is successful \n");
		}
	if(connect(socketfd,(struct sockaddr *)(&nc_args->	destaddr),sizeof(nc_args->destaddr))<0)
		{
			printf("Server is not connected \n");
			exit(1);
		}
	if(nc_args->verbose)
		{
			printf("socket connection is successful \n");
		}
		clientfile = fopen(nc_args->filename,"r");
		printf("%s \n",nc_args->filename);
	

    if(clientfile == NULL)
		{
			printf("File cannot be opened\n");
		}
	if(nc_args->verbose)
		{	
			printf("File opened successfully\n");
		}
	while(!feof(clientfile))
		{
			memset(&inputbuf,0,BUF_LEN);
			n=read(fileno(clientfile),&inputbuf,BUF_LEN);
			if(feof(clientfile))
			break;
			else if (n == 0)
			break;
			printf("bytes read is %d \n",n);
			printf("Finished reading from File - %s 					\n",inputbuf);
			fflush(clientfile);
			printf("Before Sending \n");
			n=send(socketfd,inputbuf,n,0);	
			printf("number of bytes sent is %d \n",n);
			printf("After Sending \n");
		}
	fclose(clientfile);
	//Closing the Socket
	close(socketfd);

     }//end of initialize_clientfile function

//Function initialize_clientfilebytes
void initialize_clientfilebytes(int socketfd,nc_args_t *nc_args)
       {	
		int n,yettoread;
		struct sockaddr_in destaddr;
		FILE * clientfile;
		char inputbuf[BUF_LEN];
		socketfd=socket(AF_INET,SOCK_STREAM,0);
		if(socketfd<0)
		{
			printf("socket not created \n");
			exit(1);
		}
		if(nc_args->verbose)
		{
			printf("socket creation is successful \n");
		}

		if(connect(socketfd,(struct sockaddr *)(&nc_args->			destaddr), sizeof(nc_args->destaddr))<0)
		{
			printf("Server is not connected \n");
			exit(1);
		}
		if(nc_args->verbose)
		{
			printf("Server connection is successful \n");
		}
		clientfile = fopen(nc_args->filename,"r");
		printf("%s \n",nc_args->filename);
		
		if(clientfile == NULL)
		{
			printf("File cannot be opened\n");
		}
		if(nc_args->verbose)
		{	
			printf("File opened successfully\n");

		}
		yettoread = nc_args->n_bytes;
		while( yettoread > 0)
		{
			memset(&inputbuf,0,BUF_LEN);
			n=read(fileno(clientfile),&inputbuf,nc_args->				n_bytes);
			if(feof(clientfile))
			break;
			else if(n == 0)
			break;
			yettoread-=n;
			printf("bytes read is %d \n",n);
			printf("yet to read is %d \n",yettoread);
			printf("Finished reading from File - %s 					\n",inputbuf);
			fflush(clientfile);
			printf("Before Sending \n");
			n=send(socketfd,inputbuf,n,0);	
			printf("number of bytes sent is %d \n",n);
			printf("After Sending \n");
		}
			fclose(clientfile);
			//Closing the Socket
			close(socketfd);
        	} // end of initialize_clientfilebytes function
//Function initialize_clientfileoffset
void initialize_clientfileoffset(int socketfd,nc_args_t *nc_args)
    {	
    int n,fileSize,l;
	long ftellnumber;
    struct sockaddr_in destaddr;
	FILE * clientfile;
	char inputbuf[BUF_LEN];
	socketfd=socket(AF_INET,SOCK_STREAM,0);
	if(socketfd<0)
		{
			printf("socket not created \n");
			exit(1);
		}
	if(nc_args->verbose)
		{
			printf("socket creation is successful \n");
		}

	if(connect(socketfd,(struct sockaddr *)(&nc_args->destaddr), 	sizeof(nc_args->destaddr))<0)
		{
			printf("Server is not connected \n");
			exit(1);
		}
		if(nc_args->verbose)
		{
			printf("Server connection is successful \n");
		}
	
		clientfile = fopen(nc_args->filename,"r");
		l=fseek(clientfile,nc_args->offset,SEEK_CUR);
		printf("Seek value %d \n",&l); 
		ftellnumber=ftell(clientfile);
		printf("The ftell is %d \n",&ftellnumber);
		printf("%s \n",nc_args->filename);
		
		if(clientfile == NULL)
		{
			printf("File cannot be opened\n");
		}
		if(nc_args->verbose)

		{	
			printf("File opened successfully\n");

		}
		while(!feof(clientfile))
		{	memset(&inputbuf,0,BUF_LEN);
			n=read(fileno(clientfile),&inputbuf,BUF_LEN);
			if(feof(clientfile))
			break;
			else if (n == 0)
			break;
			printf("bytes read is %d \n",n);
			printf("Finished reading from File - %s 					\n",inputbuf);
			fflush(clientfile);
			printf("Before Sending \n");
			n=send(socketfd,inputbuf,n,0);	
			printf("number of bytes sent is %d \n",n);
			printf("After Sending \n");
		}
			fclose(clientfile);
			close(socketfd);
       }// end of initialize_clientfileoffset function

// Function initialize_clientfileoffsetbytes
void initialize_clientfileoffsetbytes(int socketfd,nc_args_t *nc_args)
{
	int yettoread,n,fileSize,l,temp;
	long ftellnumber;
   	struct sockaddr_in destaddr;
	FILE * clientfile;
	char inputbuf[BUF_LEN];
	socketfd=socket(AF_INET,SOCK_STREAM,0);
	if(socketfd<0)
		{
			printf("socket not created \n");
			exit(1);
		}
	if(nc_args->verbose)
		{
			printf("socket creation is successful \n");
		}
	if(connect(socketfd,(struct sockaddr *)(&nc_args->destaddr), 	sizeof(nc_args->destaddr))<0)
		{
			printf("Server is not connected \n");
			exit(1);
		}
	if(nc_args->verbose)
		{
			printf("Server connection is successful \n");
		}
		
		clientfile = fopen(nc_args->filename,"r");
		l=fseek(clientfile,nc_args->offset,SEEK_CUR);
		printf("Offset value %d \n",nc_args->offset); 
		printf("Seek value %d \n",&l); 
		ftellnumber=ftell(clientfile);
		printf("The ftell is %d \n",&ftellnumber);
		printf("%s \n",nc_args->filename);
		if(clientfile == NULL)
		{
			printf("File cannot be opened\n");
		}
		if(nc_args->verbose)

		{	
			printf("File opened successfully\n");

		}

		yettoread = nc_args->n_bytes;
		printf("N value is %d \n",nc_args->n_bytes);
		
		while( yettoread > 0)
		{
			printf("yettoread value is %d \n",yettoread); 
			memset(&inputbuf,0,BUF_LEN);
			n=read(fileno(clientfile),&inputbuf,BUF_LEN);
			printf("read's n %d \n",n); 
			if(feof(clientfile))
			break;
			else if (n == 0)
			break;
			temp=n;
			n=yettoread;
			yettoread-=temp;
			printf("yettoread value is %d \n",yettoread);
			printf("Finished reading from File - %s 					\n",inputbuf);
			fflush(clientfile);
			printf("Before Sending \n");
			n=send(socketfd,inputbuf,n,0);	
			printf("number of bytes sent is %d \n",n);
			printf("After Sending \n");
						
		}
			fclose(clientfile);
			//Closing the Socket
			close(socketfd);
       } // end of initialize_clientfileoffsetbytes function

// Function initialize_server
void initialize_server(nc_args_t *nc_args)
       {
	int socklisten,bindreturn; 
	struct sockaddr_in destaddr,soccliaddr;
	int k,n,socketfd,connsock,soccliaddr_len,stilltoread;
	FILE *serverfile;
	char buf[BUF_LEN];
	int optval = 1;
	printf("In Server\n");
	socklisten=socket(AF_INET,SOCK_STREAM,0);
	if(socklisten<0)
	{
		perror("SOCKET LISTENING ERROR\n");
		exit(1);
	}
 	if(nc_args->verbose)

	{
		printf("Socket Listening..\n");
	}
	setsockopt(socklisten, SOL_SOCKET, SO_REUSEPORT, &optval, 	sizeof(optval));
	
	bindreturn=bind(socklisten,(struct sockaddr*)&(nc_args->	destaddr),sizeof(struct sockaddr));
	
      if(bindreturn==-1)
		{ 
		perror("\nError in binding\n");
		exit(1);
		}
	if(nc_args->verbose)
	{
		printf("Bind successful \n");
	}
	listen(socklisten,5);
	connsock=accept(socklisten,(struct sockaddr *)&soccliaddr,	&soccliaddr_len);
	if(connsock<0)
	{
		printf("Accepting error..\n");
	}
	if(nc_args->verbose)
	{
		printf("Accepted \n");
	}
		printf("trying to receive message..\n");
		serverfile=fopen(nc_args->filename,"w");
		printf("%s",nc_args->filename);
		printf("file opened \n");
		memset(&buf,0,BUF_LEN);
		while((n=read(connsock,buf,1024)) > 0)
	{		
			printf("Bytes read is %d",n);
			printf("Reading..\n");
			buf[n] = '\0';
			printf("Finished reading from socket - %s 					\n",buf);
			printf("Writing..\n");
			fprintf(serverfile,"%s",buf);
			fflush(serverfile);
	}
			fflush(serverfile);
			printf("Written to file");
			fclose(serverfile);
			close(connsock);
			close(socklisten);
       }//end of initialize_server function 

	int main(int argc, char * argv[])
    	{
	nc_args_t nc_args;	
	char input[BUF_LEN];
	int sockfd;
	printf("In main - calling parse_Args \n");
	parse_args(&nc_args, argc, argv);
	printf("nc_args.listen value is %d",nc_args.listen);
	if(nc_args.listen == 1)
  		{
		initialize_server(&nc_args);
	    	}
		else
		{
	if( nc_args.message_mode == 1 )
		{
	 	initialize_client(sockfd,&nc_args);
		}
		else
		{
	if( nc_args.offset_mode == 0 && nc_args.n_bytes_mode == 0)
		{
		initialize_clientfile(sockfd,&nc_args);
		}
	else
	{ 
	if(nc_args.offset_mode == 1 && nc_args.n_bytes_mode== 1)
      	{		
		initialize_clientfileoffsetbytes(sockfd,&nc_args);
		}

	else if( nc_args.n_bytes_mode == 1) 							{
	initialize_clientfilebytes(sockfd,&nc_args);
		}
	else if (nc_args.offset_mode == 1)
	     {
	initialize_clientfileoffset(sockfd,&nc_args);
	     }
	   }
      }
    }
        return 0;
    }
    
