/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>





/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000  
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define HMAC_LENGTH 32

#define STDIN 0

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/**************************************************************************
 * usage: Function for handling errors.                                         *
 **************************************************************************/
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}



/**************************************************************************
 * usage: Function for Encryption.                                         *
 **************************************************************************/
int encryptaes(unsigned char *key, unsigned char *iv, char *buffer,int *length, int option){

    //Declarations
    int otlen = 0, templen = 0;
    int inlen = *length;
    unsigned char inputbuff[BUFSIZE];
    unsigned char outputbuff[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
    

    //Buffers
    memcpy(inputbuff,buffer,inlen);
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    int z = strlen(key);

    //Encryption
    EVP_CipherInit_ex(&ctx,EVP_aes_128_cbc(),NULL,key,iv,option);
	if(!EVP_CipherUpdate(&ctx,outputbuff,&otlen,inputbuff,inlen))
		return 0;
	if(!EVP_CipherFinal_ex(&ctx,outputbuff+otlen,&templen))
		return 0;
	otlen+=templen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	
	memcpy(buffer,outputbuff,otlen);
	*length = otlen;
	return 1;
}

unsigned char* generate_hmac(unsigned char *key, unsigned char *data) {
    unsigned char* hmac;
    hmac = HMAC(EVP_sha256(), key, strlen((const char *)key), data, strlen((const char *)data), NULL, NULL);
    return hmac;
}

int compare_hmac(unsigned char *key, unsigned char *data, unsigned char *hmac) {
    unsigned char* new_hmac;
    new_hmac = generate_hmac(key, data);
		int i;
    for(i = 0; i < 32; i++) {
        if (hmac[i] != new_hmac[i]){
            return 0;
        }
    }

    return 1;
}


/**************************************************************************
 * usage: Function for Obtain Hashing.                                         *
 **************************************************************************/
void GetHash(unsigned char *key,unsigned char *buffer,int length,char *hash)
{
	HMAC_CTX msgdctx;
	unsigned char *outputhash = (char*)malloc(HMAC_LENGTH);
	int msgd_len;

	HMAC_CTX_init(&msgdctx);
	HMAC_Init_ex(&msgdctx,key,strlen(key),EVP_sha256(),NULL);
	HMAC_Update(&msgdctx,buffer,length);
	HMAC_Final(&msgdctx,outputhash,&msgd_len);
	HMAC_CTX_cleanup(&msgdctx);

	memcpy(hash,outputhash,HMAC_LENGTH);
}

/**************************************************************************
 * usage: Function for Perform Hashing.                                         *
 **************************************************************************/
void PFHMAC(unsigned char *key,unsigned char *buffer,int *length)
{
	char hash[HMAC_LENGTH],inputbuff[BUFSIZE];
	int i=0,inlen=*length;
	memcpy(inputbuff,buffer,inlen);
	GetHash(key,inputbuff,inlen,hash);
	
	//Appending MAC to the Message
	
	for(i=0;i<HMAC_LENGTH;i++)
		*(buffer+inlen+i) = hash[i];
	inlen += HMAC_LENGTH;
	*length = inlen;
}
/**************************************************************************
 * usage: Function for Comparing Hash.                                         *
 **************************************************************************/
int hashcheck(unsigned char *key,unsigned char *buffer,int *length)
{
	char hash1[HMAC_LENGTH],hash2[HMAC_LENGTH],inputbuff[BUFSIZE];
	int inlen = *length,i=0;
	inlen-=HMAC_LENGTH;
	if(inlen<=0) return 1;
	
	memcpy(inputbuff,buffer,inlen);
	memcpy(hash1,buffer+inlen,HMAC_LENGTH);
	GetHash(key,buffer,inlen,hash2);
	*length = inlen;

	return strncmp(hash1,hash2,HMAC_LENGTH);
}

/**************************************************************************
 * usage: Function for Checking Password Hash.                                         *
 **************************************************************************/
int checkpwd_hash(char *password,char *spassword)
{
	EVP_MD_CTX *msgdctx;
	char *hashname ="sha256";
	const EVP_MD *msgd;
	int msgd_len,i=0;
	unsigned char msgd_value[EVP_MAX_MD_SIZE];
	
	OpenSSL_add_all_digests();
	msgd=EVP_get_digestbyname(hashname);
	if (msgd == NULL) 
	{
        	printf("Unknown message digest %s\n", hashname);
        	exit(1);
 	}
	

	msgdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(msgdctx, msgd, NULL);
	EVP_DigestUpdate(msgdctx, password, strlen(password));
	EVP_DigestFinal_ex(msgdctx, msgd_value, &msgd_len);
	EVP_MD_CTX_destroy(msgdctx);


	char *hash_hex=(char*)malloc(2*msgd_len + 1);
	char *hex_buff = hash_hex;
	for(i=0;i<msgd_len;i++)
		hex_buff+=sprintf(hex_buff,"%02x",msgd_value[i]);
	*(hex_buff+1)='\0';
	
	fflush(stdout);
	fflush(stdout);
    //do_debug("Hash is:%s %s", hash_hex, spassword);
	return strcmp(hash_hex,spassword);
	
}


int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  size_t length;
  int maxfd;
  uint16_t nread, nwrite, plength;
  char temp[BUFSIZE];
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  socklen_t local_len = 0;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  unsigned char username[50];
  char password[50];
  unsigned char credentials[100];
  char susername[50];
  char spassword[64];
  FILE *fp;

  unsigned char key[16]="vijayanirudhavav",iv[16]={0};
  unsigned char msgd_value[EVP_MAX_MD_SIZE];
  int msgd_len=0;
  int flag =0;



  progname = argv[0];



  SSL_METHOD *meth;
  SSL_CTX *ctx;
  SSL *ssl;
  X509 *client_cert;

  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method();
  ctx = SSL_CTX_new(meth);

  if (!ctx)
  {
      ERR_print_errors_fp(stderr);
      exit(2);
  }

  // Verify the certificates and the locations:
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx, "./certs/cs.crt", NULL);
 

  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }


  if(cliserv==CLIENT){
    /* Client, try to connect to server */

    
    if (SSL_CTX_use_certificate_file(ctx, "./certs/client1.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./certs/client1.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Keys do not match. Please check the certificates.\n");
        exit(1);
    }
    else{
      printf("SSL Handshake successful.");
    }

    /* assign the destination address */
    //bzero(&local, sizeof(local));

    printf("Please Enter Your Username: ");
    fflush(stdout);
    scanf("%s",username);
    username[strlen(username)]='\0';

   printf("Please Enter Password :");
   fflush(stdout);
   scanf("%s",password);
   password[strlen(password)]='\0';

   fflush(stdout);
   int i=0;
   for(i=0;username[i] != '\0';i++)
         credentials[i]=username[i];
 
    credentials[i]='@';
   int ptr = i+1;

   for(i=0;password[i]!='\0';i++)
	credentials[ptr+i] = password[i];

   credentials[ptr+i]='\0';

	printf("Credentials are: ");
   for(i=0;credentials[i]!='\0';i++){
	printf("%c",credentials[i]);
   }


   fflush(stdout);

    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    //client verification
    int l = sendto(sock_fd,credentials,sizeof(credentials),0,(struct sockaddr *)&remote,sizeof(remote));
  if( l < 0) perror("sendto");

    /* connection request */
    // if (bind(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
    //   perror("bind()");
    //   exit(1);
    // }


    //do_debug("CLIENT: Connected to server %s\n", inet_ntoa(local.sin_addr));
    
  } else {
    /* Server, wait for connections */
if (SSL_CTX_use_certificate_file(ctx, "./certs/server1.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./certs/server1.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(1);
    }

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
      perror("bind()");
      exit(1);
    }

    if((nread =
        recvfrom(sock_fd,buffer,BUFSIZE,0,(struct sockaddr*)&local,&local_len)) <= 0) {
            perror("Error in Receiving data\n");
            exit(1);

        }

    char *p;
    p = strtok(buffer,"@");
	strcpy(username,p);
	p = strtok(NULL,"@");
	strcpy(password,p);

    if((fp = fopen("userdb.txt","r")) == NULL)
	    {
			printf("\nError opening file");
			exit(1);
		}
    while(!feof(fp))
		{
			if(fscanf(fp,"%s %s",susername,spassword)<0)
			perror("fscanf");
			fflush(stdout);
			if(strcmp(username,susername)==0)
			{
				//Verify password
				//Hash received password
				
				int check = checkpwd_hash(password,spassword);
				
				
				if(check==0)
				{
					fflush(stdout);
					flag = 1;
					fflush(stdout);
				}
				else
				{
					printf("Incorrect Password\n.PLease check the password.\n");
					exit(1);
				}
				
				
				
			}
		}
		fclose(fp);
		printf("%d\n",flag);
		if(flag == 0)
		{
			printf("User is not present\n");
			exit(1);
		}
		do_debug("SERVER: Client authenticated.\n");

    


    //do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }
  if(cliserv==CLIENT && flag == 1)
	do_debug("\nCLIENT: Connected to server %s\n", inet_ntoa(local.sin_addr));

  net_fd=sock_fd;


  
  
  /* use select() to handle two descriptors at once */
maxfd = (tap_fd > sock_fd)?tap_fd:sock_fd;

local_len = sizeof(local);
  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(sock_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);
      //length = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      //Encryption
      if(encryptaes(key,iv,buffer,&nread,1))
			{
					printf("Encrypted\n");
			}
			else
					printf("Encryption is Failed\n");

			do_debug("size of buffer before hashing %d", nread);

      //Hashing
      //PFHMAC(key,buffer,&nread);
      //do_debug("siz of buffer%d", nread);

      /* write length + packet */
      unsigned char* t = generate_hmac(key, buffer);
      memcpy(buffer + nread, t, 32);
      nwrite = sendto(net_fd, buffer, nread + 32, 0, (struct sockaddr*) &remote, remotelen);
      if (nwrite < 0) {
        perror("Sending data");
        exit(1);
      }
    //   if(nwrite = sendto(sock_fd,buffer,sizeof(buffer),0,(struct sockaddr*)&remote,sizeof(remote))< 0) {
    //         perror("Error in Sending data\n");
    //         exit(1);

    //     }
       }
      do_debug("Completed Writing Data");
      //plength = htons(nread);
      //nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
      //nwrite = cwrite(net_fd, buffer, nread);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    

    if(FD_ISSET(sock_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */
      if((nread = recvfrom(sock_fd,buffer,BUFSIZE,0,(struct sockaddr*)&remote,&remotelen)) <=0) {
            perror("Error in Reading data\n");
            exit(1);

        }

        // //check hash
        // if(hashcheck(key,buffer,&nread))
		// 	printf("HASH mismatched.\n");

        memcpy(temp, buffer, nread - 32);
      if (compare_hmac(key, temp, buffer + nread)) {
        perror("Wrong");
        exit(1);
      }
      //nread = decrypt(temp, nread - 32, key, iv, buffer);
      nread = nread - 32;

        //decrypt
        if(encryptaes(key,iv,temp,&nread,0))
		{
			printf("\n");
		}
		else
			printf("Decryption Failed\n");

        

      //nread = read_n(net_fd, (char *)&plength, sizeof(plength));
      //if(nread == 0) {
        /* ctrl-c at the other end */
       // break;
     // }

      net2tap++;

      /* read packet */
      nread = read_n(net_fd, buffer, ntohs(plength));
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}
