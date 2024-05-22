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
#include <signal.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/engine.h>


/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

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

/*******Encryption********/
/***Used Open ssl's AES*/
int aesencrypt(unsigned char *plaintext, int plaintext_len, 
    unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    // Variables
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    //Initializing the Cipher Context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("Init Cipher Context");
        exit(1);
    }

    //Init of encryption cipher
    if (!(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))) {
        perror("Init Encryption Cipher");
        exit(1);
    }

    //Compute the encryption
    if (!(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))) {
        perror("Computation AES");
        exit(1);
    }
    ciphertext_len = len;

    //Finalize the encryption
    if (!(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))) {
        perror("Finalization AES");
        exit(1);
    }
    ciphertext_len += len;

    //Clean Up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
/********Decryption**********/
int aesdecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;

	/* Create and initialise the context */
  	if(!(ctx = EVP_CIPHER_CTX_new())) 
  	{
  		perror("INIT error");
  		exit(1);
  	}

  	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) 
	{
  		perror("DecryptINIT error");
  		exit(1);
	}

   	/* Provide the message to be decrypted, and obtain the plaintext output.
   	* EVP_DecryptUpdate can be called multiple times if necessary
   	*/
  	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
  		perror("DecryptUPDATE error");
  		exit(1);
    }

	plaintext_len = len;

   	/* Finalise the decryption. Further plaintext bytes may be written at
   	* this stage.
   	*/
  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
  	{
  		perror("Decryption error");
  		exit(1);
  	}

  	plaintext_len += len;

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);

  	return plaintext_len;

}

/*************HMAC************/
unsigned char* ghmac(unsigned char *key, unsigned char *data) {
    unsigned char* hmac;
    hmac = HMAC(EVP_sha256(), key, strlen((const char *)key), data, strlen((const char *)data), NULL, NULL);
    return hmac;
}

int chmac(unsigned char *key, unsigned char *data, unsigned char *hmac) {
    unsigned char* new_hmac;
    new_hmac = ghmac(key, data);
    int i;

    for(i = 0; i < 32; i++) {
        if (hmac[i] != new_hmac[i]){
            return 0;
        }
    }

    return 1;
}

void print_hex(uint8_t *buf, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}



int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
 //  uint16_t total_len, ethertype;
  char buffer[BUFSIZE], temp[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  socklen_t local_len = 0;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
  unsigned char *key = (unsigned char*)malloc(32);
  unsigned char *iv = (unsigned char*)malloc(16);

  SSL_METHOD *meth;
  SSL_CTX *ctx;
  SSL *ssl;
  X509 *client_cert;

    /* Set up the library */
  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();
  SSLeay_add_ssl_algorithms();
  OPENSSL_config(NULL);
  SSL_load_error_strings();
  meth = SSLv23_server_method();
  ctx = SSL_CTX_new(meth);
  

  /* Encryption Variables */
  BIO * bio, *bbio, *acpt, *out;
  char number[10];
  char tmpbuf[11];
  char session_change[33];
  static int ssl_session_ctx_id = 1;

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
      do_debug("Server and Client are Authenticated.");
    }



    /* assign the destination address */
    //bzero(&local, sizeof(local));
    memset(&local, 0, sizeof(local));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    // if (bind(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
    //   perror("bind()");
    //   exit(1);
    // }

    net_fd = sock_fd;
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
    
    // if (listen(sock_fd, 5) < 0){
    //   perror("listen()");
    //   exit(1);
    // }
    
    /* wait for connection request */
    // remotelen = sizeof(remote);
    // memset(&remote, 0, remotelen);
    // if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0){
    //   perror("accept()");
    //   exit(1);
    // }

    //do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }

  
  
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

      
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* write length + packet */
      nread = aesencrypt (buffer, nread, key, iv, temp);
      unsigned char* t = ghmac(key, temp);
      memcpy(temp + nread, t, 32);
      do_debug("Packet is end to end encrypted and hashed!");
      nwrite = sendto(sock_fd,temp,nread + 32,0,(struct sockaddr*)&remote,sizeof(remote));
      if(nwrite < 0) {
            perror("Error in Sending data\n");
            exit(1);

        }
      }
      tap2net++;
      do_debug("Completed Writing Data");
      do_debug("Size of Buffer:%d", buffer);
      //plength = htons(nread);
      //nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
      //nwrite = cwrite(net_fd, buffer, nread);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    

    if(FD_ISSET(sock_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */
      nread =
        recvfrom(sock_fd,buffer,BUFSIZE,0,(struct sockaddr*)&remote,&remotelen);
      if(nread <=0) {
            perror("Error in Reading data\n");
            exit(1);

        }
        do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      memcpy(temp, buffer, nread - 32);
      if (chmac(key, temp, buffer + nread)) {
        perror("Wrong");
        exit(1);
      }
      nread = aesdecrypt(temp, nread - 32, key, iv, buffer); 

    

      //nread = read_n(net_fd, (char *)&plength, sizeof(plength));
      //if(nread == 0) {
        /* ctrl-c at the other end */
       // break;
     // }

      

      /* read packet */
      //nread = read_n(net_fd, buffer, ntohs(plength));
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      net2tap++;
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}
