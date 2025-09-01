#include "func.h"

#define MAXEVENTS 2
#define CAPATH NULL
#define CACERT "cert/cert.pem"

typedef struct epoll_event EpollEvent;
static int send_nickname=1;

static void ASCII(){
    puts("           _           _");
    puts("          | |         | |");
    puts("   ___ ___| |__   __ _| |");
    puts("  / __/ __| '_ \\ / _` | __|");
    puts(" | (_| (__| | | | (_| | |");
    puts("  \\___\\___|_| |_|\\__,_|\\__|");
    putchar('\n');
}

static void commands(){
    puts("available commands:");
    puts("+---------+--------------------+");
    puts("| .quit   | quit               |");
    puts("| .online | check users online |");
    puts("| .file   | transfer a file    |");
    puts("+---------+--------------------+");
    putchar('\n');
}

static in_addr_t validateIp(const char* ip_char){
    struct in_addr addr;
    if(inet_pton(AF_INET,ip_char,&addr)==0)
        STDError("provide valid ipv4 address");
    return addr.s_addr;
}

static void receiveData(const int FD,SSL_CTX* ctx,SSL* ssl){
    char msg[MSGLEN]={0};
    const ssize_t bytes_read=SSL_read(ssl,msg,sizeof(msg)-1);

    if(bytes_read<=0){
		int error_code=SSL_get_error(ssl,(int)bytes_read);
        if(error_code==SSL_ERROR_WANT_READ||error_code==SSL_ERROR_WANT_WRITE)
        	return;
        SSLErrorVerbose(ctx,ssl,"SSL_read",bytes_read);
	}

    msg[bytes_read]=0;
    printf("\33[2K\r%s\n",msg); //clear the whole line + printf msg
    //add displaying the unfinished line
    fflush(stdout);
}

static void handleInput(const int FD,SSL_CTX* ctx,SSL* ssl){
    char msg[MSGLEN]={0};

	fgets(msg,send_nickname?NICKLEN:sizeof(msg),stdin);
    size_t msg_len=strlen(msg);
    msg[msg_len]=0;

    if(msg[msg_len-1]!='\n'){
        int c;
        while((c=getchar())!='\n'&&c!=EOF);
    }
    if(sanitizeAndVerifyReadInput(msg,&msg_len)==-1)
        return;
    msg[msg_len]=0;

    if(send_nickname==0&&strcmp(msg,".quit")==0){
        SSL_CTX_free(ctx);
        SSL_free(ssl);
        close(FD);
        exit(0);
    }
    const ssize_t bytes_write=SSL_write(ssl,msg,msg_len);
    if(bytes_write<=0)
        SSLErrorVerbose(ctx,ssl,"SSL_write",bytes_write);
}

/*
static void handleSSLHandshake(const int FD,SSL_CTX* ctx,SSL* ssl){
    //SSL_set_connect_state
    //SSL_set_accept_state
    int err=SSL_do_handshake(ssl);
    if(err==1)
        puts("SSL handshake completed");
    if(err<=0)
        SSLErrorVerbose(ctx,ssl,err);
}
*/

int main(int argc,char** argv){
    if(argc!=3){
        ERROR;
        fflush(stdout);
        printf("usage: %s <server-ip-address> <port>\n",argv[0]);
        return EXIT_FAILURE;
    }

	//socket
    const in_addr_t ip=validateIp(argv[1]);
    const uint16_t port=validatePort(argv[2]);
    ASCII();
    commands();
    const int FD=createSocket();
    struct sockaddr_in addr={0};
    createAddress(&addr,ip,port);
    if(connect(FD,(struct sockaddr*)&addr,(socklen_t)sizeof(addr))==-1)
        error("connect");
    INFO("successfully connected");

	//epoll
    EpollEvent epollEvent;
    const int epFD=epoll_create1(0);
    if(epFD==-1)
        error("epoll_create1");

    epollEvent.events=EPOLLIN;
    epollEvent.data.fd=FD;
    if(epoll_ctl(epFD,EPOLL_CTL_ADD,FD,&epollEvent)==-1)
        error("epoll_ctl:FD");

    epollEvent.events=EPOLLIN;
    epollEvent.data.fd=STDIN_FILENO;
    if(epoll_ctl(epFD,EPOLL_CTL_ADD,STDIN_FILENO,&epollEvent)==-1)
        error("epoll_ctl:STDIN_FILENO");

	//ssl
    SSL_CTX* ctx=SSL_CTX_new(TLS_client_method());
    if(ctx==NULL)
        STDError("SSL_CTX_new");
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    SSL_CTX_set_verify_depth(ctx,5);
    if(SSL_CTX_load_verify_locations(ctx,CACERT,CAPATH)==0)
        SSLError("SSL_CTX_load_verify_locations",1,ctx);

    SSL* ssl=SSL_new(ctx);
    if(ssl==NULL)
        SSLError("SSL_new",1,ctx);

    /*
    if(SSL_set_tlsext_host_name(ssl,argv[1])==0)
        SSLError("SSL_set_tlsext_host_name",2,ctx,ssl);
    SSL_set_hostflags(ssl,X509_CHECK_FLAG_NO_WILDCARDS);
    if(SSL_set1_host(ssl,argv[1])==0)
        SSLError("SSL_set1_host",2,ctx,ssl);
    */
    
    if(SSL_set_fd(ssl,FD)==0)
        SSLError("SSL_set_fd",2,ctx,ssl);
    const int connect_error=SSL_connect(ssl);
    if(connect_error<=0)
        SSLErrorVerbose(ctx,ssl,"SSL_connect",connect_error);
    INFO("established TLS");

	//main flow
	if(send_nickname==1){
		send_nickname=0;
		printf("enter your nickname: ");
		fflush(stdout);
	}
	setNonBlocking(FD);

    while(1){
        EpollEvent events[MAXEVENTS];
        const int rFDs=epoll_wait(epFD,events,MAXEVENTS,-1);
        if(rFDs==-1)
            error("epoll_wait");

        for(int i=0;i<rFDs;i++){
            if(events[i].data.fd==STDIN_FILENO){
				if(send_nickname==0){
					printf("--> ");
					fflush(stdout);
				}
                handleInput(FD,ctx,ssl);
			}else if(events[i].data.fd==FD&&(events[i].events&EPOLLIN))
	    		receiveData(FD,ctx,ssl);
        }
    }

	//shutdown
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(FD);

    return 0;
}
