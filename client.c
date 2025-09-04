#include "func.h"

#define CURSORUP    "\033[A"
#define CURSORDOWN  "\033[B"
#define CURSORSTART "\r"
#define CLEARLINE   "\033[2K"

#define CMDFILE      12
#define CMDONLINE    15
#define ESC          27
#define BACKSPACE 	 127

#define MAXEVENTS 2
#define CAPATH NULL
#define CACERT "cert/cert.pem"

typedef struct epoll_event EpollEvent;
static int send_nickname=1;
static int server_quit=0;

static struct termios origTermios;
static char g_msg[MSGLEN]={0};
static size_t g_msg_len=0;

// TERMINAL-NONCANONICAL
static void ASCII(void){
    puts("           _           _       ");
    puts("          | |         | |		 ");
    puts("   ___ ___| |__   __ _| |		 ");
    puts("  / __/ __| '_ \\ / _` | __|	 ");
    puts(" | (_| (__| | | | (_| | |		 ");
    puts("  \\___\\___|_| |_|\\__,_|\\__|");
    putchar('\n');
}

static void commands(void){
    puts("available KEY commands");
    puts("+---------+-------------------+");
    puts("| ESC    | quit               |");
    puts("| CTRL+O | check users online |");
    puts("| CTRL+F | transfer a file    |");
    puts("+---------+-------------------+");
    putchar('\n');
}

static void enableRawMode(void){
	struct termios raw;
	if(tcgetattr(STDIN_FILENO,&origTermios)==-1)
        error("tcgetattr");
	raw=origTermios;
	raw.c_lflag&=(tcflag_t)~(ICANON|ECHO|ISIG);
	raw.c_cc[VMIN]=1;
	raw.c_cc[VTIME]=0;
	if(tcsetattr(STDIN_FILENO,TCSAFLUSH,&raw)==-1)
        error("tcsetattr");
}

static void disableRawMode(void){
	if(tcsetattr(STDIN_FILENO,TCSAFLUSH,&origTermios)==-1)
        error("tcsetattr");
}
// TERMINAL-NONCANONICAL

// SOCKET FUNCS
static in_addr_t validateIp(const char* ip_char){
    struct in_addr addr;
    if(inet_pton(AF_INET,ip_char,&addr)==0)
        STDError("provide valid ipv4 address");
    return addr.s_addr;
}
// SOCKET FUNCS

// RECEIVE DATA
static int receiveData(SSL* ssl){
    char msg[BROADCAST]={0};
    const ssize_t bytes_read=SSL_read(ssl,msg,BROADCAST-1);

    if(bytes_read<=0){
		int error_code=SSL_get_error(ssl,(int)bytes_read);
        if(error_code==SSL_ERROR_WANT_READ||error_code==SSL_ERROR_WANT_WRITE){
        	return 0;
		}else if(error_code==SSL_ERROR_SSL||error_code==SSL_ERROR_ZERO_RETURN){
			return -1;
		}
        SSLErrorVerbose(ssl,"SSL_read",(int)bytes_read);
		return 0;
	}
	if(send_nickname&&msg[0]!=TYPESERVER)
		return 0;

    msg[bytes_read]=0;
    printf(CLEARLINE CURSORSTART);
	if(msg[0]==TYPESERVER)
		SERVER("%s",&msg[1]); 
	else if(msg[0]==TYPECLIENT)
		printf("%s\n",&msg[1]); 
	
	printf(CLEARLINE);
	printf("--> ");
    fwrite(g_msg,1,g_msg_len,stdout);
    fflush(stdout);
	return 0;
}
// RECEIVE DATA

// SEND DATA
static int handleInput(SSL* ssl){
	char c;
	if(read(STDIN_FILENO,&c,1)<=0)
		return 0;

	if(c=='\n'){
		if(g_msg_len>0){
			const ssize_t bytes_write=SSL_write(ssl,g_msg,(int)g_msg_len);
			if(bytes_write<=0)
				SSLErrorVerbose(ssl,"SSL_write",(int)bytes_write);
			g_msg_len=0;
		}

		printf("\n--> ");
		fflush(stdout);
		send_nickname=0;
	}else if(c==ESC)
		return -1;
	else if(c==BACKSPACE){
		if(g_msg_len>0){
			g_msg_len--;
			printf("\b \b");
			fflush(stdout);
		}
	}else{
		if(g_msg_len<(send_nickname?(NICKLEN-1):(MSGLEN-1))){
			g_msg[g_msg_len++]=c;
			fwrite(&c,1,1,stdout);
			fflush(stdout);
		}
	}
	//}else if(c==CMDONLINE){
	//}else if(c==CMDFILE){
	//}
	return 0;
}
// SEND DATA

int main(int argc,char** argv){
    if(argc!=3){
        ERROR("usage: %s <server-ip-address> <port>",argv[0]);
        return EXIT_FAILURE;
    }

	//socket
    const in_addr_t ip=validateIp(argv[1]);
    const uint16_t port=validatePort(argv[2]);
    const int FD=createSocket();
    struct sockaddr_in addr={0};
    createAddress(&addr,ip,port);
    if(connect(FD,(struct sockaddr*)&addr,(socklen_t)sizeof(addr))==-1)
        error("connect");

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
    if(ctx==NULL){
        STDError("SSL_CTX_new");
	}
	SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    SSL_CTX_set_verify_depth(ctx,5);
    if(SSL_CTX_load_verify_locations(ctx,CACERT,CAPATH)==0)
        SSLError("SSL_CTX_load_verify_locations",1,ctx);

    SSL* ssl=SSL_new(ctx);
    if(ssl==NULL)
        SSLError("SSL_new",1,ctx);
    
    if(SSL_set_fd(ssl,FD)==0)
        SSLError("SSL_set_fd",2,ctx,ssl);
    const int connect_error=SSL_connect(ssl);
    if(connect_error<=0){
        SSLErrorVerbose(ssl,"SSL_connect",connect_error);
        SSLError("SSL_connect",1,ctx);
	}

	enableRawMode();
	atexit(disableRawMode);
    ASCII();
    commands();
    INFO("successfully connected");
    INFO("established TLS");
	printf("enter your nickname: ");
	fflush(stdout);

	//main flow
	setNonBlocking(FD);
    while(1){
        EpollEvent events[MAXEVENTS];
        const int rFDs=epoll_wait(epFD,events,MAXEVENTS,-1);
        if(rFDs==-1)
            error("epoll_wait");

        for(int i=0;i<rFDs;i++){
            if(events[i].data.fd==STDIN_FILENO){
                if(handleInput(ssl)==-1)
					goto shutdown;
			}else if(events[i].data.fd==FD&&(events[i].events&EPOLLIN)){
                if(receiveData(ssl)==-1){
					server_quit=1;
					goto shutdown;
				}
			}
        }
    }

shutdown:
	printf(CLEARLINE CURSORSTART);
	if(server_quit)
		INFO("server quit");
	else
		CMD("quit");
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(FD);
    return 0;
}
