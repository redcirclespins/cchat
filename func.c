#include "func.h"

// ERROR HANDLING
void error(const char* msg){
    ERRORSTD;
	fflush(stdout);
	perror(msg);
    exit(EXIT_FAILURE);
}

void errorVerbose(const char* msg){
    ERRORSTD;
	fflush(stdout);
	perror(msg);
}

void STDError(const char* msg){
    ERROR("%s",msg);
    exit(EXIT_FAILURE);
}

void STDErrorVerbose(const char* msg){
    ERROR("%s",msg);
}

void ERRGetErrorDep(void){ //deprecated!
    const unsigned long err_code=ERR_get_error();
    if(err_code){
		const char* err=ERR_error_string(err_code,NULL);
		ERROR("%s",err);
	}
}

void SSLError(const char* msg,const int num,...){
    va_list args;
    va_start(args,num);

    if(num==1){
		SSL_CTX* ctx=va_arg(args,SSL_CTX*);
		if(ctx)
			SSL_CTX_free(ctx);
	}else if(num==2){
		SSL_CTX* ctx=va_arg(args,SSL_CTX*);
        SSL* ssl=va_arg(args,SSL*);
        if(ssl){
			SSL_shutdown(ssl);
			SSL_free(ssl);
		}if(ctx)
			SSL_CTX_free(ctx);
    }else
        STDError("SSLError: invalid usage");

    va_end(args);
    STDError(msg);
}

void SSLErrorVerbose(SSL *ssl,const char* func,const int ret){
    const int error_code=SSL_get_error(ssl,ret);
    char errbuf[64]={0};

	switch(error_code){
		case SSL_ERROR_NONE:
			strncpy(errbuf,"SSL_ERROR_NONE",sizeof(errbuf)-1);
			break;
        case SSL_ERROR_ZERO_RETURN:
			strncpy(errbuf,"SSL_ERROR_ZERO_RETURN",sizeof(errbuf)-1);
			break;
		case SSL_ERROR_WANT_READ:
			strncpy(errbuf,"SSL_ERROR_WANT_READ",sizeof(errbuf)-1);
			break;
		case SSL_ERROR_WANT_WRITE:
			strncpy(errbuf,"SSL_ERROR_WANT_WRITE",sizeof(errbuf)-1);
			break;
		case SSL_ERROR_WANT_CONNECT:
			strncpy(errbuf,"SSL_ERROR_WANT_CONNECT",sizeof(errbuf)-1);
			break;
        case SSL_ERROR_WANT_ACCEPT:
			strncpy(errbuf,"SSL_ERROR_WANT_ACCEPT",sizeof(errbuf)-1);
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			strncpy(errbuf,"SSL_ERROR_WANT_X509_LOOKUP",sizeof(errbuf)-1);
			break;
		case SSL_ERROR_WANT_ASYNC:
			strncpy(errbuf,"SSL_ERROR_WANT_ASYNC",sizeof(errbuf)-1);
			break;
		case SSL_ERROR_WANT_ASYNC_JOB:
			strncpy(errbuf,"SSL_ERROR_WANT_ASYNC_JOB",sizeof(errbuf)-1);
			break;
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
			strncpy(errbuf,"SSL_ERROR_WANT_CLIENT_HELLO_CB",sizeof(errbuf)-1);
			break;
		case SSL_ERROR_SYSCALL:
			strncpy(errbuf,"SSL_ERROR_SYSCALL",sizeof(errbuf)-1);
			break;
		case SSL_ERROR_SSL:
			strncpy(errbuf,"SSL_ERROR_SSL",sizeof(errbuf)-1);
			break;
		default:
			strncpy(errbuf,"UNKNOWN_SSL_ERROR",sizeof(errbuf)-1);
			break;
    }
    errbuf[sizeof(errbuf)-1]=0;

	char final_err[128]={0};
    snprintf(final_err,sizeof(final_err),"%s:%s",func,errbuf);
    ERROR("%s",final_err);
}
// ERROR HANDLING

// SOCKET FUNCS
uint16_t validatePort(const char* port_char){
    for(int i=0;port_char[i];i++){
        if(isdigit((unsigned char)port_char[i])==0)
            STDError("provide valid port (1-65535)");
    }
    unsigned long port=strtoul(port_char,NULL,10);
    if(port==0||port>65535)
        STDError("provide valid port (1-65535)");
    return (uint16_t)port;
}

int createSocket(void){
    int FD=socket(AF_INET,SOCK_STREAM,0);
    if(FD==-1)
        error("socket failed");
    int opt=1;
    if(setsockopt(FD,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt))==-1)
        error("setsockopt failed");
    return FD;
}

void createAddress(struct sockaddr_in* addr,const in_addr_t ip,const uint16_t port){
    addr->sin_family=AF_INET;
    addr->sin_port=htons(port);
    if(ip==0)
        addr->sin_addr.s_addr=INADDR_ANY;
    else
        addr->sin_addr.s_addr=ip;
}

void setNonBlocking(const int FD){
	if(fcntl(FD,F_SETFL,fcntl(FD,F_GETFL,0)|O_NONBLOCK)==-1)
        error("fcntl:NONBLOCKING");
}

void setBlocking(const int FD){
	if(fcntl(FD,F_SETFL,fcntl(FD,F_GETFL,0)&~O_NONBLOCK)==-1)
        error("fcntl:BLOCKING");
}
// SOCKET FUNCS
