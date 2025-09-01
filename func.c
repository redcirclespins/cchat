#include "func.h"

// ERROR HANDLING
void error(const char* msg){
    ERROR;
    fflush(stdout);
    perror(msg);
    exit(EXIT_FAILURE);
}

void STDError(const char* msg){
    ERROR;
    fflush(stdout);
    fputs(msg,stderr);
    fputc('\n',stderr);
    exit(EXIT_FAILURE);
}

void ERRGetErrorDep(){ //deprecated!
    unsigned long err_code=ERR_get_error();
    if(err_code)
	fprintf(stderr,"SSL error: %s\n",ERR_error_string(err_code,NULL));
}

void SSLErrorVerbose(SSL_CTX* ctx,SSL *ssl,const char* func,const int ret){
    int error_code=SSL_get_error(ssl,ret);
    SSL_CTX_free(ctx);
    SSL_free(ssl);
    char err[64];

    switch(error_code){
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_ZERO_RETURN:
            strncpy(err,"SSL_ERROR_ZERO_RETURN",sizeof(err));
	    break;
        case SSL_ERROR_WANT_READ:
            strncpy(err,"SSL_ERROR_WANT_READ",sizeof(err));
	    break;
        case SSL_ERROR_WANT_WRITE:
            strncpy(err,"SSL_ERROR_WANT_WRITE",sizeof(err));
	    break;
        case SSL_ERROR_WANT_CONNECT:
            strncpy(err,"SSL_ERROR_WANT_CONNECT",sizeof(err));
	    break;
        case SSL_ERROR_WANT_ACCEPT:
            strncpy(err,"SSL_ERROR_WANT_ACCEPT",sizeof(err));
	    break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            strncpy(err,"SSL_ERROR_WANT_X509_LOOKUP",sizeof(err));
	    break;
        case SSL_ERROR_WANT_ASYNC:
            strncpy(err,"SSL_ERROR_WANT_ASYNC",sizeof(err));
	    break;
        case SSL_ERROR_WANT_ASYNC_JOB:
            strncpy(err,"SSL_ERROR_WANT_ASYNC",sizeof(err));
	    break;
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            strncpy(err,"SSL_ERROR_WANT_CLIENT_HELLO_CB",sizeof(err));
	    break;
        case SSL_ERROR_SYSCALL:
            strncpy(err,"SSL_ERROR_SYSCALL",sizeof(err));
	    break;
        case SSL_ERROR_SSL:
            strncpy(err,"SSL_ERROR_SSL",sizeof(err));
	    break;
        default:
            strncpy(err,"UNKNOWN_SSL_ERROR",sizeof(err));
	    break;
    }

    size_t final_err_size=snprintf(NULL,0,"%s:%s",func,err);
    char* final_err=malloc(final_err_size+1);
    snprintf(final_err,final_err_size,"%s:%s",func,err);
    final_err[final_err_size+1]=0;
    STDError(final_err);
}

void SSLError(const char* msg,const int num,...){
    va_list free;
    va_start(free,num);

    if(num>2||num<1)
        STDError("SSLError");
    else if(num==1)
        SSL_CTX_free(va_arg(free,SSL_CTX*));
    else if(num==2){
        SSL_CTX_free(va_arg(free,SSL_CTX*));
        SSL_free(va_arg(free,SSL*));
    }

    va_end(free);
    STDError(msg);
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

int createSocket(){
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

// MESSAGE HANDLING
int sanitizeAndVerifyReadInput(char *msg,size_t *msg_len){
    if(msg==NULL||*msg==0)
        return -1;

    size_t i=0;
    while(i<*msg_len){
        if(msg[i]=='\n'||msg[i]=='\r'||msg[i]=='\b'|| 
            msg[i]=='\t'||msg[i]=='\f'||msg[i]=='\v'||
            msg[i]=='\\'||msg[i]=='\''||msg[i]=='\"'){
            for(size_t j=i;j<*msg_len-1;j++)
                msg[j]=msg[j+1];
            msg[--(*msg_len)]=0;
        }else
            i++;
    }

    if(*msg==0)
        return -1;
    return 0;
}
// MESSAGE HANDLING
