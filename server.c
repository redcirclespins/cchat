#include "func.h"

#define MAXCLIENTS 2
#define MAXEVENTS 4
#define CERTPWD "" //insert password from cert/pass here
#define CERT "cert/cert.pem"
#define KEY "cert/cert.key"

typedef struct epoll_event EpollEvent;
static EpollEvent events[MAXEVENTS]={0};

typedef struct ClientSocket{
    struct sockaddr_in addr;
    char nickname[NICKLEN];
    int FD;
    SSL* ssl;
}ClientSocket;
static ClientSocket clients[MAXCLIENTS]={0};

int passwordCallback(char* buf,int size,int rwflag,void* userdata){
    char* password=(char*)userdata;
    if(!password||password[0]==0||size<strlen(password)+1)
        return 0;
    strncpy(buf,password,strlen(password)+1);
    return strlen(password);
}

static void sendToOthers(const char* msg,const ClientSocket* senderSocket,SSL_CTX* ctx){
    for(int i=0;i<MAXCLIENTS;i++){
        if(clients[i].FD&&clients[i].FD!=senderSocket->FD&&clients[i].nickname[0]!=0){
            const ssize_t bytes_write=SSL_write(clients[i].ssl,msg,strlen(msg));
            if(bytes_write<=0)
                SSLErrorVerbose(ctx,clients[i].ssl,"SSL_write",bytes_write);
        }
    }
}

static void clientDisconnect(const int epFD,ClientSocket* clientSocket,SSL_CTX* ctx){
    const size_t msg_len=snprintf(NULL,0,"'%s' disconnected",clientSocket->nickname);
    char* msg=malloc(msg_len+1);
    if(msg==NULL)
        error("malloc");
    snprintf(msg,msg_len+1,"'%s' disconnected",clientSocket->nickname); //+\0
    msg[msg_len]=0;
    sendToOthers(msg,clientSocket,ctx);
    free(msg);

    SSL_shutdown(clientSocket->ssl);
    SSL_free(clientSocket->ssl);
    epoll_ctl(epFD,EPOLL_CTL_DEL,clientSocket->FD,NULL);
    close(clientSocket->FD);
    memset(clientSocket,0,sizeof(*clientSocket));
}

static void receiveData(const int epFD,ClientSocket* clientSocket,SSL_CTX* ctx){
    char msg[MSGLEN]={0};
    SSL* ssl=clientSocket->ssl;
	const int accept_nickname=clientSocket->nickname[0]==0;

	ssize_t bytes_read=SSL_read(ssl,msg,accept_nickname?NICKLEN-1:sizeof(msg)-1);
	if(bytes_read<=0){
		int error_code=SSL_get_error(ssl,(int)bytes_read);
		if(error_code==SSL_ERROR_WANT_READ||error_code==SSL_ERROR_WANT_WRITE)
			return;
		SSLErrorVerbose(ctx,ssl,"SSL_read",bytes_read);
	}
	msg[bytes_read]=0;

	size_t msg_len=bytes_read;
	if(sanitizeAndVerifyReadInput(msg,&msg_len)==-1)
		return;
	msg[msg_len]=0;

	if(accept_nickname){
		strncpy(clientSocket->nickname,msg,strlen(msg));
		clientSocket->nickname[strlen(msg)]=0;
	}else{
		char broadcast[MSGLEN-1+2+NICKLEN-1+1]; //-\0+": "-\0+\0
		snprintf(broadcast,sizeof(broadcast),"%s: %s",clientSocket->nickname,msg);
		broadcast[strlen(broadcast)]=0;
		sendToOthers(broadcast,clientSocket,ctx);
		//fix the last char missing
	}
}

static void acceptNewClient(const int epFD,const int FD,EpollEvent* epollEvent,ClientSocket* clientSocket,SSL_CTX* ctx){
    struct sockaddr_in clientAddress;
    socklen_t sz=sizeof(clientAddress);
    const int clientFD=accept(FD,(struct sockaddr*)&clientAddress,&sz);
    if(clientFD==-1)
        error("accept");

    SSL* ssl=SSL_new(ctx);
    if(ssl==NULL)
        SSLError("SSL_new",1,ctx);
    if(SSL_set_fd(ssl,clientFD)==0)
        SSLError("SSL_set_fd",2,ctx,ssl);
    const int accept_error=SSL_accept(ssl);
    if(accept_error<=0)
        SSLErrorVerbose(ctx,ssl,"SSL_accept",accept_error);

    clientSocket->addr=clientAddress;
    clientSocket->nickname[0]=0;
    clientSocket->FD=clientFD;
    clientSocket->ssl=ssl;

    setNonBlocking(clientFD);
    epollEvent->events=EPOLLIN|EPOLLRDHUP|EPOLLHUP;
    epollEvent->data.fd=clientFD;
    if(epoll_ctl(epFD,EPOLL_CTL_ADD,clientFD,epollEvent)==-1)
        perror("epoll_ctl:clientFD");
}

int main(int argc,char** argv){
    if(argc!=2){
        ERROR;
        fflush(stdout);
        printf("usage: %s <port>\n",argv[0]);
        return EXIT_FAILURE;
    }

	//socket
    const uint16_t port=validatePort(argv[1]);
    const int FD=createSocket();
    struct sockaddr_in addr={0};
    const int optval=1;

    createAddress(&addr,(in_addr_t)0,port);
    if(setsockopt(FD,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval)))
        error("setsockopt");
    if(bind(FD,(struct sockaddr*)&addr,(socklen_t)sizeof(addr))==-1)
        error("bind");
    if(listen(FD,MAXCLIENTS)==-1)
        error("listen");
    INFO("server started on port %u",(unsigned)port);

	//epoll
    EpollEvent epollEvent;
    const int epFD=epoll_create1(0);
    if(epFD==-1)
        error("epoll_create1");
    epollEvent.events=EPOLLIN;
    epollEvent.data.fd=FD;
    if(epoll_ctl(epFD,EPOLL_CTL_ADD,FD,&epollEvent)==-1)
        error("epoll_ctl:FD");

	//ssl
    SSL_CTX* ctx=SSL_CTX_new(TLS_server_method());
    if(ctx==NULL)
        STDError("SSL_CTX_new");
    SSL_CTX_set_default_passwd_cb(ctx,passwordCallback);
    SSL_CTX_set_default_passwd_cb_userdata(ctx,(void*)&CERTPWD);

    if(SSL_CTX_use_certificate_file(ctx,CERT,SSL_FILETYPE_PEM)!=1)
        SSLError("SSL_CTX_use_certificate_file",1,ctx);
    if(SSL_CTX_use_PrivateKey_file(ctx,KEY,SSL_FILETYPE_PEM)!=1)
        SSLError("SSL_CTX_use_PrivateKey_file",1,ctx);
    if(SSL_CTX_check_private_key(ctx)!=1)
        SSLError("SSL_CTX_check_private_key",1,ctx);

	//main flow
    while(1){
        int nFDs=epoll_wait(epFD,events,MAXEVENTS,-1);
        if(nFDs==-1)
            error("epoll_wait");

        for(int i=0;i<nFDs;i++){
			//accept
            if(events[i].data.fd==FD){
                int accepted=0;
                for(int j=0;j<MAXCLIENTS;j++){
                    if(clients[j].FD==0){
                        memset(&clients[j],0,sizeof(clients[j]));
                        acceptNewClient(epFD,FD,&epollEvent,&clients[j],ctx);
                        accepted=1;
                        break;
                    }
                }
                if(accepted==0){
                    struct sockaddr_in dump_addr;
                    socklen_t dump_sz=sizeof(dump_addr);
                    int tmpFD=accept(FD,(struct sockaddr*)&dump_addr,&dump_sz);
                    if(tmpFD!=-1){
                        const char* msg="server full!";
                        write(tmpFD,msg,strlen(msg));
                        close(tmpFD);
                    }
                }
                continue;
            }

			//read + write + clientDisconnect
            for(int j=0;j<MAXCLIENTS;j++){
                ClientSocket *clientSocket=&clients[j];
                if(clientSocket->FD==0)
                    continue;
                if(events[i].data.fd==clientSocket->FD){
                    if(events[i].events&(EPOLLRDHUP|EPOLLHUP))
                        clientDisconnect(epFD,clientSocket,ctx);
                    else if(events[i].events&EPOLLIN)
                        receiveData(epFD,clientSocket,ctx);
                    break;
                }
            }
        }
    }

	//shutdown
    SSL_CTX_free(ctx);
    close(FD);
    return 0;
}
