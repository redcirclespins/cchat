#include "func.h"

#define MAXCLIENTS 2
#define MAXEVENTS  4
#define TIMEOUT    1000

#define CERTPWD "" //insert password from cert/pass
#define CERT    "cert/cert.pem"
#define KEY 	"cert/cert.key"

typedef struct epoll_event EpollEvent;
static EpollEvent events[MAXEVENTS]={0};

static volatile sig_atomic_t stop_server=0;
static void handleSigInt(int sig){
	(void)sig;
	stop_server=1;
}

typedef struct ClientSocket{
    struct sockaddr_in addr;
    char nickname[NICKLEN];
    int FD;
    SSL* ssl;
}ClientSocket;
static ClientSocket clients[MAXCLIENTS]={0};

// SSL FUNCS
static int passwordCallback(char* buf,int size,int rwflag,void* userdata){
	(void)rwflag;

    const char* password=(const char*)userdata;
    if(!password||password[0]==0){
        return 0;
	}

	const size_t pass_len=strlen(password);
	if((int)(pass_len+1)>size){
		return 0;
	}

	memcpy(buf,password,pass_len);
	buf[pass_len]=0;
    return (int)pass_len;
}
// SSL FUNCS

// SEND DATA
static void sendToOthers(const char* msg,const ClientSocket* senderSocket){
    for(int i=0;i<MAXCLIENTS;i++){
        if(clients[i].FD&&clients[i].FD!=senderSocket->FD&&clients[i].nickname[0]!=0){
            const ssize_t bytes_write=SSL_write(clients[i].ssl,msg,(int)strlen(msg));
            if(bytes_write<=0)
                SSLErrorVerbose(clients[i].ssl,"SSL_write",(int)bytes_write);
        }
    }
}

static void sendBack(const char* msg,const ClientSocket* senderSocket){
	const ssize_t bytes_write=SSL_write(senderSocket->ssl,msg,(int)strlen(msg));
	if(bytes_write<=0)
		SSLErrorVerbose(senderSocket->ssl,"SSL_write",(int)bytes_write);
}
// SEND DATA

// HANDLE CLIENTS
static void clientDisconnect(const int epFD,ClientSocket* clientSocket){
	if(clientSocket->nickname[0]!=0){
		char client_quit[MSGLEN]={0};
		client_quit[0]=TYPESERVER;
		snprintf(&client_quit[1],MSGLEN-1,"'%s' disconnected",clientSocket->nickname);
		sendToOthers(client_quit,clientSocket);
	}

	if(clientSocket->ssl){
		SSL_shutdown(clientSocket->ssl);
		SSL_free(clientSocket->ssl);
	}
    epoll_ctl(epFD,EPOLL_CTL_DEL,clientSocket->FD,NULL);
    close(clientSocket->FD);
    memset(clientSocket,0,sizeof(*clientSocket));
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
    if(accept_error<=0){
        SSLErrorVerbose(ssl,"SSL_accept",accept_error);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(clientFD);
		return;
	}

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
// HANDLE CLIENTS

// RECEIVE DATA
static void specialMessage(const uint8_t byte,ClientSocket* clientSocket){
	if(byte==BYTEONLINE){
		char online[NICKLEN*MAXCLIENTS+MAXCLIENTS*2+11]={0};
		online[0]=TYPESERVER;
		char* ptr=&online[1];

		for(int i=0;i<MAXCLIENTS;i++){
			if(clients[i].FD>0&&clients[i].FD!=clientSocket->FD&&clients[i].nickname[0]!=0){
				const size_t sz=strlen(clients[i].nickname);
				memcpy(ptr,clients[i].nickname,sz);
				ptr+=sz;
				*ptr++=',';
				*ptr++=' ';
			}
		}

		if(ptr>&online[1]){
			ptr-=2;
			strcpy(ptr," are online");
		}else
			strcpy(ptr,"none online");

		sendBack(online,clientSocket);
	}
}

static void receiveData(const int epFD,ClientSocket* clientSocket){
    char msg[MSGLEN]={0};
    SSL* ssl=clientSocket->ssl;
	const uint8_t accept_nickname=clientSocket->nickname[0]==0;

	ssize_t bytes_read=SSL_read(ssl,msg,accept_nickname?NICKLEN-1:MSGLEN-1);
	if(bytes_read<=0){
		int error_code=SSL_get_error(ssl,(int)bytes_read);
		if(error_code==SSL_ERROR_WANT_READ||error_code==SSL_ERROR_WANT_WRITE)
			return;
		if(error_code==SSL_ERROR_ZERO_RETURN){
			clientDisconnect(epFD,clientSocket);
			return;
		}
		SSLErrorVerbose(ssl,"SSL_read",(int)bytes_read);
		return;
	}
	msg[bytes_read]=0;
	//sanitize

	if(accept_nickname){
		memcpy(clientSocket->nickname,msg,NICKLEN-1);
		clientSocket->nickname[NICKLEN-1]=0;

		char new_client[MSGLEN]={0};
		new_client[0]=TYPESERVER;
		snprintf(&new_client[1],MSGLEN-1,"'%s' connected",clientSocket->nickname);
		new_client[strlen(new_client)]=0;
		sendToOthers(new_client,clientSocket);
	}else{
		if(bytes_read==1){
			specialMessage((uint8_t)msg[0],clientSocket);
			return;
		}

		char broadcast[BROADCAST]={0};
		broadcast[0]=TYPECLIENT;
		snprintf(&broadcast[1],BROADCAST-1,"%s: %s",clientSocket->nickname,msg);
		broadcast[strlen(broadcast)]=0;
		sendToOthers(broadcast,clientSocket);
	}
}
// RECEIVE DATA

int main(int argc,char** argv){
    if(argc!=2){
        ERROR("usage: %s <port>",argv[0]);
        return EXIT_FAILURE;
    }
	signal(SIGINT,handleSigInt);
    signal(SIGTERM,handleSigInt);

	//socket
    const uint16_t port=validatePort(argv[1]);
    const int FD=createSocket();
    struct sockaddr_in addr={0};
    const uint8_t optval=1;

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
    SSL_CTX_set_default_passwd_cb_userdata(ctx,(void*)CERTPWD);

	SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION);
    SSL_CTX_set_options(ctx,SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_ecdh_auto(ctx,1);

    if(SSL_CTX_use_certificate_file(ctx,CERT,SSL_FILETYPE_PEM)!=1)
        SSLError("SSL_CTX_use_certificate_file",1,ctx);
    if(SSL_CTX_use_PrivateKey_file(ctx,KEY,SSL_FILETYPE_PEM)!=1)
        SSLError("SSL_CTX_use_PrivateKey_file",1,ctx);
    if(SSL_CTX_check_private_key(ctx)!=1)
        SSLError("SSL_CTX_check_private_key",1,ctx);

	//main flow
    while(!stop_server){
        const int nFDs=epoll_wait(epFD,events,MAXEVENTS,TIMEOUT);
        if(nFDs==-1){
			if(errno==EINTR)
				continue;
            error("epoll_wait");
		}

        for(int i=0;i<nFDs;i++){
			//accept
            if(events[i].data.fd==FD){
                for(int j=0;j<MAXCLIENTS;j++){
                    if(clients[j].FD==0){
                        memset(&clients[j],0,sizeof(clients[j]));
                        acceptNewClient(epFD,FD,&epollEvent,&clients[j],ctx);
                        break;
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
                        clientDisconnect(epFD,clientSocket);
                    else if(events[i].events&EPOLLIN)
                        receiveData(epFD,clientSocket);
                    break;
                }
            }
        }
    }

	//shutdown
	for(int i=0;i<MAXCLIENTS;i++){
		if(clients[i].FD>0)
			clientDisconnect(epFD,&clients[i]);
	}
    if(FD){
		epoll_ctl(epFD,EPOLL_CTL_DEL,FD,NULL);
		close(FD);
	}
	if(ctx)
    	SSL_CTX_free(ctx);
	if(epFD)
		close(epFD);
	INFO("server terminated gracefully");
    return 0;
}
