#ifndef FUNC_H
#define FUNC_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

//+\0
#define MSGLEN 257
#define NICKLEN 33

#define NICKLENMIN 5

void error(const char*);
void STDError(const char*);
void SSLErrorVerbose(SSL_CTX*,SSL*,const char*,const int);
void SSLError(const char*,const int,...);
uint16_t validatePort(const char*);
int createSocket();
void createAddress(struct sockaddr_in*,const in_addr_t,const uint16_t);
void setNonBlocking(const int);
void setBlocking(const int);
int sanitizeAndVerifyReadInput(char*,size_t*);

#endif
