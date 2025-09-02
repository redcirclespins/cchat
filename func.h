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
#include <termios.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define MSGLEN     257 //\0
#define NICKLEN    33  //\0
#define NICKLENMIN 5
#define BROADCAST  MSGLEN+NICKLEN+1 //%s: %s\0

#define RESET "\033[0m"
#define RED   "\033[31m"
#define GREEN "\033[32m"

#define INFO(msg,...)     printf("[" GREEN "INFO" RESET "] " msg "\n",##__VA_ARGS__)
#define ERRORSTD(msg,...) printf("[" RED "ERROR" RESET "] " msg "\n",##__VA_ARGS__)
#define ERROR 			  printf("[" RED "ERROR" RESET "] ")

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
