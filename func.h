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

#define TYPESERVER 0x01
#define TYPECLIENT 0x02

#define MSGLEN     257 //+\0
#define NICKLEN    33 //+\0
#define BROADCAST  (1+MSGLEN-1+2+NICKLEN-1+1) //[TYPE]+%s+": "+%s\0

#define RESET "\033[0m"
#define RED   "\033[31m"
#define GREEN "\033[32m"

#define ERRORSTD    	printf("[" RED "ERROR" RESET "] ")
#define ERROR(msg,...)  fprintf(stderr,"[" RED "ERROR" RESET "] " msg "\n",##__VA_ARGS__)
#define SERVER(msg,...) printf("[" GREEN "SERVER" RESET "] " msg "\n",##__VA_ARGS__)
#define INFO(msg,...)   printf("[" GREEN "INFO" RESET "] " msg "\n",##__VA_ARGS__)
#define CMD(msg,...)    printf("[" GREEN "COMMAND" RESET "] " msg "\n",##__VA_ARGS__)

void error(const char*);
void STDError(const char*);
void ERRGetErrorDep(void); //deprecated!
void SSLErrorVerbose(SSL*,const char*,const int);
void SSLError(const char*,const int,...);
uint16_t validatePort(const char*);
int createSocket(void);
void createAddress(struct sockaddr_in*,const in_addr_t,const uint16_t);
void setNonBlocking(const int);
void setBlocking(const int);

#endif
