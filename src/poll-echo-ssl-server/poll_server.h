/* ***********************************************************************
 * (C) 2018 by Yiannis Bourkelis (hello@andama.org)
 * ***********************************************************************/

#ifndef POLL_SERVER_H
#define POLL_SERVER_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <iostream> //std::cout, memset
#include <vector>
#include <string.h> //memset
#include <QThread> //sleep

#ifndef WIN32
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h> //inet_ntop
#include <unistd.h> //close
#include <netinet/tcp.h> //gia to TCP_NODELAY
#else
//#define NOMINMAX
#include <stdio.h>
#include "winsock2.h"
#include <ws2tcpip.h>
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#define in_addr_t uint32_t
#pragma comment(lib, "Ws2_32.lib")
#endif

class PollServer
{
public:
    //constructors
    PollServer();

    //enums
    enum protocol {IPv4, IPv4_IPv6};

    //methods

    //starts the poll server
    void start(int server_port, protocol ip_protocol);

    //ssl specific init and cleanup
    void InitializeSSL();
    void DestroySSL();
    void create_context();
    void configure_context();

    void displayLastError(std::string description);

    #ifdef WIN32
    void disableNagleAlgorithm(SOCKET socket);
    #else
    void disableNagleAlgorithm(int socket);
    #endif

    #ifdef WIN32
    void setSocketNonBlocking(SOCKET socket);
    #else
    void setSocketNonBlocking(int socket);
    #endif

private:
    //variables
    SSL_CTX *sslctx_;
    std::map<int, SSL*> sslmap_;

};

#endif // POLL_SERVER_H
