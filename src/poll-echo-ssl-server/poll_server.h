/* ***********************************************************************
 * (C) 2018 by Yiannis Bourkelis (hello@andama.org)
 * ***********************************************************************/

#ifndef POLL_SERVER_H
#define POLL_SERVER_H

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <map>

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
