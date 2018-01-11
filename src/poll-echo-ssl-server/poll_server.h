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

    //methods

    //starts the poll server
    void start();

    //ssl specific init and cleanup
    void InitializeSSL();
    void DestroySSL();
    void ShutdownSSL();
    void create_context();
    void configure_context();

private:
    //variables
    SSL_CTX *sslctx_;
    std::map<int, SSL*> sslmap_;

};

#endif // POLL_SERVER_H
