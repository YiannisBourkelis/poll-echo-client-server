/* ***********************************************************************
 * (C) 2018 by Yiannis Bourkelis (hello@andama.org)
 * ***********************************************************************/

#ifndef POLL_CLIENT_H
#define POLL_CLIENT_H

#include <string>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class PollClient
{
public:
    PollClient();

    enum protocol {IPv4, IPv6};

    void ConnectToServer(std::string host, int port, protocol ip_protocol);
    void InitializeSSL();
    void DestroySSL();
    void ShutdownSSL();
    void create_context();
    void configure_context();

private:
    //variables
    SSL_CTX *sslctx_;
    SSL *cssl;
};

#endif // POLL_CLIENT_H
