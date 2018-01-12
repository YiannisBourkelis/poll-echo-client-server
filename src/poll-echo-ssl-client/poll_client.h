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
    void ConnectToServer(std::string host, int port);
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
