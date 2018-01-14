/* ***********************************************************************
 * (C) 2018 by Yiannis Bourkelis (hello@andama.org)
 * ***********************************************************************/

#include "poll_client.h"

#ifdef WIN32
//#define NOMINMAX
#include <stdio.h>
#include "winsock2.h"
#include <ws2tcpip.h>
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#define in_addr_t uint32_t
#pragma comment(lib, "Ws2_32.lib")

#else
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> //gia to TCP_NODELAY
#endif

#include <iostream>
#include "vector"
#include <errno.h>
#include <thread>
#include <memory>
#include <QThread>

PollClient::PollClient()
{
}

void PollClient::InitializeSSL()
{
    SSL_load_error_strings();
    SSL_library_init(); //xreiazetai gia to linux logo bug se palaioteres ekdoseis openssl
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

void PollClient::DestroySSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

void PollClient::ShutdownSSL()
{
    SSL_shutdown(cssl);
    SSL_free(cssl);
}

void PollClient::create_context()
{
    const SSL_METHOD *method;

    method = TLSv1_2_client_method();

    sslctx_ = SSL_CTX_new(method);
    if (!sslctx_) {
    perror("Unable to create SSL context");
    exit(EXIT_FAILURE);
    }
}

void PollClient::ConnectToServer(std::string host, int port, protocol ip_protocol)
{
    int    bytes_recv;
    struct sockaddr_in  serv_addr4;
    struct sockaddr_in6 serv_addr6;
    struct hostent *SERVER;
    int socketfd = 0;

    #ifdef WIN32
    // Initialize Winsock
    int iResult;
    WSADATA wsaData;
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << std::endl;
        return;
    }
    #endif

    #ifndef WIN32
    //gia na mi prokaleitai crash otan paw na grapsw se socket pou exei kleisei
    //http://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
    signal(SIGPIPE, SIG_IGN);
    #endif

    InitializeSSL();
    SSL_library_init();
    create_context();

    //SERVER = gethostbyname("mailgate.filoxeni.com");
    //SERVER = gethostbyname("andamaproxy-us-west.filoxeni.com");
    //SERVER = gethostbyname("andamaproxy-ro-timisoara.filoxeni.com");
    SERVER = gethostbyname(host.data());

    if (ip_protocol == PollClient::IPv4){
        socketfd = socket(AF_INET, SOCK_STREAM, 0);
        memset((char *) &serv_addr4,0, sizeof(serv_addr4));;
        serv_addr4.sin_family = AF_INET;

        bcopy((char *)SERVER->h_addr,
             (char *)&serv_addr4.sin_addr,
             SERVER->h_length);
        serv_addr4.sin_port = htons(port);
    } else {
        socketfd = socket(AF_INET6, SOCK_STREAM, 0);
        memset((char *) &serv_addr6,0, sizeof(serv_addr6));;
        serv_addr6.sin6_family = AF_INET6;

        bcopy((char *)SERVER->h_addr,
             (char *)&serv_addr6.sin6_addr,
             SERVER->h_length);
        serv_addr6.sin6_port = htons(port);
    }

    #ifdef WIN32
    if (socketfd == INVALID_SOCKET) {
    #else
    if (socketfd < 0){
    #endif
        perror("ERROR opening socket");
        DestroySSL();
        return;
    }

    if (SERVER == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
    #ifdef WIN32
        closesocket(socketfd);
    #else
        close(socketfd);
    #endif
        DestroySSL();
        return;
    }

    //serv_addr.sin_addr.s_addr=inet_addr("192.168.32.20"); // <------------- local server

    //SIMANTIKO: kanw disable to nagle algorithm. meiwnei to latency.
    int flag = 1;
    setsockopt(socketfd,      /* socket affected */
                            IPPROTO_TCP,     /* set option at TCP level */
                            TCP_NODELAY,     /* name of option */
                            (char *) &flag,  /* the cast is historical cruft */
                            sizeof(int));    /* length of option value */

     //connect to server
    int conres = -1;
    if (ip_protocol == PollClient::IPv4){
        conres = ::connect(socketfd, (struct sockaddr *) &serv_addr4, sizeof(serv_addr4));
    } else {
        conres = ::connect(socketfd, (struct sockaddr *) &serv_addr6, sizeof(serv_addr6));
    }

    if (conres < 0)
    {
        std::cout << "ERROR connecting. result: " << conres << "\n";
        #ifdef WIN32
        std::cout << "ERROR connecting. result: " << WSAGetLastError() << "\n";
        closesocket(socketfd);
        #else
        perror("ERROR connecting");
        close(socketfd);
        #endif
        DestroySSL();
        return;
     }

    cssl = SSL_new(sslctx_);
    SSL_set_fd(cssl, socketfd);
    int conres2 = SSL_connect(cssl);
    if (conres2 < 0)
    {
        int mysse = SSL_get_error(cssl, conres2);
        std::cout << "ERROR connecting. SSL error result: " << mysse << "\n";
        std::cout << "ERROR connecting. result: " << conres << "\n";
        perror("ERROR connecting");
        #ifdef WIN32
        closesocket(socketfd);
        #else
        close(socketfd);
        #endif
        ShutdownSSL();
        DestroySSL();
        return;
     }

    struct sockaddr_in local_address;
    socklen_t addr_size = sizeof(local_address);
    getsockname(socketfd, (struct sockaddr *) &local_address, &addr_size);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(local_address.sin_addr), str, INET_ADDRSTRLEN);
    std::cout << "client local port after proxy connect:" << local_address.sin_port << ", IP:" << str << std::endl;

    while(true){
        //std::string input_str;
        //std::cin >> input_str;
        std::vector<char> buff(1024);
        std::string input_str = "weddwedwed";

        int bytes_written = SSL_write(cssl, input_str.data(), input_str.size());
        if (bytes_written == 0) {
            perror("SSL_write - bytes_written = 0");
            #ifdef WIN32
            closesocket(socketfd);
            #else
            close(socketfd);
            #endif
            ShutdownSSL();
            DestroySSL();
            return;
        }
        if (bytes_written == -1) {
            perror("SSL_write - bytes_written = -1");
            #ifdef WIN32
            closesocket(socketfd);
            #else
            close(socketfd);
            #endif
            ShutdownSSL();
            DestroySSL();
            return;
        }

        bytes_recv = SSL_read(cssl, buff.data(), 1024);
            if (bytes_recv == 0){
                perror("SSL_read - bytes_recv = 0");
                #ifdef WIN32
                closesocket(socketfd);
                #else
                close(socketfd);
                #endif
                ShutdownSSL();
                DestroySSL();
                return;
            }
            else if (bytes_recv == -1){
                perror("SSL_read - bytes_recv = -1");
                #ifdef WIN32
                closesocket(socketfd);
                #else
                close(socketfd);
                #endif
                ShutdownSSL();
                DestroySSL();
                return;
            }

            std::string sbuff(buff.begin(), buff.end());
            std::cout << sbuff << std::endl;
            QThread::msleep(1000);
        }
}
