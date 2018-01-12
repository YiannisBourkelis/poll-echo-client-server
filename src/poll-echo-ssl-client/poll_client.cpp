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
    //SSL_shutdown(cSSL_);
    //SSL_free(cSSL_);
}

void PollClient::create_context()
{
    const SSL_METHOD *method;

    method = TLSv1_2_client_method();

    sslctx_ = SSL_CTX_new(method);
    if (!sslctx_) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    }
}

void PollClient::configure_context()
{
    //SSL_CTX_set_ecdh_auto(sslctx_, 1);

    /*
    // Set the key and cert
    if (SSL_CTX_use_certificate_file(sslctx_, "../certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(sslctx_, "../key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    }
    */
}


void PollClient::ConnectToServer(std::string host, int port)
{
    int    bytes_recv;
    struct sockaddr_in serv_addr;
    struct hostent *SERVER;
    int listen_socket = 0;
    char buffer[80];

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

        InitializeSSL();
        //create_context();
        //configure_context();

    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
#ifdef WIN32
    if (listen_socket == INVALID_SOCKET) {
#else
    if (listen_socket < 0){
#endif
        perror("ERROR opening socket");
        return;
    }

    //SERVER = gethostbyname("mailgate.filoxeni.com");
    //SERVER = gethostbyname("andamaproxy-us-west.filoxeni.com");
    //SERVER = gethostbyname("andamaproxy-ro-timisoara.filoxeni.com");
    SERVER = gethostbyname(host.data());

    if (SERVER == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
#ifdef WIN32
        closesocket(listen_socket);
#else
        close(listen_socket);
#endif
        return;
    }

    memset((char *) &serv_addr,0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;


    bcopy((char *)SERVER->h_addr,
         (char *)&serv_addr.sin_addr,
         SERVER->h_length);
    //serv_addr.sin_addr.s_addr = INADDR_ANY;

    //serv_addr.sin_addr.s_addr=inet_addr("192.168.32.20"); // <------------- local server

    //SIMANTIKO: kanw disable to nagle algorithm. meiwnei to latency.
    int flag = 1;

    setsockopt(listen_socket,      /* socket affected */
                            IPPROTO_TCP,     /* set option at TCP level */
                            TCP_NODELAY,     /* name of option */
                            (char *) &flag,  /* the cast is historical cruft */
                            sizeof(int));    /* length of option value */

        serv_addr.sin_port = htons(port);

        SSL_library_init();
        create_context();

        //connect to server
    int conres = ::connect(listen_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    cssl = SSL_new(sslctx_);
    SSL_set_fd(cssl, listen_socket);

    int conres2 = SSL_connect(cssl);

    ERR_print_errors_fp(stderr);

    if (conres2 < 0)
    {
        int mysse = SSL_get_error(cssl, conres2);
         std::cout << "ERROR connecting. SSL error result: " << mysse << "\n";
        std::cout << "ERROR connecting. result: " << conres << "\n";
        perror("ERROR connecting");
#ifdef WIN32
        closesocket(listen_socket);
#else
        close(listen_socket);
#endif
        return;
     }

    struct sockaddr_in local_address;
    socklen_t addr_size = sizeof(local_address);
    int ddd = listen_socket;
    getsockname(ddd, (struct sockaddr *) &local_address, &addr_size);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(local_address.sin_addr), str, INET_ADDRSTRLEN);
    std::cout << "client local port after proxy connect:" << local_address.sin_port << ", IP:" << str << std::endl;

    //int bytes_recv = 0;
    while(true){
        //std::string input_str;
        //std::cin >> input_str;
        std::vector<char> buff(1024);
        std::string input_str = "weddwedwed";

        //send(listen_socket, input_str.data(), input_str.size(), 0);
        SSL_write(cssl, input_str.data(), input_str.size());

        //bytes_recv = recv(listen_socket, &buffer[0], sizeof(buffer), 0);
        //bytes_recv = recv(listen_socket, buff.data(), 1024, 0);
        bytes_recv = SSL_read(cssl, buff.data(), 1024);
            if (bytes_recv == 0){
                            perror(
                             "######### --- Main command loop disconnected from server. ---- ######## "
                             "####  recv return 0 bytes. [MAIN command loop]. Returning from function. ");


    #ifdef WIN32
                closesocket(listen_socket);
    #else
                close(listen_socket);
    #endif
                return;
            }
            else if (bytes_recv == -1){
                perror("void clientsocket::connectToServer() ## bytes_recv == -1 ## [MAIN command loop]. Returning from function.");

    #ifdef WIN32
                closesocket(listen_socket);
    #else
                close(listen_socket);
    #endif
                return;
            }

            std::string sbuff(buff.begin(), buff.end());
            std::cout << sbuff << std::endl;
            sleep(1);
        }
}
