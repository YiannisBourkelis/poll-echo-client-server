/* ***********************************************************************
 * (C) 2018 by Yiannis Bourkelis (hello@andama.org)
 * ***********************************************************************/

// Using poll() instead of select()
// poll server based on code from https://www.ibm.com/support/knowledgecenter/en/ssw_i5_54/rzab6/poll.htm

// SSL Programming Tutorial
// http://h41379.www4.hpe.com/doc/83final/ba554_90007/ch04s03.html

// Simple TLS Server
// https://wiki.openssl.org/index.php/Simple_TLS_Server

#include "poll_server.h"

PollServer::PollServer()
{
}

void PollServer::InitializeSSL()
{
    SSL_load_error_strings();
    SSL_library_init(); //xreiazetai gia to linux logo bug se palaioteres ekdoseis openssl
    OpenSSL_add_all_algorithms();
}

void PollServer::DestroySSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

void PollServer::create_context()
{
    const SSL_METHOD *method;

    method = TLSv1_2_server_method();

    sslctx_ = SSL_CTX_new(method);
    if (!sslctx_) {
    perror("Unable to create SSL context");
    exit(EXIT_FAILURE);
    }
}

void PollServer::configure_context()
{
    SSL_CTX_set_ecdh_auto(sslctx_, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(sslctx_, "../certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(sslctx_, "../key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        exit(EXIT_FAILURE);
    }
}

void PollServer::displayLastError(std::string description){
#ifdef WIN32
        std::cout <<  description << " - Last error number: " << WSAGetLastError() << std::endl;
#else
        perror(description.data());
#endif
}

#ifdef WIN32
void PollServer::disableNagleAlgorithm(SOCKET socket){
#else
void PollServer::disableNagleAlgorithm(int socket){
#endif
    /*************************************************************/
    /* SIMANTIKO: kanw disable to nagle algorithm. meiwnei to latency. */
    /*************************************************************/
   int flag = 1;
   int setsockopt_nagle_ret = 0;
   setsockopt_nagle_ret = setsockopt(socket,                    /* socket affected */
                           IPPROTO_TCP,     /* set option at TCP level */
                           TCP_NODELAY,     /* name of option */
                           (char *) &flag,  /* the cast is historical cruft */
                           sizeof(int));    /* length of option value */
   if (setsockopt_nagle_ret < 0){
       displayLastError("setsockopt to disable nagle algorithm failed for listening socket");
   }
}

#ifdef WIN32
void PollServer::setSocketNonBlocking(SOCKET socket){
#else
void PollServer::setSocketNonBlocking(int socket){
#endif
    /*************************************************************/
    /* Set socket to be nonblocking. All of the sockets for    */
    /* the incoming connections will also be nonblocking since  */
    /* they will inherit that state from the listening socket.   */
    /*************************************************************/
    int rc, on = 1;
    #ifdef WIN32
    rc = ioctlsocket(socket, FIONBIO, (u_long*)&on);
    #else
    rc = ioctl(socket, FIONBIO, (char *)&on);
    #endif
    if (rc < 0)
    {
      displayLastError("ioctl() failed for listen_sd");
      #ifdef WIN32
      closesocket(socket);
      #else
      close(socket);
      #endif
      exit(-1);
    }
}

void PollServer::start(int server_port, protocol ip_protocol)
{
  int                   len, rc, on = 1;
  bool                  end_server = false, compress_array = false;
  int                   close_conn;
  char                  buffer[80];
  struct sockaddr_in    addr4, clientaddr4;
  struct sockaddr_in6   addr6, clientaddr6;
  socklen_t             addrlen4 = sizeof(clientaddr4);
  socklen_t             addrlen6 = sizeof(clientaddr6);
  int                   nfds = 1, current_size = 0, i, j;

#ifdef WIN32
    WSAPOLLFD           fds[200];
    SOCKET              listen_sd = -1, new_sd = -1;
    // Initialize Winsock
    int iResult;
    WSADATA wsaData;
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << std::endl;
        return;
    }
#else
    struct              pollfd fds[200];
    int                 listen_sd = -1, new_sd = -1;
#endif

#ifndef WIN32
 //gia na mi prokaleitai crash otan paw na grapsw se socket pou exei kleisei
 //http://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
 signal(SIGPIPE, SIG_IGN);
 #endif

  InitializeSSL();
  create_context();
  configure_context();

  /*************************************************************/
  /* Create an AF_INET stream socket to receive incoming       */
  /* connections on                                            */
  /*************************************************************/
  if (ip_protocol == PollServer::IPv4) {
    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
  } else {
    listen_sd = socket(AF_INET6, SOCK_STREAM, 0);
  }
  if (listen_sd < 0)
  {
    perror("socket() failed");
    exit(-1);
  }

  /*************************************************************/
  /* Allow socket descriptor to be reuseable                   */
  /*************************************************************/
  rc = setsockopt(listen_sd, SOL_SOCKET,  SO_REUSEADDR,
                  (char *)&on, sizeof(on));
  if (rc < 0)
  {
    perror("setsockopt() failed");
    #ifdef WIN32
    closesocket(listen_sd);
    #else
    close(listen_sd);
    #endif
    exit(-1);
  }

  /* Set socket to be nonblocking.                             */
  setSocketNonBlocking(listen_sd);

  /*************************************************************/
  /* Bind the socket                                           */
  /*************************************************************/
  if (ip_protocol == PollServer::IPv4) {
      memset(&addr4, 0, sizeof(addr4));
      addr4.sin_family      = AF_INET;
      addr4.sin_addr.s_addr = INADDR_ANY;
      addr4.sin_port        = htons(server_port);
      rc = bind(listen_sd, (struct sockaddr *)&addr4, sizeof(addr4));
  } else {
      memset(&addr6, 0, sizeof(addr6));
      addr6.sin6_family      = AF_INET6;
      addr6.sin6_addr        = in6addr_any;
      addr6.sin6_port        = htons(server_port);
      rc = bind(listen_sd, (struct sockaddr *)&addr6, sizeof(addr6));
  }

  if (rc < 0)
  {
    perror("bind() failed");
    #ifdef WIN32
    closesocket(listen_sd);
    #else
    close(listen_sd);
    #endif
    exit(-1);
  }

  /*************************************************************/
  /* Set the listen back log                                   */
  /*************************************************************/
  std::cout << "Listening for connections on port:" << server_port << std::endl;
  rc = listen(listen_sd, 35);
  if (rc < 0)
  {
    perror("listen() failed");
    #ifdef WIN32
    closesocket(listen_sd);
    #else
    close(listen_sd);
    #endif
    exit(-1);
  }

  /*************************************************************/
  /* Initialize the pollfd structure                           */
  /*************************************************************/
  memset(fds, 0 , sizeof(fds));

  /*************************************************************/
  /* Set up the initial listening socket                        */
  /*************************************************************/
  fds[0].fd     = listen_sd;
  #ifdef WIN32
  fds[0].events = POLLRDNORM;
  #else
  fds[0].events = POLLIN;
  #endif

   /* SIMANTIKO: kanw disable to nagle algorithm. meiwnei to latency. */
   disableNagleAlgorithm(listen_sd);

  /*************************************************************/
  /* Loop waiting for incoming connects or for incoming data   */
  /* on any of the connected sockets.                          */
  /*************************************************************/
  do
  {
    /***********************************************************/
    /* Call poll() without a timeout.      */
    /***********************************************************/
    std::cout << "Waiting on poll()...\n" << std::endl;
    #ifdef WIN32
    rc = WSAPoll(fds, nfds, -1);
    #else
    rc = poll(fds, nfds, -1);
    #endif

    /***********************************************************/
    /* Check to see if the poll call failed.                   */
    /***********************************************************/
    if (rc < 0)
    {
      perror("  poll() failed");
      break;
    }

    /***********************************************************/
    /* One or more descriptors are readable.  Need to          */
    /* determine which ones they are.                          */
    /***********************************************************/
    current_size = nfds;
    for (i = 0; i < current_size; i++)
    {
      /*********************************************************/
      /* Loop through to find the descriptors that returned    */
      /* POLLIN and determine whether it's the listening       */
      /* or the active connection.                             */
      /*********************************************************/
      if(fds[i].revents == 0)
        continue;

      /*********************************************************/
      /* If revents is not POLLIN, it's an unexpected result,  */
      /* and closes the socket                                 */
      /*********************************************************/
#ifdef WIN32
      if(fds[i].revents != POLLRDNORM)
#else
      if(fds[i].revents != POLLIN)
#endif
      {
        std::cout << printf("  Error! revents = %d\n", fds[i].revents) << std::endl;
        perror("  Error on readable descriptor");

          #ifdef WIN32
          closesocket(fds[i].fd);
          #else
          close(fds[i].fd);
          #endif
          SSL_shutdown(sslmap_.at(fds[i].fd));
          SSL_free(sslmap_.at(fds[i].fd));
          sslmap_.erase(sslmap_.find(fds[i].fd));
          fds[i].fd = -1;
          compress_array = true;

        break;
      }

      if (fds[i].fd == listen_sd)
      {
        /*******************************************************/
        /* Listening descriptor is readable.                   */
        /*******************************************************/
        std::cout << ("  Listening socket is readable\n") << std::endl;

        /*******************************************************/
        /* Accept all incoming connections that are            */
        /* queued up on the listening socket before we         */
        /* loop back and call poll again.                      */
        /*******************************************************/
        do
        {
          /*****************************************************/
          /* Accept each incoming connection. If              */
          /* accept fails with EWOULDBLOCK, then we            */
          /* have accepted all of them. Any other             */
          /* failure on accept will cause us to end the        */
          /* server.                                           */
          /*****************************************************/
          new_sd = accept(listen_sd, NULL, NULL);
          //Sta windows, gia kapoio logo to new_sd epistrefei MAX_UINT
          //otan den yparxei allo socket gia accept kai oxi -1 opws ginetai se linux/osx
#ifdef WIN32
          if (new_sd == UINT_MAX || new_sd < 0)
          {
            if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
          if (new_sd < 0)
          {
            if (errno != EWOULDBLOCK)
#endif
            {
              perror("  accept() failed");
              end_server = true;
            }
            break;
          }

          /* SIMANTIKO: kanw disable to nagle algorithm. meiwnei to latency. */
          disableNagleAlgorithm(new_sd);

         /* Set socket to be nonblocking.    */
        setSocketNonBlocking(new_sd);

          sslmap_.insert(std::pair<int,SSL*>(new_sd, SSL_new(sslctx_)));
          SSL_set_fd(sslmap_.at(new_sd), new_sd);
          //Here is the SSL Accept portion.  Now all reads and writes must use SSL
          int ssl_err = SSL_accept(sslmap_.at(new_sd));
          if(ssl_err <= 0)
          {
              //SSL_ERROR_NONE
              int sslgerr = SSL_get_error(sslmap_.at(new_sd), ssl_err);
              while ( sslgerr == SSL_ERROR_WANT_READ){
                  QThread::usleep(10);
                  //sleep(1);//1 second
                  ssl_err = SSL_accept(sslmap_.at(new_sd));
                  sslgerr = SSL_get_error(sslmap_.at(new_sd), ssl_err);
                  //std::cout << "SSL accept error: " << sslgerr << std::endl;
              }
          }

          /*****************************************************/
          /* Add the new incoming connection to the            */
          /* pollfd structure                                  */
          /*****************************************************/
          std::cout << printf("  New incoming connection - %d\n", new_sd) << std::endl;
          fds[nfds].fd = new_sd;
          #ifdef WIN32
          fds[nfds].events = POLLRDNORM;
          #else
          fds[nfds].events = POLLIN;
          #endif
          nfds++;

          /*****************************************************************/
          /* Display the client address.  Note that if the client is       */
          /* an IPv4 client, the address will be shown as an IPv4 Mapped   */
          /* IPv6 address.                                                 */
          /*****************************************************************/
          if (ip_protocol == PollServer::IPv4) {
              char str[INET_ADDRSTRLEN];
              getpeername(new_sd, (struct sockaddr *)&clientaddr4, &addrlen4);
              if(inet_ntop(AF_INET, &clientaddr4.sin_addr, str, sizeof(str))) {
                 std::cout << printf("Client address is %s\n", str) << std::endl;
                 std::cout << printf("Client port is %d\n", ntohs(clientaddr4.sin_port)) << std::endl;
              }
          } else {
              char str[INET6_ADDRSTRLEN];
              getpeername(new_sd, (struct sockaddr *)&clientaddr6, &addrlen6);
              if(inet_ntop(AF_INET6, &clientaddr6.sin6_addr, str, sizeof(str))) {
                 std::cout << printf("Client address is %s\n", str) << std::endl;
                 std::cout << printf("Client port is %d\n", ntohs(clientaddr6.sin6_port)) << std::endl;
              }
          }

          // apostoli mynimatos kalosorismatos
          std::string greeting = "Welcome to the SSL Poll Echo Server by Yiannis Bourkelis\n";
          int rc = SSL_write(sslmap_.at(new_sd), greeting.data(), greeting.size());

          /*****************************************************/
          /* Loop back up and accept another incoming          */
          /* connection                                        */
          /*****************************************************/
#ifdef WIN32
        } while (new_sd != UINT_MAX && new_sd != -1);
#else
        } while (new_sd != -1);
#endif
      }

      /*********************************************************/
      /* This is not the listening socket, therefore an        */
      /* existing connection must be readable                  */
      /*********************************************************/

      else
      {
        std::cout << printf("  Descriptor %d is readable\n", fds[i].fd) << std::endl;
        close_conn = false;
        /*******************************************************/
        /* Receive all incoming data on this socket            */
        /* before we loop back and call poll again.            */
        /*******************************************************/

        do
        {
          /*****************************************************/
          /* Receive data on this connection until the         */
          /* recv fails with EWOULDBLOCK. If any other        */
          /* failure occurs, we will close the                 */
          /* connection.                                       */
          /*****************************************************/
          SSL_set_fd(sslmap_.at(fds[i].fd), fds[i].fd);
          rc = SSL_read(sslmap_.at(fds[i].fd), buffer, sizeof(buffer));

          if (rc < 0)
          {
#ifdef WIN32
            if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
            if (errno != EWOULDBLOCK)
#endif
            {
              displayLastError("recv() failed");
              close_conn = true;
            }
            break;
          }

          /*****************************************************/
          /* Check to see if the connection has been           */
          /* closed by the client                              */
          /*****************************************************/
          if (rc == 0)
          {
            std::cout << ("  Connection closed\n") << std::endl;
            close_conn = true;
            break;
          }

          /*****************************************************/
          /* Data was received                                 */
          /*****************************************************/
          len = rc;
          std::cout << printf("  %d bytes received\n", len) << std::endl;

          /*****************************************************/
          /* Echo the data back to the client                  */
          /*****************************************************/
          std::string echoStr("Echo: ");
          std::vector<char> send_buffer (echoStr.begin(), echoStr.end());
          std::vector<char> vbuffer(buffer, buffer+len);
          send_buffer.insert(send_buffer.end(),vbuffer.begin(), vbuffer.end());
          rc = SSL_write(sslmap_.at(fds[i].fd), send_buffer.data(), send_buffer.size());
          if (rc < 0)
          {
#ifdef WIN32
            if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
            if (errno != EWOULDBLOCK)
#endif
                {
            displayLastError("send() failed");
            close_conn = true;
          }
            break;
          }

           //to recieve egine opote vgainw apo to loop
          //break;
        } while(true);

        /*******************************************************/
        /* If the close_conn flag was turned on, we need       */
        /* to clean up this active connection. This           */
        /* clean up process includes removing the              */
        /* descriptor.                                         */
        /*******************************************************/
        if (close_conn)
        {
          #ifdef WIN32
          closesocket(fds[i].fd);
          #else
          close(fds[i].fd);
          #endif
          SSL_shutdown(sslmap_.at(fds[i].fd));
          SSL_free(sslmap_.at(fds[i].fd));
          sslmap_.erase(sslmap_.find(fds[i].fd));
          fds[i].fd = -1;
          compress_array = true;
        }


      }  /* End of existing connection is readable             */
    } /* End of for loop through pollable descriptors              */

    /***********************************************************/
    /* If the compress_array flag was turned on, we need       */
    /* to squeeze together the array and decrement the number  */
    /* of file descriptors. We do not need to move back the    */
    /* events and revents fields because the events will always*/
    /* be POLLIN in this case, and revents is output.          */
    /***********************************************************/
    if (compress_array)
    {
      compress_array = false;
      for (i = 0; i < nfds; i++)
      {
        if (fds[i].fd == -1)
        {
          for(j = i; j < nfds; j++)
          {
            fds[j].fd = fds[j+1].fd;
          }
          nfds--;
        }
      }
    }

  } while (end_server == false); /* End of serving running.    */

  /*************************************************************/
  /* Clean up all of the sockets that are open                  */
  /*************************************************************/
  for (i = 0; i < nfds; i++)
  {
    if(fds[i].fd >= 0)
        #ifdef WIN32
        closesocket(fds[i].fd);
        #else
        close(fds[i].fd);
        #endif
     if (sslmap_.find(fds[i].fd) != sslmap_.end()) {
        SSL_shutdown(sslmap_.at(fds[i].fd));
        SSL_free(sslmap_.at(fds[i].fd));
        sslmap_.erase(fds[i].fd);
      }
  }//for

  DestroySSL();
}
