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


#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h> //inet_ntop

#include <unistd.h> //close
#include <netinet/tcp.h> //gia to TCP_NODELAY
#include <iostream> //std::cout, memset
#include <vector>
#include <string.h> //memset

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
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
    }
}

void PollServer::configure_context()
{
    SSL_CTX_set_ecdh_auto(sslctx_, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(sslctx_, "../certificate.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(sslctx_, "../key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void PollServer::start(int server_port)
{
  int                   len, rc, on = 1;
  int                   listen_sd = -1, new_sd = -1;
  bool                  end_server = false, compress_array = false;
  int                   close_conn;
  char                  buffer[80];
  struct sockaddr_in6   addr, clientaddr;
  socklen_t             addrlen = sizeof(clientaddr);
  struct                pollfd fds[200];
  int                   nfds = 1, current_size = 0, i, j;

  InitializeSSL();
  create_context();
  configure_context();

  /*************************************************************/
  /* Create an AF_INET stream socket to receive incoming       */
  /* connections on                                            */
  /*************************************************************/
  listen_sd = socket(AF_INET6, SOCK_STREAM, 0);
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
    close(listen_sd);
    exit(-1);
  }

  /*************************************************************/
  /* Set socket to be nonblocking. All of the sockets for    */
  /* the incoming connections will also be nonblocking since  */
  /* they will inherit that state from the listening socket.   */
  /*************************************************************/
  rc = ioctl(listen_sd, FIONBIO, (char *)&on);
  if (rc < 0)
  {
    perror("ioctl() failed");
    close(listen_sd);
    exit(-1);
  }

  /*************************************************************/
  /* Bind the socket                                           */
  /*************************************************************/
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family      = AF_INET6;
  addr.sin6_addr        = in6addr_any;
  addr.sin6_port        = htons(server_port);
  rc = bind(listen_sd, (struct sockaddr *)&addr, sizeof(addr));
  if (rc < 0)
  {
    perror("bind() failed");
    close(listen_sd);
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
    close(listen_sd);
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
  fds[0].events = POLLIN;

   /*************************************************************/
   /* SIMANTIKO: kanw disable to nagle algorithm. meiwnei to latency. */
   /*************************************************************/
  int flag = 1;
  int setsockopt_nagle_ret = 0;
  setsockopt_nagle_ret = setsockopt(listen_sd,                    /* socket affected */
                          IPPROTO_TCP,     /* set option at TCP level */
                          TCP_NODELAY,     /* name of option */
                          (char *) &flag,  /* the cast is historical cruft */
                          sizeof(int));    /* length of option value */
  if (setsockopt_nagle_ret < 0){
      perror("setsockopt to disable nagle algorithm failed for listening socket");
  }

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
    rc = poll(fds, nfds, -1);

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
      if(fds[i].revents != POLLIN)
      {
        std::cout << printf("  Error! revents = %d\n", fds[i].revents) << std::endl;
        perror("  Error on readable descriptor");

          close(fds[i].fd);
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
          if (new_sd < 0)
          {
            if (errno != EWOULDBLOCK)
            {
              perror("  accept() failed");
              end_server = true;
            }
            break;
          }

          /*************************************************************/
          /* SIMANTIKO: kanw disable to nagle algorithm. meiwnei to latency. */
          /*************************************************************/
         int flag = 1;
         int setsockopt_nagle_ret = 0;
         setsockopt_nagle_ret = setsockopt(listen_sd,                    /* socket affected */
                                 IPPROTO_TCP,     /* set option at TCP level */
                                 TCP_NODELAY,     /* name of option */
                                 (char *) &flag,  /* the cast is historical cruft */
                                 sizeof(int));    /* length of option value */
         if (setsockopt_nagle_ret < 0){
             perror("setsockopt to disable nagle algorithm failed for listening socket");
         }



          sslmap_.insert(std::pair<int,SSL*>(new_sd, SSL_new(sslctx_)));
          SSL_set_fd(sslmap_.at(new_sd), new_sd);
          ERR_print_errors_fp(stderr);
          //Here is the SSL Accept portion.  Now all reads and writes must use SSL
          int ssl_err = SSL_accept(sslmap_.at(new_sd));
          if(ssl_err <= 0)
          {
              //SSL_ERROR_NONE
              int sslgerr = SSL_get_error(sslmap_.at(new_sd), ssl_err);
              while ( sslgerr == SSL_ERROR_WANT_READ){
                  usleep(10);
                  //sleep(1);//1 second
                  ssl_err = SSL_accept(sslmap_.at(new_sd));
                  sslgerr = SSL_get_error(sslmap_.at(new_sd), ssl_err);
                  //std::cout << "SSL accept error: " << sslgerr << std::endl;
              }
          }

          /*************************************************************/
          /* SIMANTIKO: kanw disable to nagle algorithm. meiwnei to latency. */
          /*************************************************************/
         setsockopt_nagle_ret = 0;
         setsockopt_nagle_ret = setsockopt(listen_sd,                    /* socket affected */
                                 IPPROTO_TCP,     /* set option at TCP level */
                                 TCP_NODELAY,     /* name of option */
                                 (char *) &flag,  /* the cast is historical cruft */
                                 sizeof(int));    /* length of option value */
         if (setsockopt_nagle_ret < 0){
             perror("setsockopt to disable nagle algorithm failed for new socket");
         }

          /*****************************************************/
          /* Add the new incoming connection to the            */
          /* pollfd structure                                  */
          /*****************************************************/
          std::cout << printf("  New incoming connection - %d\n", new_sd) << std::endl;
          fds[nfds].fd = new_sd;
          fds[nfds].events = POLLIN;
          nfds++;

          /*****************************************************************/
          /* Display the client address.  Note that if the client is       */
          /* an IPv4 client, the address will be shown as an IPv4 Mapped   */
          /* IPv6 address.                                                 */
          /*****************************************************************/
          char str[INET6_ADDRSTRLEN];
          getpeername(new_sd, (struct sockaddr *)&clientaddr, &addrlen);
          if(inet_ntop(AF_INET6, &clientaddr.sin6_addr, str, sizeof(str))) {
             std::cout << printf("Client address is %s\n", str) << std::endl;
             std::cout << printf("Client port is %d\n", ntohs(clientaddr.sin6_port)) << std::endl;
          }

          /*****************************************************/
          /* Loop back up and accept another incoming          */
          /* connection                                        */
          /*****************************************************/
        } while (new_sd != -1);
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
          std::cout << "errno after SSL_read: " << errno << std::endl;
          if (rc < 0)
          {
            if (errno != EWOULDBLOCK)
            {
              perror("  recv() failed");
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
            perror("  send() failed");
            close_conn = true;
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
          close(fds[i].fd);
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
      close(fds[i].fd);
      if (sslmap_.find(fds[i].fd) != sslmap_.end()) {
          SSL_shutdown(sslmap_.at(fds[i].fd));
          SSL_free(sslmap_.at(fds[i].fd));
          sslmap_.erase(fds[i].fd);
      }
  }//for

  DestroySSL();
}
