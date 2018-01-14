# poll-echo-ssl-client-server
A simple, multi-platform, poll based echo server supporting IPv4/IPv6 and OpenSSL TLS, written in C++/Qt

I wrote this basic client and server as I was investigating how to write a high perfomrance server, based on poll.

The server echoes back whatever it receives using a secure TLS channel. It supports multiple connected clients.

Run the poll-echo-ssl-server and connect to it using the command: openssl s_client -connect localhost:12348

