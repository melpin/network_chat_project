#ifndef SET_SOCKET
#define SET_SOCKET

#include "header.h"

void init_lib();
SOCKADDR_IN set_port(int port);
void bind_socket(SOCKET server_sock, SOCKADDR_IN serverAddr);
void disconnect_socket(SOCKET server_sock, SOCKET cli_sock);

#endif