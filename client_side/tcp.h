#ifndef TCP
#define TCP

#include "header.h"

void tcp_socket(SOCKET *sock);
SOCKET wait_connect(SOCKET server_sock);
void recv_tcpdata(SOCKET cli_sock, char buffer[], int size);
void tcpdata_send(SOCKET cli_sock, char buffer[], int size);

#endif