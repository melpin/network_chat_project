#ifndef UDP
#define UDP

#include "header.h"

void udp_socket(SOCKET *sock);
SOCKADDR_IN recv_udpdata(SOCKET server_sock, char buffer[], int size);
void udpdata_send(SOCKET server_sock, char buffer[], SOCKADDR_IN cliAddr);

#endif