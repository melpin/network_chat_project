#ifndef SET_SOCKET
#define SET_SOCKET

#include "header.h"

void init_lib();
SOCKADDR_IN set_port(char ip_addr[], int port);
void connect_socket(SOCKET host_sock, SOCKADDR_IN serverAddr);
void send_data(SOCKET host_socket, char buffer[], int size);
void recv_data(SOCKET host_socket, char buffer[], int size);
void disconnect_socket(SOCKET server_sock);

#endif