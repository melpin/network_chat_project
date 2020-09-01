#include "set_socket.h"

void Error_handle(char string[])
{
	printf("%s\n", string);
	exit(0);
}

void init_lib(){
	WSADATA wsadata;

	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
		Error_handle("WSAStartup error!");
}

SOCKADDR_IN set_port(char ip_addr[], int port){
	SOCKADDR_IN serverAddr;

	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = inet_addr(ip_addr);
	serverAddr.sin_port = htons(port);

	return serverAddr;
}


void connect_socket(SOCKET host_sock, SOCKADDR_IN serverAddr){
	if (connect(host_sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
		Error_handle("connect error");
}

void send_data(SOCKET host_socket, char buffer[], int size){
	send(host_socket, buffer, strlen(buffer), 0);
}

void recv_data(SOCKET host_socket, char buffer[], int size){
	int recv_len = 0;
	recv_len = recv(host_socket, buffer, size, 0);
	if (recv_len == -1)
		Error_handle("recv error");
}

void disconnect_socket(SOCKET server_sock){
	closesocket(server_sock);
	WSACleanup();
}