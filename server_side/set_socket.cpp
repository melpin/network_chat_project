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

SOCKADDR_IN set_port(int port){
	SOCKADDR_IN serverAddr;

	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddr.sin_port = htons(port);

	return serverAddr;
}

void bind_socket(SOCKET server_sock, SOCKADDR_IN serverAddr){
	if (bind(server_sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
		Error_handle("bind error");
}

void disconnect_socket(SOCKET server_sock, SOCKET cli_sock){
	closesocket(cli_sock);
	closesocket(server_sock);
	WSACleanup();
}