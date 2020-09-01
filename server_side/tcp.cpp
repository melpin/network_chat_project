#include "tcp.h"

void tcp_socket(SOCKET *sock){
	*sock = socket(PF_INET, SOCK_STREAM, 0);
	if (*sock == INVALID_SOCKET)
		Error_handle("server socket error");
}

SOCKET wait_connect(SOCKET server_sock){
	SOCKET cli_sock;
	SOCKADDR_IN cliAddr;
	int cliAddr_size = 0;
	printf("listen!\n");
	if (listen(server_sock, 5) == SOCKET_ERROR)
		Error_handle("listen error");

	cliAddr_size = sizeof(cliAddr);
	cli_sock = accept(server_sock, (SOCKADDR*)&cliAddr, &cliAddr_size);
	if (cli_sock == INVALID_SOCKET)
		Error_handle("client socket error");

	return cli_sock;
}

void recv_tcpdata(SOCKET cli_sock, char buffer[], int size){
	int recv_len = 0;
	recv_len = recv(cli_sock, buffer, size, 0);
	if (recv_len == -1)
		Error_handle("recv error");
}

void tcpdata_send(SOCKET cli_sock, char buffer[], int size){
	send(cli_sock, buffer, size, 0);
}

