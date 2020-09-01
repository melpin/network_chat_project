#include "udp.h"

void udp_socket(SOCKET *sock){
	*sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (*sock == INVALID_SOCKET)
		Error_handle("server socket error");
}


SOCKADDR_IN recv_udpdata(SOCKET server_sock, char buffer[], int size){
	int recv_len = 0;
	int cliAddr_size = 0;
	SOCKADDR_IN cliAddr;
	cliAddr_size = sizeof(cliAddr);
	recv_len = recvfrom(server_sock, buffer, size, 0, (SOCKADDR*)&cliAddr, &cliAddr_size);
	if (recv_len == -1)
		Error_handle("recv error");
	return cliAddr;
}

void udpdata_send(SOCKET server_sock, char buffer[], SOCKADDR_IN cliAddr){
	int cliAddr_size = 0;
	cliAddr_size = sizeof(cliAddr);
	sendto(server_sock, buffer, strlen(buffer), 0, (SOCKADDR*)&cliAddr, cliAddr_size);
}

