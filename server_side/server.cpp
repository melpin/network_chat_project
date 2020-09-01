#include "set_socket.h"
#include "tcp.h"
#include "udp.h"
#include "set_ssl.h"

int main(){
	SOCKET server_sock, cli_sock;
	SOCKADDR_IN serverAddr, cliAddr;
	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL* ssl;
	int port = 0;
	int protocol_type = 0;
	char buffer[256] = { 0 };

	printf("server terminal\n");

	init_lib();

	printf("TCP : 1\nUDP : 2\nSSL : 3\n> ");
	scanf_s("%d", &protocol_type);

	if (protocol_type == 1)	tcp_socket(&server_sock);
	else if (protocol_type == 2) udp_socket(&server_sock);
	else if (protocol_type == 3){
		tcp_socket(&server_sock);
		meth = InitializeSSL();
		ctx = CTX_setting(meth);
		SSL_CTX_set_file(ctx);
	}
	printf("input port number : ");
	scanf_s("%d", &port);
	
	serverAddr = set_port(port);
	bind_socket(server_sock, serverAddr);

	if (protocol_type == 1){
		cli_sock = wait_connect(server_sock);
		while (1){
			recv_tcpdata(cli_sock, buffer, sizeof(buffer) - 1);
			if (strstr(buffer, "exit") != NULL) break;
			printf("TCP: client say : %s", buffer);
			tcpdata_send(cli_sock, buffer, strlen(buffer));
			RtlZeroMemory(buffer, 256);
		}
	}
	else if (protocol_type == 2){
		while (1){
			cliAddr = recv_udpdata(server_sock, buffer, sizeof(buffer));
			if (strstr(buffer, "exit") != NULL) break;
			printf("UDP: client say : %s", buffer);
			udpdata_send(server_sock, buffer, cliAddr);
			RtlZeroMemory(buffer, 256);
		}
	}
	else if (protocol_type == 3){
		cli_sock = wait_connect(server_sock);
		ssl = new_ssl_make(ctx);
		ssl_accept_socket(ssl, cli_sock);
		get_cipher_info(ssl);

		while (1){
			recv_ssldata(ssl, buffer, sizeof(buffer));
			printf("SSL: client say : %s", buffer);
			if (strstr(buffer, "exit") != NULL) break;
			ssldata_send(ssl, buffer, strlen(buffer));
		}
	}

	disconnect_socket(server_sock, cli_sock);
	if (protocol_type == 3) ShutdownSSL(ssl, ctx);
	return 0;
}
