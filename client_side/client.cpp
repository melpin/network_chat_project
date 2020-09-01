#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "set_socket.h"
#include "tcp.h"
#include "udp.h"
#include "set_ssl.h"

int main(){
	SOCKET host_socket;
	SOCKADDR_IN serverAddr;
	SSL_METHOD *meth;
	SSL_CTX* ctx;
	SSL* ssl;
	X509 *client_cert;
	int port = 0;
	int protocol_type = 0;
	char buffer[256] = { 0 };
	char ip_addr[15] = { 0 };

	printf("client terminal\n");

	init_lib();

	printf("TCP : 1\nUDP : 2\nSSL : 3\n> ");
	scanf_s("%d", &protocol_type);

	if (protocol_type == 1)	tcp_socket(&host_socket);
	else if (protocol_type == 2) udp_socket(&host_socket);
	else if (protocol_type == 3){
		tcp_socket(&host_socket);
		meth = InitializeSSL();
		ctx = CTX_setting(meth);
		SSL_CTX_set_file(ctx);
	}

	printf("input ip(xxx.xxx.xxx.xxx) :");
	scanf_s("%s", ip_addr, 15);
	printf("input port :");
	scanf_s("%d", &port);

	serverAddr = set_port(ip_addr, port);
	connect_socket(host_socket, serverAddr);

	
	if ((protocol_type == 1) | (protocol_type == 2)){
		while (1){
			printf("input data :");
			fflush(stdin);
			fgets(buffer, 256, stdin);
			send_data(host_socket, buffer, strlen(buffer));
			if (strstr(buffer, "exit") != NULL) break;
			recv_data(host_socket, buffer, sizeof(buffer));

			printf("server reply : %s", buffer);
			RtlZeroMemory(buffer, 256);
		}
	}
	else if (protocol_type == 3){
		ssl = new_ssl_make(ctx);
		SSL_set_fd(ssl, host_socket);
		SSL_connect(ssl);
		client_cert = get_cipher_info(ssl);

		while (1){
			printf("input data :");
			fflush(stdin);
			fgets(buffer, 256, stdin);
			ssldata_send(ssl, buffer, strlen(buffer));
			if (strstr(buffer, "exit") != NULL) break;
			recv_ssldata(ssl, buffer, sizeof(buffer));
			printf("server reply : %s", buffer);
			RtlZeroMemory(buffer, 256);
		}
	}

	disconnect_socket(host_socket);
	return 0;

}

