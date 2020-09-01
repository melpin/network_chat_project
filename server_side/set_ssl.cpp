#include "set_ssl.h"

int verify_client = OFF;

SSL_METHOD *InitializeSSL()
{
	SSL_library_init(); /* load encryption & hash algorithms for SSL */
	SSL_load_error_strings(); /* load the error strings for good error reporting */
	OpenSSL_add_all_algorithms();
	SSLeay_add_ssl_algorithms();
	return SSLv3_method();
}

SSL_CTX *CTX_setting(SSL_METHOD *method)
{
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx)
		Error_handle("CTX setting error");
	return ctx;
}

void SSL_CTX_set_file(SSL_CTX *ctx){
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) < 0)
		Error_handle("SSL CTX set certificate file error");
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) < 0)
		Error_handle("SSL CTX set privatekey file error");
	if (!SSL_CTX_check_private_key(ctx))
		Error_handle("Private key does not match the certificate public key");
	if (verify_client == ON){
		if (!SSL_CTX_load_verify_locations(ctx, CERTF_CA, NULL))
			Error_handle("CTX load error");
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ctx, 1);
	}
}

SSL *new_ssl_make(SSL_CTX *ctx){
	SSL *ssl;
	ssl = SSL_new(ctx);
	if (ssl == NULL)
		Error_handle("new ssl make error");
	return ssl;
}

void ssl_accept_socket(SSL *ssl, SOCKET cli_sock){
	SSL_set_fd(ssl, cli_sock);
	printf("SSL_accept start\n");
	if (SSL_accept(ssl) == -1) Error_handle("ssl accept error");
	printf("SSL_accept success\n");
}

void get_cipher_info(SSL *ssl){
	X509 *client_cert = NULL;
	char    *str;
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	if (verify_client == ON)
	{
		client_cert = SSL_get_peer_certificate(ssl);
		if (client_cert != NULL)
		{
			printf("Client certificate:\n");
			str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
			if (str == NULL) Error_handle("X509 get subject name error");
			printf("\t subject: %s\n", str);
			free(str);
			str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
			if (str == NULL) Error_handle("X509 get issuer name error");
			printf("\t issuer: %s\n", str);
			free(str);
			X509_free(client_cert);
		}
		else printf("The SSL client does not have certificate.\n");
	}
}

void ShutdownSSL(SSL *ssl, SSL_CTX *ctx)
{
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
}

void recv_ssldata(SSL *ssl, char buffer[], int size){
	int recv_len = 0;
	recv_len = SSL_read(ssl, buffer, size);
	if (recv_len == -1)
		Error_handle("ssl recv error");
	buffer[recv_len] = '\0';
}

void ssldata_send(SSL *ssl, char buffer[], int size){
	int send_len = 0;
	send_len = SSL_write(ssl, buffer, size);
	if(send_len == -1)
		Error_handle("ssl send error");
}