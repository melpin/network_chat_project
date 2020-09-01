#ifndef SET_SSL
#define SET_SSL

#include "header.h"
#include <openssl\rsa.h>
#include <openssl\bio.h>
#include <openssl\err.h>
#include <openssl\x509.h>
#include <openssl\pem.h>
#include <openssl\rand.h>
#include <openssl\evp.h>
#include <openssl\crypto.h>
#include <openssl\ssl.h>
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#define HOME "C:\\OpenSSL\\bin\\"
#define CERTF  HOME "ca.crt"
#define KEYF  HOME  "ca.key"



SSL_METHOD *InitializeSSL();
SSL_CTX *CTX_setting(SSL_METHOD *method);
void SSL_CTX_set_file(SSL_CTX *ctx);
SSL *new_ssl_make(SSL_CTX *ctx);
void ssl_accept(SSL *ssl, SOCKET cli_sock);
void ShutdownSSL(SSL *ssl, SSL_CTX *ctx);
X509 *get_cipher_info(SSL *ssl);
void get_server_cert(SSL *ssl);
void recv_ssldata(SSL *ssl, char buffer[], int size);
void ssldata_send(SSL *ssl, char buffer[], int size);


#endif // !SSL
