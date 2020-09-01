# network_chat_project
chatting server,client with udp, tcp, ssl protocol

<h2>server side  </h2>  

header.h > define basic header  
set_socket.h > init_lib, set_port, bind_socket, disconnect_socket function prototype define  
set_ssl > ssl certification path, many functions prototype for ssl  
tcp.h > tcp socket init, recv, send, connect wait function prototype define  
udp. h > udp socket init, recv, send function prototype define  

<h3>set_socket.cpp  </h3>  
init_lib function > init winsock lib    

set_port function > sockaddr structer define and return    

bind_socket function > bind, wait client    

disconnect_socket function > close socket    


<h3>udp.cpp  </h3>
upd_socket function > init udp socket  

recv_udpdata function > recv data with udp socket  

udpdata_send function> send data with udp socket  


<h3>tcp.cpp  </h3>
tcp_socket function > init tcp socket  

wait_connect function > tcp socket need 3way handshake, so listen and accept process  

recv_tcpdata function > recv data with tcp socket  

tcpdata_send function > send data with tcp socket  


<h3>set_ssl.cpp  </h3>
initializeSSL function > load ssl method, algorithm  

CTX_setting function > ssl context structure init  

SSL_CTX_set_file function > ssl certification load from window path, set CTX structure  

new_ssl_make function > return ssl make with ctx  

ssl_accept_socket function > ssl sertification bind with socket  

get_cipher_info function > exchange cipher spec between client and server in ssl init process  

shutdonwSSL function > ssl certi close  

recv_ssldata function > rcv data with ssl  

ssldata_send function > send data with ssl  


<h3>server.cpp  </h3>
main function  

input socket type and init  

input ip, port  

wait client


<hr>

<h2>client side  </h2>

headers same  

<h3>client.cpp  </h3>
main function  

input socket type and init  

input ip, port  

connect to server  

