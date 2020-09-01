#include "udp.h"

void udp_socket(SOCKET *sock){
	*sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (*sock == INVALID_SOCKET)
		Error_handle("server socket error");
}
