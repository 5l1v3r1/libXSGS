#include "demo.h"

int verbose = 0;

int hostname_to_ip(char *hostname, char *ip) {
	struct hostent *he;
	struct in_addr **addr_list;
	int i;

	if ((he = gethostbyname(hostname)) == NULL) {
		char err_str[100];
		sprintf(err_str, "Error resolving %s", hostname);
		herror(err_str);
		return 1;
	}

	addr_list = (struct in_addr **) he->h_addr_list;

	for (i = 0; addr_list[i] != NULL; i++) {
		//Return the first one;
		strcpy(ip, inet_ntoa(*addr_list[i]));
		return 0;
	}

	return 2;
}

int send_data(int sockfd, BYTE type, DWORD size, BYTE *data) {
	STRUC_NET_PACKET net_pack;
	DWORD write_size = 0;

	net_pack.header.type = type;
	net_pack.header.body_size = size;
	net_pack.body = data;

	write_size += write(sockfd, (BYTE*)&(net_pack.header), sizeof(net_pack.header));
	write_size += write(sockfd, net_pack.body, net_pack.header.body_size);

    if(write_size != (sizeof(net_pack.header) + size) ) {
    	return 1;
    }

    return 0;
}

int recv_data(int sockfd, BYTE *type, DWORD *size, BYTE **data) {
	STRUC_NET_PACKET net_pack;
	int ret=0, isnetpack=0, read_size=0;
	time_t s_time, c_time;

	// try to receive a correct net packet for 5s
	for (s_time = c_time = time(NULL); (c_time - s_time) < WAIT_RECV_SEC; c_time = time(NULL)) {
		ret = recv(sockfd, (BYTE*)&(net_pack.header), sizeof(net_pack.header), MSG_PEEK | MSG_DONTWAIT);
		if(ret >= (int)sizeof(net_pack.header)) {
			BYTE *peek_buf = (BYTE*)malloc(sizeof(net_pack.header) + net_pack.header.body_size);
			ret = recv(sockfd, peek_buf, sizeof(net_pack.header) + net_pack.header.body_size, MSG_PEEK | MSG_DONTWAIT);
			free(peek_buf);
			if(ret >= (int)(sizeof(net_pack.header) + net_pack.header.body_size)) {
				// correct net packet received
				isnetpack = 1;
				break;
			}
		}
		// wait 100ms
		usleep(100000);
	}

	// check if a correct net packet is waiting in socket buffer
	if (!isnetpack) {
		return 1;
	}

	// read the net packet from socket buffer
	read_size += recv(sockfd, (BYTE*)&(net_pack.header), sizeof(net_pack.header), 0);
	net_pack.body = (BYTE*)malloc(net_pack.header.body_size);
	read_size += recv(sockfd, net_pack.body, net_pack.header.body_size, 0);

	// check again if net packet is correct
	if (read_size != (int)(sizeof(net_pack.header) + net_pack.header.body_size)) {
		free(net_pack.body);
		*type = 0;
		*size = 0;
		*data = NULL;
		return 2;
	}

	// set returning data
    *type = net_pack.header.type;
    *size = net_pack.header.body_size;
    *data = net_pack.body;

    return 0;
}

void sflush(int sockfd) {
	BYTE buf[32];
	while (recv(sockfd, buf, 32, MSG_DONTWAIT) != -1);
	return;
}

STRUC_SSL_CONNECTION* ssl_connect (int sockfd, char *ca_pem_filename, char *expected_peer_subject, DWORD subject_len) {
	STRUC_SSL_CONNECTION *ssl_con = (STRUC_SSL_CONNECTION*)malloc(sizeof(STRUC_SSL_CONNECTION));
	ssl_con->sslHandle = NULL;
	ssl_con->sslContext = NULL;

	// Register the error strings for libcrypto & libssl
	SSL_load_error_strings();

	// Register the available ciphers and digests
	SSL_library_init();

	// New context saying we are a client, and using TLSv1.2
	ssl_con->sslContext = SSL_CTX_new(TLSv1_2_client_method());
	if (ssl_con->sslContext == NULL) {
		ERR_print_errors_fp(stderr);
		free(ssl_con);
		return NULL;
	}

	// load CA certificate for verification of peer certificate
	if(!SSL_CTX_load_verify_locations(ssl_con->sslContext, ca_pem_filename, NULL)) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// Create an SSL structure for the connection
	ssl_con->sslHandle = SSL_new(ssl_con->sslContext);
	if (ssl_con->sslHandle == NULL) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// Connect the SSL structure to our connection
	if (!SSL_set_fd(ssl_con->sslHandle, sockfd)) {
		ERR_print_errors_fp(stderr);
		SSL_shutdown(ssl_con->sslHandle);
		SSL_free(ssl_con->sslHandle);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// Initiate SSL handshake
	if (SSL_connect(ssl_con->sslHandle) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_shutdown(ssl_con->sslHandle);
		SSL_free(ssl_con->sslHandle);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// get verification result of the peer certificate
	if (SSL_get_verify_result(ssl_con->sslHandle) != X509_V_OK) {
		ERR_print_errors_fp(stderr);
		SSL_shutdown(ssl_con->sslHandle);
		SSL_free(ssl_con->sslHandle);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// check if peer has a certificate
	X509 *cert = SSL_get_peer_certificate(ssl_con->sslHandle);
	if(cert == NULL) {
		ERR_print_errors_fp(stderr);
		SSL_shutdown(ssl_con->sslHandle);
		SSL_free(ssl_con->sslHandle);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// check subject of the peer certificate
	if(memcmp(expected_peer_subject, cert->name, subject_len)) {
		err_printf("ERROR: SSL peer certificate has an unexpected subject (%s).\n", cert->name);
		SSL_shutdown(ssl_con->sslHandle);
		SSL_free(ssl_con->sslHandle);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}
	X509_free(cert);

	return ssl_con;
}

STRUC_SSL_CONNECTION* ssl_accept (int sockfd, char* cert_file, char* key_file) {
	STRUC_SSL_CONNECTION *ssl_con = (STRUC_SSL_CONNECTION*)malloc(sizeof(STRUC_SSL_CONNECTION));
	ssl_con->sslHandle = NULL;
	ssl_con->sslContext = NULL;

	// Register the error strings for libcrypto & libssl
	SSL_load_error_strings();

	// Register the available ciphers and digests
	SSL_library_init();

	// New context saying we are a client, and using TLSv1.2
	ssl_con->sslContext = SSL_CTX_new(TLSv1_2_server_method());
	if (ssl_con->sslContext == NULL) {
		ERR_print_errors_fp (stderr);
		free(ssl_con);
		return NULL;
	}

	// set the local certificate from CertFile
	if (SSL_CTX_use_certificate_file(ssl_con->sslContext, cert_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// set the private key from KeyFile (may be the same as CertFile)
	if (SSL_CTX_use_PrivateKey_file(ssl_con->sslContext, key_file, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	/// verify private key
	if (!SSL_CTX_check_private_key(ssl_con->sslContext)) {
		fprintf(stderr, "ERROR: Private key does not match the public certificate.\n");
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// Create an SSL structure for the connection
	ssl_con->sslHandle = SSL_new(ssl_con->sslContext);
	if (ssl_con->sslHandle == NULL) {
		ERR_print_errors_fp (stderr);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// Connect the SSL structure to our connection
	if (!SSL_set_fd(ssl_con->sslHandle, sockfd)) {
		ERR_print_errors_fp (stderr);
		SSL_shutdown(ssl_con->sslHandle);
		SSL_free(ssl_con->sslHandle);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	// Initiate SSL handshake
	if (SSL_accept(ssl_con->sslHandle) != 1) {
		ERR_print_errors_fp (stderr);
		SSL_shutdown(ssl_con->sslHandle);
		SSL_free(ssl_con->sslHandle);
		SSL_CTX_free(ssl_con->sslContext);
		free(ssl_con);
		return NULL;
	}

	return ssl_con;
}

int ssl_send_data(STRUC_SSL_CONNECTION* ssl_con, BYTE type, DWORD size, BYTE *data) {
	STRUC_NET_PACKET net_pack;
	DWORD write_size = 0;

	net_pack.header.type = type;
	net_pack.header.body_size = size;
	net_pack.body = data;

	write_size += SSL_write(ssl_con->sslHandle, (BYTE*)&(net_pack.header), sizeof(net_pack.header));
	write_size += SSL_write(ssl_con->sslHandle, net_pack.body, net_pack.header.body_size);

    if(write_size != (sizeof(net_pack.header) + size) ) {
    	return 1;
    }

    return 0;
}

int ssl_recv_data(STRUC_SSL_CONNECTION* ssl_con, BYTE *type, DWORD *size, BYTE **data) {
	STRUC_NET_PACKET net_pack;
	int isnetpack=0, header=0;
	time_t s_time, c_time;

	// try to receive a correct net packet for WAIT_RECV_SEC seconds
	for (s_time = c_time = time(NULL); (c_time - s_time) < WAIT_RECV_SEC; c_time = time(NULL)) {
		// get net packet header
		if (!header) {
			if(SSL_peek(ssl_con->sslHandle, (BYTE*)&(net_pack.header), sizeof(net_pack.header)) == sizeof(net_pack.header)) {
				SSL_read(ssl_con->sslHandle, (BYTE*)&(net_pack.header), sizeof(net_pack.header));
				net_pack.body = (BYTE*)malloc(net_pack.header.body_size);
				header = 1;
			}
		}

		// get net packet body
		if (header) {
			if(SSL_peek(ssl_con->sslHandle, net_pack.body, net_pack.header.body_size) == (int)net_pack.header.body_size) {
				SSL_read(ssl_con->sslHandle, net_pack.body, net_pack.header.body_size);
				isnetpack = 1;
				break;
			}
		}

		// wait 100ms
		usleep(100000);
	}

	// check if a correct net packet is waiting in socket buffer
	if (!isnetpack) {
		free(net_pack.body);
		*type = 0;
		*size = 0;
		*data = NULL;
		return 1;
	}

	// set returning data
    *type = net_pack.header.type;
    *size = net_pack.header.body_size;
    *data = net_pack.body;

    return 0;
}

void ssl_sflush(STRUC_SSL_CONNECTION* ssl_con) {
	BYTE buf[32];
	while (SSL_peek(ssl_con->sslHandle, buf, 32) != -1) {
		SSL_read(ssl_con->sslHandle, buf, 32);
	}
	return;
}

void ssl_disconnect (STRUC_SSL_CONNECTION *ssl_con) {

	// shutdown SSL connection and free handle
	if (ssl_con->sslHandle) {
		SSL_shutdown(ssl_con->sslHandle);
		SSL_free(ssl_con->sslHandle);
	}

	// free SSL context
	if (ssl_con->sslContext) {
		SSL_CTX_free(ssl_con->sslContext);
	}

	free(ssl_con);
}
