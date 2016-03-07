#ifndef XSGS_DEMO_H
#define XSGS_DEMO_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <libgen.h>
#include <string.h>
#include <pthread.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef XSGS_H
	typedef uint8_t		BYTE;
	typedef uint16_t	WORD;
	typedef uint32_t	DWORD;
	typedef uint64_t	QWORD;
#endif


#define CLIENT_PORT	"5001"
#define SERVER_PORT	"5002"
#define GRPMGR_PORT	"5003"

#define MAX_THREAD	4

#define MAX_PENDING_CON_CNT	10

#define LOG_PATH		"log/"
#define LOG_PATH_LEN	(sizeof(LOG_PATH) - 1)
#define CERT_PATH		"cert_store/"
#define CERT_PATH_LEN	(sizeof(CERT_PATH) - 1)
#define KEY_PATH		"key_store/"
#define KEY_PATH_LEN	(sizeof(KEY_PATH) - 1)
#define DB_PATH			"database/"
#define DB_PATH_LEN		(sizeof(DB_PATH) - 1)

#define SERVER_CERT_SUBJECT		"/C=DE/ST=Nordrhein-Westfalen/O=System Security/OU=Development/CN=server/emailAddress=martin.goll@rub.de"
#define SERVER_CERT_SUBJECT_LEN	(sizeof(SERVER_CERT_SUBJECT) - 1)

#define TYPE_RAW_DATA_MSG	0
#define TYPE_SIGNED_MSG		1
#define TYPE_SIGNED_MSG_ACK 2
#define TYPE_JPD1_MSG		3
#define TYPE_JPD2_MSG		4
#define TYPE_JPD3_MSG		5
#define TYPE_JPD4_MSG		6

#define SIGNED_MSG_ACK_HASH_BITS	256

#define WAIT_RECV_SEC	10

#define verb_printf(...)	if (verbose == 1) {					\
								fprintf(stdout, __VA_ARGS__);	\
								fflush(stdout);					\
							}
#define err_printf(...) fprintf(stderr, __VA_ARGS__); fflush(stderr);

#pragma pack(push, 1)
typedef struct {
    struct {
        BYTE type;
        DWORD body_size;
    } header;
    BYTE* body;
} STRUC_NET_PACKET;
#pragma pack(pop)

typedef struct {
	DWORD data1_size;	// size of data1 in bytes
	DWORD data2_size;	// size of data2 in bytes
	BYTE *data1;		// data which will be signed plain
	BYTE *data2;		// data which will be encrypted and then signed
} STRUC_PROC_MSG;

typedef struct {
    SSL *sslHandle;
    SSL_CTX *sslContext;
} STRUC_SSL_CONNECTION;

// resolve fully qualified domain name
int hostname_to_ip(char *hostname, char *ip);

// send data with net packet structure over socket
int send_data(int sockfd, BYTE type, DWORD size, BYTE *data);

// receive data with net packet structure over socket
int recv_data(int sockfd, BYTE *type, DWORD *size, BYTE **data);

// flush socket buffer (clear)
void sflush(int sockfd);

// establish SSL connection
STRUC_SSL_CONNECTION* ssl_connect (int sockfd, char *ca_pem_filename, char *expected_peer_subject, DWORD subject_len);
STRUC_SSL_CONNECTION* ssl_accept (int sockfd, char* cert_file, char* key_file);

// send data with net packet structure over SSL socket
int ssl_send_data(STRUC_SSL_CONNECTION* ssl_con, BYTE type, DWORD size, BYTE *data);

// receive data with net packet structure over SSL socket
int ssl_recv_data(STRUC_SSL_CONNECTION* ssl_con, BYTE *type, DWORD *size, BYTE **data);

// flush SSL socket buffer (clear)
void ssl_sflush(STRUC_SSL_CONNECTION* ssl_con);

// close SSL connection and free SSL structures
void ssl_disconnect (STRUC_SSL_CONNECTION *ssl_con);

#endif // XSGS_DEMO_H
