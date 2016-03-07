#include "xsgs.h"
#include "demo.h"

extern int verbose;

typedef struct {
	int help_flag;
	char *server_address;
	char *server_port;
} CMD_OPT;

typedef struct {
	int connfd;
	struct sockaddr_in cli_addr;
} CLIENT_THREAD_ARGS;

void print_help(char **argv);
int parse_options(CMD_OPT *opts, int argc, char **argv);
int server(char* server_address, char* server_port);
void sig_handler(int signo);
void* client_thread(CLIENT_THREAD_ARGS *args);

XSGS_PUBLIC_KEY *gpk = NULL;
int listenfd = 0;
pthread_t tid[MAX_THREAD];
FILE *log_fp = NULL;
pthread_mutex_t log_file_lock;

int main(int argc, char **argv) {
	int ret = 0;

	CMD_OPT opts;
	memset(&opts, 0, sizeof(CMD_OPT));
	ret = parse_options(&opts, argc, argv);

	if (ret || opts.help_flag) {
		print_help(argv);
		ret = -1;
	} else {
		ret = server(opts.server_address, opts.server_port);
	}

	return ret;
}

void print_help(char **argv) {
	struct in_addr ip;
	ip.s_addr = htonl(INADDR_LOOPBACK);

	printf("\n***  Demonstration Server  ***\n");
	printf("Author: Martin Goll\n");
	printf("Contact: martin.goll@rub.de\n");
	printf("****************************\n\n");
	printf("Syntax: %s [-v] [--server-address fqdn|ip] [--server-port port]\n\n", basename(argv[0]));
	printf("%5s %-25s %s\n", "-?,", "--help", "Show this help message.");
	printf("%5s %-25s %s\n", "-v,", "--verbose", "More verbose output.");
	printf("%5s %-25s %s%s.\n", "", "--server-address=fqdn|ip", "Modifies the server address. Default is ", inet_ntoa(ip));
	printf("%5s %-25s %s%s.\n", "", "--server-port=port", "Modifies the server port. Default is ", SERVER_PORT);

	return;
}

// Parses the command line and fills the options structure, returns non-zero on error
int parse_options(CMD_OPT *opts, int argc, char **argv) {
	while (1) {
		static struct option long_options[] = {
				{ "verbose", no_argument, NULL, 1 },
				{ "help", no_argument, NULL, 1 },
				{ "server-address", required_argument, NULL, 0 },
				{ "server-port", required_argument, NULL, 0 },
				{ 0, 0, 0, 0 }
		};
		long_options[0].flag = &verbose;
		long_options[1].flag = &(opts->help_flag);

		// getopt_long stores the option index here.
		int option_index = 0;

		int c = getopt_long(argc, argv, "v?", long_options, &option_index);

		// Detect the end of the options.
		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			// If this option set a flag, do nothing else now.
			if (long_options[option_index].flag != 0) {
				break;
			}

			if (strcmp(long_options[option_index].name, "server-address") == 0) {
				opts->server_address = optarg;
			} else if (strcmp(long_options[option_index].name, "server-port") == 0) {
				opts->server_port = optarg;
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
			opts->help_flag = 1;
			break;

		default:
			return 1;
		}
	}
	return 0;
}

int server(char *server_address, char *server_port) {
	CLIENT_THREAD_ARGS args[MAX_THREAD];
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t cli_len;
	int ret = 0, i = 0;

	verb_printf("\n+++ Demonstration Server +++\n\n");

	memset(tid, 0, sizeof(tid[0]) * MAX_THREAD);

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err_printf("ERROR: Can't catch SIGINT\n");
		return 1;
	}

	// import group keys
	gpk = xsgs_gpk_import_file(KEY_PATH "xsgs_gpk.key");
	if (gpk == NULL) {
		return 2;
	}

	// open log file
	log_fp = fopen(LOG_PATH "server.log", "ab");
	if (log_fp == NULL) {
		err_printf("ERROR: Can't open log file: %s (%sserver.log)\n", strerror(errno), LOG_PATH);
		gpk_clear(gpk);
		return 3;
	}

	// initialize log file mutex
	if (pthread_mutex_init(&log_file_lock, NULL) != 0) {
		err_printf("ERROR: Can't initialize log file mutex: %s\n", strerror(errno));
		gpk_clear(gpk);
		fclose(log_fp);
		return 4;
	}

	// create server socket
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		err_printf("ERROR: Can't create server socket: %s\n", strerror(errno));
		gpk_clear(gpk);
		fclose(log_fp);
		pthread_mutex_destroy(&log_file_lock);
		return 5;
	}

	// set server socket address and port
	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	if (server_address != NULL) {
		char ip[20];
		if (hostname_to_ip(server_address, ip)) {
			gpk_clear(gpk);
			fclose(log_fp);
			pthread_mutex_destroy(&log_file_lock);
			close(listenfd);
			return 6;
		}
		inet_aton(ip, &serv_addr.sin_addr);
	} else {
		serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	if (server_port != NULL) {
		serv_addr.sin_port = htons(atoi(server_port));
	} else {
		serv_addr.sin_port = htons(atoi(SERVER_PORT));
	}

	// bind server socket
	ret = bind(listenfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
	if (ret != 0) {
		err_printf("ERROR: Can't bind server socket: %s\n", strerror(errno));
		gpk_clear(gpk);
		fclose(log_fp);
		pthread_mutex_destroy(&log_file_lock);
		close(listenfd);
		return 7;
	}

	// listen server socket
	listen(listenfd, MAX_PENDING_CON_CNT);

	// wait for client connection
	verb_printf("Waiting for clients on %s:%u (Press Ctrl + C to stop) ...\n", inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));
	while (1) {
		// accept client connection
		cli_len = sizeof(cli_addr);
		args[i].connfd = accept(listenfd, (struct sockaddr*) &cli_addr, &cli_len);
		args[i].cli_addr = cli_addr;
		verb_printf("\nAccepted client connection from %s:%u -> create handler thread: ", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

		// create client connection thread
		ret = pthread_create(&tid[i], NULL, (void*) &client_thread, (void*) &args[i]);
		if (ret != 0) {
			verb_printf("failed (%s)\n", strerror(errno));
			if (verbose == 0) err_printf("ERROR: Can't create client connection thread: %s\n", strerror(errno));
		} else {
			verb_printf("successfull (%lu)\n", tid[i]);
		}
		i = (i + 1) % MAX_THREAD;
		if (tid[i] != 0) {
			pthread_join(tid[i], NULL);
		}
	}

	return 0;
}

void sig_handler(int signo) {
	verb_printf("\nCleaning up ... ");

	// join process threads
	for (int i = 0; i < MAX_THREAD; i++) {
		if (tid[i] != 0) {
			pthread_join(tid[i], NULL);
		}
	}

	// close listen socket
	if (listenfd != 0) {
		close(listenfd);
	}

	// clear group public key
	if (gpk != NULL) {
		gpk_clear(gpk);
	}

	// close log file
	fclose(log_fp);

	// destroy log file mutex
	pthread_mutex_destroy(&log_file_lock);

	verb_printf("done\n");

	exit(signo);
}

void* client_thread(CLIENT_THREAD_ARGS *args) {
	DWORD size = 0;
	BYTE type=0, *data=NULL;
	int ret=0, isvalid=0;
	pthread_t id = pthread_self();
	XSGS_SIGNED_MSG *sig_msg;
	char dmp_filename[100], log_line[300];
	FILE* fp=NULL;
	BYTE *hash=NULL;
	STRUC_SSL_CONNECTION *ssl_con=NULL;

	memset(dmp_filename, 0, 100);
	memset(log_line, 0, 300);

	// accept SSL connection from client
	ssl_con = ssl_accept(args->connfd, CERT_PATH "servercert.pem", KEY_PATH "serverkey.pem");
	if(ssl_con == NULL) {
		err_printf("[%lu] ERROR: Can't accept SSL connection from client (%s:%u).\n", id, inet_ntoa(args->cli_addr.sin_addr), ntohs(args->cli_addr.sin_port));
		close(args->connfd);
		return NULL;
	}

	// receive message from client
	ret = ssl_recv_data(ssl_con, &type, &size, &data);
	if (ret) {
		err_printf("[%lu] ERROR: Can't receive data from client (%s:%u).\n", id, inet_ntoa(args->cli_addr.sin_addr), ntohs(args->cli_addr.sin_port));
		ssl_disconnect(ssl_con);
		close(args->connfd);
		return NULL;
	}

	// handle received data type
	switch (type) {
		// received unknown message
		default:
		// received signed message
		case TYPE_SIGNED_MSG:
			verb_printf("[%lu] Received SIGNED_MSG (%u bytes) from client (%s:%u).\n", id, size, inet_ntoa(args->cli_addr.sin_addr), ntohs(args->cli_addr.sin_port));

			// send signed message acknowledge
			hash = (BYTE*)malloc(SIGNED_MSG_ACK_HASH_BITS / 8);
			xsgs_hash(data, size * 8, hash, SIGNED_MSG_ACK_HASH_BITS);
			ret = ssl_send_data(ssl_con, TYPE_SIGNED_MSG_ACK, SIGNED_MSG_ACK_HASH_BITS / 8, hash);
			if (ret) {
				err_printf("[%lu] ERROR: Can't send SIGNED_MSG_ACK (%d bytes) to client (%s:%u): %s\n", id, size, inet_ntoa(args->cli_addr.sin_addr), ntohs(args->cli_addr.sin_port), strerror(errno));
				ssl_disconnect(ssl_con);
				close(args->connfd);
				free(hash);
				return NULL;
			}
			verb_printf("[%lu] Send SIGNED_MSG_ACK (%d bytes) to client (%s:%u).\n", id, size, inet_ntoa(args->cli_addr.sin_addr), ntohs(args->cli_addr.sin_port));

			// shutdown SSL layer for connection
			ssl_disconnect(ssl_con);

			// close client connection
			close(args->connfd);

			// parse signed message data to signed message structure
			sig_msg = xsgs_sm_import_buf(gpk, data);

			// verify signed data
			isvalid = xsgs_verify(gpk, sig_msg);
			sm_clear(sig_msg);

			// dump received packet: { BYTE isvalid, DWORD msg_size, BYTE[] msg = { DWORD pt_size, DWORD ct_size, BYTE[] pt, BYTE[] ct }, BYTE[] sig } > $hash.dmp
			sprintf(dmp_filename, LOG_PATH);
			for(int i=LOG_PATH_LEN; i < (LOG_PATH_LEN + SIGNED_MSG_ACK_HASH_BITS / 8); i++) {
				sprintf(&dmp_filename[i], "%02x", hash[i - LOG_PATH_LEN]);
			}
			sprintf(&dmp_filename[LOG_PATH_LEN + SIGNED_MSG_ACK_HASH_BITS / 8], ".dmp");
			free(hash);
			fp = fopen(dmp_filename, "wb");
			if (fp == NULL) {
				err_printf("[%lu] Error opening dmp file: %s (%s)\n", id, strerror(errno), dmp_filename);
				free(data);
				return NULL;
			}
			fwrite(&isvalid, 1, 1, fp);
			fwrite(data, 1, size, fp);
			fclose(fp);
			verb_printf("[%lu] Dumped { BYTE isvalid, DWORD msg_size, BYTE[] msg = { DWORD pt_size, DWORD ct_size, BYTE[] pt, BYTE[] ct }, BYTE[] sig } (%u bytes) to %s.\n", id, size+1, dmp_filename);

			// dump received packet to $hash.txt
			sprintf(&dmp_filename[LOG_PATH_LEN + SIGNED_MSG_ACK_HASH_BITS / 8], ".txt");
			fp = fopen(dmp_filename, "wb");
			if (fp == NULL) {
				err_printf("[%lu] Error opening dmp file: %s (%s)\n", id, strerror(errno), dmp_filename);
				free(data);
				return NULL;
			}
			memset(log_line, 0, 300);
			ret = sprintf(log_line, "*** SIGNED MESSAGE DUMP***\n\nVerification Result: %u\n\nSigned Message Size: %u\n\nPaintext Message Part (%u bytes):\n", isvalid, size, *(DWORD*)&data[4]);
			fwrite(log_line, 1, ret, fp);
			fwrite(&data[12], 1, *(DWORD*)&data[4], fp);
			fwrite("\n\n", 1, 2, fp);
			memset(log_line, 0, 300);
			ret = sprintf(log_line, "Ciphertext Message Part (%u bytes):\n", *(DWORD*)&data[8]);
			fwrite(log_line, 1, ret, fp);
			for(DWORD i=0; i < *(DWORD*)&data[8]; i++) {
				sprintf(log_line, "%02x", data[12 + *(DWORD*)&data[4] + i]);
				fwrite(log_line, 1, 2, fp);
			}
			fwrite("\n\n", 1, 2, fp);
			memset(log_line, 0, 300);
			ret = sprintf(log_line, "XSGS Message Signature (%u bytes):\n", size - 4 - ntohl(*(DWORD*)&data[0]));
			fwrite(log_line, 1, ret, fp);
			for(DWORD i=0; i < (size - 4 - ntohl(*(DWORD*)&data[0])); i++) {
				sprintf(log_line, "%02x", data[4 + ntohl(*(DWORD*)&data[0]) + i]);
				fwrite(log_line, 1, 2, fp);
			}
			fwrite("\n\n", 1, 2, fp);
			fclose(fp);
			free(data);
			verb_printf("[%lu] Dumped { BYTE isvalid, DWORD msg_size, BYTE[] msg = { DWORD pt_size, DWORD ct_size, BYTE[] pt, BYTE[] ct }, BYTE[] sig } (%u bytes) to %s.\n", id, size+1, dmp_filename);

			// write log entry: { TS: received signed msg $hash ( verification: [success|failed] )\n } >> server.log
			time_t TS = time(NULL);
			struct tm *ptm = gmtime(&TS);
			ptm->tm_hour = (ptm->tm_hour + 2) % 24;
			char timestamp[30];
			memset(timestamp, 0, 30);
			strftime(timestamp, 30, "%Y-%m-%d %H:%M:%S", ptm);
			dmp_filename[LOG_PATH_LEN + SIGNED_MSG_ACK_HASH_BITS / 8] = 0;
			memset(log_line, 0, 300);
			if(isvalid) {
				ret = sprintf(log_line, "%s: received a signed message %s (verification: success)\n", timestamp, &dmp_filename[LOG_PATH_LEN]);
			}
			else {
				ret = sprintf(log_line, "%s: received a signed message %s (verification: failed)\n", timestamp, &dmp_filename[LOG_PATH_LEN]);
			}
			log_line[ret] = 0;
			pthread_mutex_lock(&log_file_lock);
			fwrite(log_line, 1, ret, log_fp);
			fflush(log_fp);
			pthread_mutex_unlock(&log_file_lock);

			break;
	}

	//verb_printf("[%lu] Finished.\n", id);
	return NULL;
}
