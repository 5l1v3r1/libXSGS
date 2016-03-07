#include "xsgs.h"
#include "demo.h"

extern int verbose;

typedef struct {
	int help_flag;
	char *client_address;
	char *client_port;
	char *server_address;
	char *server_port;
} CMD_OPT;

typedef struct {
	int connfd;
	char* server_address;
	char* server_port;
	struct sockaddr_in proc_addr;
} IPC_THREAD_ARGS;

void print_help(char **argv);
int parse_options(CMD_OPT *opts, int argc, char **argv);
int client(char *client_address, char *client_port, char *server_address, char *server_port);
void sig_handler(int signo);
void *ipc_thread(IPC_THREAD_ARGS *args);

XSGS_PUBLIC_KEY* gpk = NULL;
XSGS_USER_KEY* uk = NULL;
XSGS_USER_CERT* ucert = NULL;
int listenfd = 0;
pthread_t tid[MAX_THREAD];

int main(int argc, char **argv) {
	int ret = 0;

	CMD_OPT opts;
	memset(&opts, 0, sizeof(CMD_OPT));
	ret = parse_options(&opts, argc, argv);

	if (ret || opts.help_flag) {
		print_help(argv);
		ret = -1;
	} else {
		ret = client(opts.client_address, opts.client_port, opts.server_address,
				opts.server_port);
	}

	return ret;
}

void print_help(char **argv) {
	struct in_addr ip;
	ip.s_addr = htonl(INADDR_LOOPBACK);

	printf("\n***  Demonstration Client  ***\n");
	printf("Author: Martin Goll\n");
	printf("Contact: martin.goll@rub.de\n");
	printf("****************************\n\n");
	printf("Syntax: %s [-v] [--client-address fqdn|ip] [--client-port port] [--server-address fqdn|ip] [--server-port port]\n\n", basename(argv[0]));
	printf("%5s %-25s %s\n", "-?,", "--help", "Show this help message.");
	printf("%5s %-25s %s\n", "-v,", "--verbose", "More verbose output.");
	printf("%5s %-25s %s%s.\n", "", "--client-address=fqdn|ip", "Modifies the client address for incoming signature requests. Default is ", inet_ntoa(ip));
	printf("%5s %-25s %s%s.\n", "", "--client-port=port", "Modifies the client port for incoming signature requests. Default is ", CLIENT_PORT);
	printf("%5s %-25s %s%s.\n", "", "--server-address=fqdn|ip", "Modifies the server address for committing signed data. Default is ", inet_ntoa(ip));
	printf("%5s %-25s %s%s.\n", "", "--server-port=port", "Modifies the server port for committing signed data. Default is ", SERVER_PORT);

	return;
}

// Parses the command line and fills the options structure, returns non-zero on error
int parse_options(CMD_OPT *opts, int argc, char **argv) {
	while (1) {
		static struct option long_options[] = {
				{ "verbose", no_argument, NULL, 1 },
				{ "help", no_argument, NULL, 1 },
				{ "client-address", required_argument, NULL, 0 },
				{ "client-port", required_argument, NULL, 0 },
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

			if (strcmp(long_options[option_index].name, "client-address") == 0) {
				opts->client_address = optarg;
			} else if (strcmp(long_options[option_index].name, "client-port") == 0) {
				opts->client_port = optarg;
			} else if (strcmp(long_options[option_index].name, "server-address") == 0) {
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

int client(char *client_address, char *client_port, char *server_address, char *server_port) {
	IPC_THREAD_ARGS args[MAX_THREAD];
	struct sockaddr_in cli_addr, proc_addr;
	socklen_t proc_len;
	int ret = 0, i = 0;

	verb_printf("\n+++ Demonstration Client +++\n\n");

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
	uk = xsgs_uk_import_file(gpk, KEY_PATH "xsgs_uk.key");
	if (uk == NULL) {
		gpk_clear(gpk);
		return 3;
	}
	ucert = xsgs_ucert_import_file(gpk, CERT_PATH "xsgs_ucert.cert");
	if (ucert == NULL) {
		gpk_clear(gpk);
		uk_clear(uk);
		return 4;
	}

	// create client socket
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		err_printf("ERROR: Can't create client socket: %s\n", strerror(errno));
		gpk_clear(gpk);
		uk_clear(uk);
		ucert_clear(ucert);
		return 5;
	}

	// set client socket address and port
	memset(&cli_addr, '0', sizeof(cli_addr));
	cli_addr.sin_family = AF_INET;
	if (client_address != NULL) {
		char ip[20];
		if (hostname_to_ip(client_address, ip)) {
			close(listenfd);
			gpk_clear(gpk);
			uk_clear(uk);
			ucert_clear(ucert);
			return 6;
		}
		inet_aton(ip, &cli_addr.sin_addr);
	} else {
		cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	if (client_port != NULL) {
		cli_addr.sin_port = htons(atoi(client_port));
	} else {
		cli_addr.sin_port = htons(atoi(CLIENT_PORT));
	}

	// bind client socket
	ret = bind(listenfd, (struct sockaddr*) &cli_addr, sizeof(cli_addr));
	if (ret != 0) {
		err_printf("ERROR: Can't bind client socket: %s\n", strerror(errno));
		close(listenfd);
		gpk_clear(gpk);
		uk_clear(uk);
		ucert_clear(ucert);
		return 7;
	}

	// listen ipc socket
	listen(listenfd, MAX_PENDING_CON_CNT);

	// wait for local process connection
	verb_printf("Waiting for processes on %s:%u (Press Ctrl + C to stop) ...\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
	while (1) {
		// accept process connection
		proc_len = sizeof(cli_addr);
		args[i].connfd = accept(listenfd, (struct sockaddr*) &proc_addr, &proc_len);
		args[i].server_address = server_address;
		args[i].server_port = server_port;
		args[i].proc_addr = proc_addr;
		verb_printf("\nAccepted process connection from %s:%u -> create handler thread: ", inet_ntoa(proc_addr.sin_addr), ntohs(proc_addr.sin_port));

		// create process connection thread
		ret = pthread_create(&tid[i], NULL, (void*) &ipc_thread, (void*) &args[i]);
		if (ret != 0) {
			verb_printf("failed (%s)\n", strerror(errno));
			if (verbose == 0) err_printf("ERROR: Can't create process connection thread: %s\n", strerror(errno));
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

	// clear key and cert memory
	if (gpk != NULL) {
		gpk_clear(gpk);
	}
	if (uk != NULL) {
		uk_clear(uk);
	}
	if (ucert != NULL) {
		ucert_clear(ucert);
	}

	verb_printf("done\n");

	exit(signo);
}

void* ipc_thread(IPC_THREAD_ARGS *args) {
	DWORD size = 0;
	BYTE type=0, *data=NULL;
	STRUC_PROC_MSG proc_msg;
	int sockfd=0, ret=0;
	struct sockaddr_in serv_addr;
	pthread_t id = pthread_self();
	BYTE *hash=NULL;
	STRUC_SSL_CONNECTION *ssl_con=NULL;

	// receive message from process
	ret = recv_data(args->connfd, &type, &size, &data);
	if (ret) {
		err_printf("[%lu] ERROR: Can't receive data from process(%s:%u).\n", id, inet_ntoa(args->proc_addr.sin_addr), ntohs(args->proc_addr.sin_port));
		close(args->connfd);
		return NULL;
	}

	// handle received message
	switch (type) {
		// received unknown message
		default:
		// received raw data message
		case TYPE_RAW_DATA_MSG:
			verb_printf("[%lu] Received RAW_DATA_MSG (%u bytes) from process (%s:%u).\n", id, size, inet_ntoa(args->proc_addr.sin_addr), ntohs(args->proc_addr.sin_port));

			// close process connection
			close(args->connfd);

			// parse data to process message structure
			proc_msg.data1_size = *(DWORD*)data;
			proc_msg.data1 = &data[8];

			// encrypt data2 of process message
			xsgs_rsa_encrypt(CERT_PATH "openercert.pem", &data[8 + proc_msg.data1_size], *(DWORD*)&data[4], &proc_msg.data2, &proc_msg.data2_size);

			// parse process message to signed message structure
			XSGS_SIGNED_MSG *sig_msg = (XSGS_SIGNED_MSG*)malloc(sizeof(XSGS_SIGNED_MSG));
			sig_msg->msg_len = 8 + proc_msg.data1_size + proc_msg.data2_size;
			sig_msg->msg = (BYTE*)malloc(sig_msg->msg_len);
			memcpy(&sig_msg->msg[0], (BYTE*)&proc_msg.data1_size, 4);
			memcpy(&sig_msg->msg[4], (BYTE*)&proc_msg.data2_size, 4);
			memcpy(&sig_msg->msg[8], proc_msg.data1, proc_msg.data1_size);
			memcpy(&sig_msg->msg[8 + proc_msg.data1_size], proc_msg.data2, proc_msg.data2_size);
			free(proc_msg.data2);
			free(data);

			// sign process message
			xsgs_sign(gpk, ucert, uk, sig_msg);

			// parse signed message to byte array
			size = xsgs_sm_export_buf(&data, sig_msg);
			sm_clear(sig_msg);

			// create server socket
			sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (sockfd < 0) {
				err_printf("[%lu] ERROR: Can't create server socket: %s\n", id, strerror(errno));
				free(data);
				return NULL;
			}

			// create server address structure
			memset(&serv_addr, '0', sizeof(serv_addr));
			serv_addr.sin_family = AF_INET;
			if (args->server_address != NULL) {
				char ip[20];
				if (hostname_to_ip(args->server_address, ip)) {
					close(sockfd);
					free(data);
					return NULL;
				}
				inet_aton(ip, &serv_addr.sin_addr);
			} else {
				serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			}
			if (args->server_port != NULL) {
				serv_addr.sin_port = htons(atoi(args->server_port));
			} else {
				serv_addr.sin_port = htons(atoi(SERVER_PORT));
			}

			// connect to server
			ret = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
			if(ret < 0) {
				err_printf("[%lu] ERROR: Can't connect to server (%s:%u): %s\n", id, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port), strerror(errno));
				close(sockfd);
				free(data);
				return NULL;
			}

			// establish SSL connection to server
			ssl_con = ssl_connect(sockfd, CERT_PATH "cacert.pem", SERVER_CERT_SUBJECT, SERVER_CERT_SUBJECT_LEN);
			if(ssl_con == NULL) {
				err_printf("[%lu] ERROR: Can't establish SSL connection to server (%s:%u).\n", id, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));
				close(sockfd);
				free(data);
				return NULL;
			}

			// create hash for acknowledge
			hash = (BYTE*)malloc(SIGNED_MSG_ACK_HASH_BITS / 8);
			xsgs_hash(data, size * 8, hash, SIGNED_MSG_ACK_HASH_BITS);

			for (DWORD buf_len = 0; buf_len == 0; ) {

				// send signed message to server
				ret = ssl_send_data(ssl_con, TYPE_SIGNED_MSG, size, data);
				if (ret) {
					err_printf("[%lu] Can't send SIGNED_MSG (%d bytes) to server (%s:%u): %s\n", id, size, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port), strerror(errno));
					ssl_disconnect(ssl_con);
					close(sockfd);
					free(data);
					free(hash);
					return NULL;
				}
				verb_printf("[%lu] Send SIGNED_MSG (%d bytes) to server (%s:%u).\n", id, size, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));

				// receive message from server
				BYTE *buf = NULL;
				ret = ssl_recv_data(ssl_con, &type, &buf_len, &buf);
				if (ret) {
					err_printf("[%lu] ERROR: Can't receive data from server(%s:%u).\n", id, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));
					ssl_sflush(ssl_con);
				}
				else {
					free(data);
					data = buf;
					size = buf_len;
				}
			}

			// handle received data type
			switch (type) {
				// received unknown message
				default:
				// received acknowledge for the signed message from server
				case TYPE_SIGNED_MSG_ACK:
					verb_printf("[%lu] Received SIGNED_MSG_ACK (%u bytes) from server (%s:%u).\n", id, size, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));

					// shutdown SSL layer for connection
					ssl_disconnect(ssl_con);
					// close server connection
					close(sockfd);

					// check acknowledge hash
					if(memcmp(data, hash, SIGNED_MSG_ACK_HASH_BITS / 8)) {
						err_printf("[%lu] ERROR: SIGNED_MSG_ACK (%u bytes) from server (%s:%u) is incorrect.\n", id, size, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));
						free(data);
						free(hash);
						return NULL;
					}
					verb_printf("[%lu] SIGNED_MSG_ACK (%u bytes) from server (%s:%u) is correct.\n", id, size, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));

					free(data);
					free(hash);

					break;
			}

			break;
	}

	//verb_printf("[%lu] Finished.\n", id);
	return NULL;
}

