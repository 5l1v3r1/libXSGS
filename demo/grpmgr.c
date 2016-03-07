// TODO: send gpk on user join, revoke user -> update all remaining users over TLS

#include "xsgs.h"
#include "demo.h"

extern int verbose;

typedef struct {
	int help_flag;
	char *grpmgr_address;
	char *grpmgr_port;
} CMD_OPT;

typedef struct {
	int connfd;
	struct sockaddr_in usr_addr;
} USER_THREAD_ARGS;

void print_help(char **argv);
int parse_options(CMD_OPT *opts, int argc, char **argv);
int grpmgr(char* grpmgr_address, char* grpmgr_port);
void sig_handler(int signo);
void* user_thread(USER_THREAD_ARGS *args);
int run_join(int sockfd, struct sockaddr_in *usr_addr, pthread_t id, BYTE type, BYTE *data, DWORD size, char *upk_pem_filename);

XSGS_PAILLIER_PUBKEY *ppk=NULL;
XSGS_PUBLIC_KEY *gpk = NULL;
XSGS_ISSUER_KEY *ik=NULL;
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
		ret = grpmgr(opts.grpmgr_address, opts.grpmgr_port);
	}

	return ret;
}

void print_help(char **argv) {
	struct in_addr ip;
	ip.s_addr = htonl(INADDR_LOOPBACK);

	printf("\n***  Demonstration Group Manager  ***\n");
	printf("Author: Martin Goll\n");
	printf("Contact: martin.goll@rub.de\n");
	printf("****************************\n\n");
	printf("Syntax: %s [-v] [--grpmgr-address fqdn|ip] [--grpmgr-port port]\n\n", basename(argv[0]));
	printf("%5s %-25s %s\n", "-?,", "--help", "Show this help message.");
	printf("%5s %-25s %s\n", "-v,", "--verbose", "More verbose output.");
	printf("%5s %-25s %s%s.\n", "", "--grpmgr-address=fqdn|ip", "Modifies the group manager address. Default is ", inet_ntoa(ip));
	printf("%5s %-25s %s%s.\n", "", "--grpmgr-port=port", "Modifies the group manager port. Default is ", GRPMGR_PORT);

	return;
}

// Parses the command line and fills the options structure, returns non-zero on error
int parse_options(CMD_OPT *opts, int argc, char **argv) {
	while (1) {
		static struct option long_options[] = {
				{ "verbose", no_argument, NULL, 1 },
				{ "help", no_argument, NULL, 1 },
				{ "grpmgr-address", required_argument, NULL, 0 },
				{ "grpmgr-port", required_argument, NULL, 0 },
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

			if (strcmp(long_options[option_index].name, "grpmgr-address") == 0) {
				opts->grpmgr_address = optarg;
			} else if (strcmp(long_options[option_index].name, "grpmgr-port") == 0) {
				opts->grpmgr_port = optarg;
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

int grpmgr(char *grpmgr_address, char *grpmgr_port) {
	USER_THREAD_ARGS args[MAX_THREAD];
	struct sockaddr_in grpmgr_addr, usr_addr;
	socklen_t usr_len;
	int ret = 0, i = 0;

	verb_printf("\n+++ Demonstration Group Manager +++\n\n");

	memset(tid, 0, sizeof(tid[0]) * MAX_THREAD);

	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		err_printf("ERROR: Can't catch SIGINT\n");
		return 1;
	}

	// import paillier public key
	ppk = xsgs_ppk_import_file(KEY_PATH "xsgs_ppk.key");
	if (ppk == NULL) {
		return 2;
	}

	// import group public key
	gpk = xsgs_gpk_import_file(KEY_PATH "xsgs_gpk.key");
	if (gpk == NULL) {
		ppk_clear(ppk);
		return 3;
	}

	// import secret issuer key
	ik = xsgs_ik_import_file(gpk, KEY_PATH "xsgs_ik.key");
	if (ik == NULL) {
		ppk_clear(ppk);
		gpk_clear(gpk);
		return 3;
	}

	// open log file
	log_fp = fopen(LOG_PATH "grpmgr.log", "ab");
	if (log_fp == NULL) {
		err_printf("ERROR: Can't open log file: %s (%sgrpmgr.log)\n", strerror(errno), LOG_PATH);
		ppk_clear(ppk);
		gpk_clear(gpk);
		ik_clear(ik);
		return 4;
	}

	// initialize log file mutex
	if (pthread_mutex_init(&log_file_lock, NULL) != 0) {
		err_printf("ERROR: Can't initialize log file mutex: %s\n", strerror(errno));
		ppk_clear(ppk);
		gpk_clear(gpk);
		ik_clear(ik);
		fclose(log_fp);
		return 5;
	}

	// create group manager socket
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		err_printf("ERROR: Can't create group manager socket: %s\n", strerror(errno));
		ppk_clear(ppk);
		gpk_clear(gpk);
		ik_clear(ik);
		fclose(log_fp);
		pthread_mutex_destroy(&log_file_lock);
		return 6;
	}

	// set group manager socket address and port
	memset(&grpmgr_addr, '0', sizeof(grpmgr_addr));
	grpmgr_addr.sin_family = AF_INET;
	if (grpmgr_address != NULL) {
		char ip[20];
		if (hostname_to_ip(grpmgr_address, ip)) {
			ppk_clear(ppk);
			gpk_clear(gpk);
			ik_clear(ik);
			fclose(log_fp);
			pthread_mutex_destroy(&log_file_lock);
			close(listenfd);
			return 7;
		}
		inet_aton(ip, &grpmgr_addr.sin_addr);
	} else {
		grpmgr_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	if (grpmgr_port != NULL) {
		grpmgr_addr.sin_port = htons(atoi(grpmgr_port));
	} else {
		grpmgr_addr.sin_port = htons(atoi(GRPMGR_PORT));
	}

	// bind group manager socket
	ret = bind(listenfd, (struct sockaddr*) &grpmgr_addr, sizeof(grpmgr_addr));
	if (ret != 0) {
		err_printf("ERROR: Can't bind group manager socket: %s\n", strerror(errno));
		ppk_clear(ppk);
		gpk_clear(gpk);
		ik_clear(ik);
		fclose(log_fp);
		pthread_mutex_destroy(&log_file_lock);
		close(listenfd);
		return 8;
	}

	// listen group manager socket
	listen(listenfd, MAX_PENDING_CON_CNT);

	// wait for user connection
	verb_printf("Waiting for users on %s:%u (Press Ctrl + C to stop) ...\n", inet_ntoa(grpmgr_addr.sin_addr), ntohs(grpmgr_addr.sin_port));
	while (1) {
		// accept user connection
		usr_len = sizeof(usr_addr);
		args[i].connfd = accept(listenfd, (struct sockaddr*) &usr_addr, &usr_len);
		args[i].usr_addr = usr_addr;
		verb_printf("\nAccepted user connection from %s:%u -> create handler thread: ", inet_ntoa(usr_addr.sin_addr), ntohs(usr_addr.sin_port));

		// create user connection thread
		ret = pthread_create(&tid[i], NULL, (void*) &user_thread, (void*) &args[i]);
		if (ret != 0) {
			verb_printf("failed (%s)\n", strerror(errno));
			if (verbose == 0) err_printf("ERROR: Can't create user connection thread: %s\n", strerror(errno));
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

	// clear paillier public key
	if (ppk != NULL) {
		ppk_clear(ppk);
	}

	// clear group public key
	if (gpk != NULL) {
		gpk_clear(gpk);
	}

	// clear issuer key
	if (ik != NULL) {
		ik_clear(ik);
	}

	// close log file
	fclose(log_fp);

	// destroy log file mutex
	pthread_mutex_destroy(&log_file_lock);

	verb_printf("done\n");

	exit(signo);
}

void* user_thread(USER_THREAD_ARGS *args) {
	DWORD size = 0;
	BYTE type=0, *data=NULL;
	int ret=0;
	pthread_t id = pthread_self();

	// receive message from user
	ret = recv_data(args->connfd, &type, &size, &data);
	if (ret) {
		err_printf("[%lu] ERROR: Can't receive data from user (%s:%u).\n", id, inet_ntoa(args->usr_addr.sin_addr), ntohs(args->usr_addr.sin_port));
		close(args->connfd);
		return NULL;
	}

	// handle received message
	switch (type) {
		// received unknown message
		default:
		// received join phase 1 message
		case TYPE_JPD1_MSG:
			verb_printf("[%lu] Received JPD1_MSG (%u bytes) from user (%s:%u).\n", id, size, inet_ntoa(args->usr_addr.sin_addr), ntohs(args->usr_addr.sin_port));

			ret = run_join(args->connfd, &args->usr_addr, id, type, data, size, CERT_PATH "usercert.pem");

			break;
	}

	// close connection to user
	close(args->connfd);


	//verb_printf("[%lu] Finished.\n", id);
	return NULL;
}

int run_join(int sockfd, struct sockaddr_in *usr_addr, pthread_t id, BYTE type, BYTE *data, DWORD size, char *upk_pem_filename) {
	int ret=0;
	char filename[100], log_line[300];
	XSGS_JOIN_PHASE1 *jpd1=NULL;
	XSGS_JOIN_PHASE2 *jpd2=NULL;
	XSGS_JOIN_PHASE3 *jpd3=NULL;
	XSGS_JOIN_PHASE4 *jpd4=NULL;
	XSGS_USER_DB_ENTRY *udbe=NULL;
	X509* cert=NULL;
	FILE* fp=NULL;

	memset(filename, 0, 100);
	memset(log_line, 0, 300);

	// parse byte data to join phase 1 data structure
	jpd1 = xsgs_jpd1_import_buf(gpk, data);
	free(data);

	// run join phase 2
	udbe = (XSGS_USER_DB_ENTRY*)malloc(sizeof(XSGS_USER_DB_ENTRY));
	jpd2 = (XSGS_JOIN_PHASE2*) malloc(sizeof(XSGS_JOIN_PHASE2));
	if (xsgs_user_join_phase2(gpk, udbe, ik, ppk, jpd1, jpd2)) {
		err_printf("[%lu] ERROR: Can't verify user proof U.\n", id);
		udbe_clear(udbe);
		jpd1_clear(jpd1);
		jpd2_clear(jpd2);
		return 1;
	}
	jpd1_clear(jpd1);

	// parse join phase 2 data structure to byte data
	size = xsgs_jpd2_export_buf(&data, jpd2);
	jpd2_clear(jpd2);

	// send join phase 2 data to user
	verb_printf("[%lu] Send JPD2_MSG (%u bytes) to user (%s:%u): ", id, size, inet_ntoa(usr_addr->sin_addr), ntohs(usr_addr->sin_port));
	ret = send_data(sockfd, TYPE_JPD2_MSG, size, data);
	free(data);
	if (ret) {
		verb_printf("failed (%s)\n", strerror(errno));
		if (verbose == 0) err_printf("[%lu] ERROR: Can't send JPD2_MSG (%u) to user (%s:%u): %s\n", id, size, inet_ntoa(usr_addr->sin_addr), ntohs(usr_addr->sin_port), strerror(errno));
		udbe_clear(udbe);
		return 2;
	}
	else {
		verb_printf("successfull\n");
	}

	// receive join phase 3 data from user
	ret = recv_data(sockfd, &type, &size, &data);
	if (ret) {
		err_printf("[%lu] ERROR: Can't receive data from user (%s:%u).\n", id, inet_ntoa(usr_addr->sin_addr), ntohs(usr_addr->sin_port));
		udbe_clear(udbe);
		return 3;
	}
	verb_printf("[%lu] Received JPD3_MSG (%u bytes) from user (%s:%u).\n", id, size, inet_ntoa(usr_addr->sin_addr), ntohs(usr_addr->sin_port));

	// parse byte data to join phase 3 data structure
	jpd3 = xsgs_jpd3_import_buf(data);
	free(data);

	// run join phase 4
	jpd4 = (XSGS_JOIN_PHASE4*) malloc(sizeof(XSGS_JOIN_PHASE4));
	if (xsgs_user_join_phase4(gpk, udbe, jpd3, jpd4, upk_pem_filename)) {
		err_printf("[%lu] ERROR: Can't verify user identity A.\n", id);
		udbe_clear(udbe);
		jpd3_clear(jpd3);
		jpd4_clear(jpd4);
		return 4;
	}
	jpd3_clear(jpd3);

	// parse join phase 4 data structure to byte data
	size = xsgs_jpd4_export_buf(&data, jpd4);
	jpd4_clear(jpd4);

	// send join phase 4 data to user
	verb_printf("[]%lu Send JPD4_MSG (%u bytes) to user (%s:%u): ", id, size, inet_ntoa(usr_addr->sin_addr), ntohs(usr_addr->sin_port));
	ret = send_data(sockfd, TYPE_JPD4_MSG, size, data);
	free(data);
	if (ret) {
		verb_printf("failed (%s)\n", strerror(errno));
		if (verbose == 0) err_printf("[%lu] ERROR: Can't send JPD4_MSG (%u) to user (%s:%u): %s\n", id, size, inet_ntoa(usr_addr->sin_addr), ntohs(usr_addr->sin_port), strerror(errno));
		udbe_clear(udbe);
		return 5;
	}
	else {
		verb_printf("successfull\n");
	}

	//parse user identifier structure to byte data (compressed)
	size = element_length_in_bytes_compressed(udbe->UCert.A);
	data = (BYTE*)malloc(size);
	element_to_bytes_compressed(data, udbe->UCert.A);

	// export user database entry to file $A.db
	sprintf(filename, DB_PATH);
	for(int i=DB_PATH_LEN; i < (int)(DB_PATH_LEN + size); i++) {
		sprintf(&filename[i], "%02x", data[i - DB_PATH_LEN]);
	}
	sprintf(&filename[DB_PATH_LEN + size], ".db");
	xsgs_udbe_export_file(filename, udbe);
	udbe_clear(udbe);
	verb_printf("[%lu] Exported user database entry to %s\n", id, filename);

	// write log entry: { TS: joined user $name to group\n } >> grpmgr.log
	time_t TS = time(NULL);
	struct tm *ptm = gmtime(&TS);
	ptm->tm_hour = (ptm->tm_hour + 2) % 24;
	char timestamp[30];
	memset(timestamp, 0, 30);
	strftime(timestamp, 30, "%Y-%m-%d %H:%M:%S", ptm);
	memset(log_line, 0, 300);
	filename[DB_PATH_LEN + size] = 0;
	fp = fopen(upk_pem_filename, "rb");
	PEM_read_X509(fp, &cert, NULL, NULL);
	fclose(fp);
	ret = sprintf(log_line, "%s: joined a user to group (pki id: %s, group id: %s)\n", timestamp,  cert->name, &filename[DB_PATH_LEN]);
	X509_free(cert);
	log_line[ret] = 0;
	pthread_mutex_lock(&log_file_lock);
	fwrite(log_line, 1, ret, log_fp);
	fflush(log_fp);
	pthread_mutex_unlock(&log_file_lock);

	return 0;
}
