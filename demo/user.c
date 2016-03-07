// TODO: get gpk for join over TLS, check for user revocation over TLS -> update gpk & user credentials over TLS

#include "xsgs.h"
#include "demo.h"

extern int verbose;

typedef struct {
	int help_flag;
	char *grpmgr_address;
	char *grpmgr_port;
} CMD_OPT;

void print_help(char **argv);
int parse_options(CMD_OPT *opts, int argc, char **argv);
int user(char *grpmgr_address, char *grpmgr_port);
int run_join(int sockfd, struct sockaddr_in *gm_addr, char *ppk_bin_filename, char *gpk_bin_filename, char *usk_pem_filename);

int main(int argc, char **argv) {
	int ret = 0;

	CMD_OPT opts;
	memset(&opts, 0, sizeof(CMD_OPT));
	ret = parse_options(&opts, argc, argv);

	if (ret || opts.help_flag) {
		print_help(argv);
		ret = -1;
	} else {
		ret = user(opts.grpmgr_address, opts.grpmgr_port);
	}

	return ret;
}

void print_help(char **argv) {
	struct in_addr ip;
	ip.s_addr = htonl(INADDR_LOOPBACK);

	printf("\n***  Demonstration User  ***\n");
	printf("Author: Martin Goll\n");
	printf("Contact: martin.goll@rub.de\n");
	printf("****************************\n\n");
	printf("Syntax: %s [-v] [--grpmgr-address fqdn|ip] [--grpmgr-port port]\n\n", basename(argv[0]));
	printf("%5s %-25s %s\n", "-?,", "--help", "Show this help message.");
	printf("%5s %-25s %s\n", "-v,", "--verbose", "More verbose output.");
	printf("%5s %-25s %s%s.\n", "", "--grpmgr-address=fqdn|ip", "Modifies the group manager address for joining a user to group. Default is ", inet_ntoa(ip));
	printf("%5s %-25s %s%s.\n", "", "--grpmgr-port=port", "Modifies the group manager port for joining a user to group. Default is ", GRPMGR_PORT);

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

int user(char *grpmgr_address, char *grpmgr_port) {
	int sockfd=0, ret=0;
	struct sockaddr_in gm_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		err_printf("ERROR: Can't create group manager socket: %s\n", strerror(errno));
		return 1;
	}

	memset(&gm_addr, '0', sizeof(gm_addr));
	gm_addr.sin_family = AF_INET;
	if (grpmgr_address != NULL) {
		char ip[20];
		if (hostname_to_ip(grpmgr_address, ip)) {
			close(sockfd);
			return 2;
		}
		inet_aton(ip, &gm_addr.sin_addr);
	} else {
		gm_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	if (grpmgr_port != NULL) {
		gm_addr.sin_port = htons(atoi(grpmgr_port));
	} else {
		gm_addr.sin_port = htons(atoi(GRPMGR_PORT));
	}

	// connect to group manager
	verb_printf("Connection to group manager (%s:%u): ", inet_ntoa(gm_addr.sin_addr), ntohs(gm_addr.sin_port));
	ret = connect(sockfd, (struct sockaddr*)&gm_addr, sizeof(gm_addr));
	if(ret < 0) {
		verb_printf("failed (%s)\n", strerror(errno));
		if (verbose == 0) err_printf("ERROR: Can't connect to group manager (%s:%u): %s\n", inet_ntoa(gm_addr.sin_addr), ntohs(gm_addr.sin_port), strerror(errno));
		close(sockfd);
		return 3;
	}
	else {
		verb_printf("successful\n");
	}

	ret = run_join(sockfd, &gm_addr, KEY_PATH "xsgs_ppk.key", KEY_PATH "xsgs_gpk.key", KEY_PATH "userkey.pem");

	// close connection to group manager
	close(sockfd);

	return ret;
}

int run_join(int sockfd, struct sockaddr_in *gm_addr, char *ppk_bin_filename, char *gpk_bin_filename, char *usk_pem_filename) {
	int ret=0;
	XSGS_PAILLIER_PUBKEY *ppk=NULL;
	XSGS_PUBLIC_KEY *gpk=NULL;
	XSGS_USER_CERT *ucert=NULL;
	XSGS_USER_KEY *uk=NULL;
	XSGS_JOIN_PHASE1 *jpd1=NULL;
	XSGS_JOIN_PHASE2 *jpd2=NULL;
	XSGS_JOIN_PHASE3 *jpd3=NULL;
	XSGS_JOIN_PHASE4 *jpd4=NULL;
	DWORD size = 0;
	BYTE type=0, *data=NULL;
	char filename[300];

	// import public key for paillier encryption
	ppk = xsgs_ppk_import_file(ppk_bin_filename);
	if (ppk == NULL) {
		return 4;
	}

	// import group public key
	gpk = xsgs_gpk_import_file(gpk_bin_filename);
	if (gpk == NULL) {
		ppk_clear(ppk);
		return 5;
	}

	// run join phase 1
	uk = (XSGS_USER_KEY*) malloc(sizeof(XSGS_USER_KEY));
	jpd1 = (XSGS_JOIN_PHASE1*) malloc(sizeof(XSGS_JOIN_PHASE1));
	xsgs_user_join_phase1(gpk, uk, ppk, jpd1);
	ppk_clear(ppk);

	// parse join phase 1 data structure to byte data
	size = xsgs_jpd1_export_buf(&data, jpd1);

	// send join phase 1 data to group manager
	verb_printf("Send JPD1_MSG (%u bytes) to group manager (%s:%u): ", size, inet_ntoa(gm_addr->sin_addr), ntohs(gm_addr->sin_port));
	ret = send_data(sockfd, TYPE_JPD1_MSG, size, data);
	free(data);
	if (ret) {
		verb_printf("failed (%s)\n", strerror(errno));
		if (verbose == 0) err_printf("ERROR: Can't send JPD1_MSG (%u) to group manager (%s:%u): %s\n", size, inet_ntoa(gm_addr->sin_addr), ntohs(gm_addr->sin_port), strerror(errno));
		gpk_clear(gpk);
		uk_clear(uk);
		jpd1_clear(jpd1);
		return 6;
	}
	else {
		verb_printf("successfull\n");
	}

	// receive join phase 2 data from group manager
	ret = recv_data(sockfd, &type, &size, &data);
	if (ret) {
		err_printf("ERROR: Can't receive data from group manger (%s:%u).\n", inet_ntoa(gm_addr->sin_addr), ntohs(gm_addr->sin_port));
		gpk_clear(gpk);
		uk_clear(uk);
		jpd1_clear(jpd1);
		return 7;
	}
	verb_printf("Received JPD2_MSG (%u bytes) from group manager (%s:%u).\n", size, inet_ntoa(gm_addr->sin_addr), ntohs(gm_addr->sin_port));

	// parse byte data to join phase 2 data structure
	jpd2 = xsgs_jpd2_import_buf(gpk, data);
	free(data);

	// run join phase 3
	ucert = (XSGS_USER_CERT*) malloc(sizeof(XSGS_USER_CERT));
	jpd3 = (XSGS_JOIN_PHASE3*) malloc(sizeof(XSGS_JOIN_PHASE3));
    if(xsgs_user_join_phase3(gpk, ucert, jpd1, jpd2, jpd3, usk_pem_filename)) {
    	err_printf("ERROR: Can't verify group manager proof V or sign own identity A.\n");
		gpk_clear(gpk);
		uk_clear(uk);
		ucert_clear(ucert);
		jpd1_clear(jpd1);
		jpd2_clear(jpd2);
		jpd3_clear(jpd3);
    	return 8;
    }
    jpd1_clear(jpd1);
	jpd2_clear(jpd2);

    // parse join phase 3 data structure to byte data
	size = xsgs_jpd3_export_buf(&data, jpd3);
	jpd3_clear(jpd3);

	// send join phase 3 data to group manager
	verb_printf("Send JPD3_MSG (%u bytes) to group manager (%s:%u): ", size, inet_ntoa(gm_addr->sin_addr), ntohs(gm_addr->sin_port));
	ret = send_data(sockfd, TYPE_JPD3_MSG, size, data);
	free(data);
	if (ret) {
		verb_printf("failed (%s)\n", strerror(errno));
		if (verbose == 0) err_printf("ERROR: Can't send JPD3_MSG (%u) to group manager (%s:%u): %s\n", size, inet_ntoa(gm_addr->sin_addr), ntohs(gm_addr->sin_port), strerror(errno));
		gpk_clear(gpk);
		uk_clear(uk);
		ucert_clear(ucert);
		return 9;
	}
	else {
		verb_printf("successfull\n");
	}

	// receive join phase 4 data from group manager
	ret = recv_data(sockfd, &type, &size, &data);
	if (ret) {
		err_printf("ERROR: Can't receive data from group manger(%s:%u).\n", inet_ntoa(gm_addr->sin_addr), ntohs(gm_addr->sin_port));
		gpk_clear(gpk);
		uk_clear(uk);
		ucert_clear(ucert);
		return 10;
	}
	verb_printf("Received JPD4_MSG (%u bytes) from group manager (%s:%u).\n", size, inet_ntoa(gm_addr->sin_addr), ntohs(gm_addr->sin_port));

	// parse byte data to join phase 4 data structure
	jpd4 = xsgs_jpd4_import_buf(gpk, data);
	free(data);

	// run join phase 5
	if(xsgs_user_join_phase5(gpk, ucert, uk, jpd4)) {
		err_printf("ERROR: Can't verify own credentials A, x and y.\n");
		gpk_clear(gpk);
		uk_clear(uk);
		ucert_clear(ucert);
		jpd4_clear(jpd4);
		return 11;
	}
	jpd4_clear(jpd4);

	//parse user identifier structure to byte data (compressed)
	size = element_length_in_bytes_compressed(ucert->A);
	data = (BYTE*)malloc(size);
	element_to_bytes_compressed(data, ucert->A);

	// save user credentials to file $A.cert
	memset(filename, 0, 300);
	sprintf(filename, CERT_PATH);
	for(int i=CERT_PATH_LEN; i < (int)(CERT_PATH_LEN + size); i++) {
		sprintf(&filename[i], "%02x", data[i - CERT_PATH_LEN]);
	}
	sprintf(&filename[CERT_PATH_LEN + size], ".cert");
	xsgs_ucert_export_file(filename, ucert);
	ucert_clear(ucert);
	verb_printf("Exported user certificate to  %s\n", filename);

	// save user credentials to file $A.key
	memset(filename, 0, 300);
	sprintf(filename, KEY_PATH);
	for(int i=KEY_PATH_LEN; i < (int)(KEY_PATH_LEN + size); i++) {
		sprintf(&filename[i], "%02x", data[i - KEY_PATH_LEN]);
	}
	sprintf(&filename[KEY_PATH_LEN + size], ".key");
	free(data);
	xsgs_uk_export_file(filename, uk);
	uk_clear(uk);
	verb_printf("Exported user key to  %s\n", filename);

	// clear group public key
	gpk_clear(gpk);

	return 0;
}
