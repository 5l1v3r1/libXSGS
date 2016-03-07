#include "demo.h"

extern int verbose;

typedef struct {
	int help_flag;
	char *client_address;
	char *client_port;
} CMD_OPT;

void print_help(char **argv);
int parse_options(CMD_OPT *opts, int argc, char **argv);
int dummy(char *client_address, char *client_port);

int main(int argc, char **argv) {
	int ret = 0;

	CMD_OPT opts;
	memset(&opts, 0, sizeof(CMD_OPT));
	ret = parse_options(&opts, argc, argv);

	if (ret || opts.help_flag) {
		print_help(argv);
		ret = -1;
	} else {
		ret = dummy(opts.client_address, opts.client_port);
	}

	return ret;
}

void print_help(char **argv) {
	struct in_addr ip;
	ip.s_addr = htonl(INADDR_LOOPBACK);

	printf("\n***  Demonstration Dummy  ***\n");
	printf("Author: Martin Goll\n");
	printf("Contact: martin.goll@rub.de\n");
	printf("****************************\n\n");
	printf("Syntax: %s [-v] [--client-address fqdn|ip] [--client-port port]\n\n", basename(argv[0]));
	printf("%5s %-25s %s\n", "-?,", "--help", "Show this help message.");
	printf("%5s %-25s %s\n", "-v,", "--verbose", "More verbose output.");
	printf("%5s %-25s %s%s.\n", "", "--client-address=fqdn|ip", "Modifies the client address for committing signature requests. Default is ", inet_ntoa(ip));
	printf("%5s %-25s %s%s.\n", "", "--client-port=port", "Modifies the client port for committing signature requests. Default is ", CLIENT_PORT);

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

int dummy(char *client_address, char *client_port) {
	int sockfd=0, ret=0;
	struct sockaddr_in cli_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		err_printf("ERROR: Can't create client socket: %s\n", strerror(errno));
		return 1;
	}

	memset(&cli_addr, '0', sizeof(cli_addr));
	cli_addr.sin_family = AF_INET;
	if (client_address != NULL) {
		char ip[20];
		if (hostname_to_ip(client_address, ip)) {
			close(sockfd);
			return 2;
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

	// connect to client
	verb_printf("Connection to client (%s:%u): ", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
	ret = connect(sockfd, (struct sockaddr*)&cli_addr, sizeof(cli_addr));
	if(ret < 0) {
		verb_printf("failed (%s)\n", strerror(errno));
		if (verbose == 0) err_printf("ERROR: Can't connect to client (%s:%u): (%s)\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), strerror(errno));
		close(sockfd);
		return 3;
	}
	else {
		verb_printf("successful\n");
	}

	// generate dummy process message
	BYTE *proc_msg = (BYTE*)malloc(208);
	*(DWORD*)proc_msg = 100;
	*(DWORD*)&proc_msg[4] = 100;
	memset(&proc_msg[8], 'a', 100);
	memset(&proc_msg[108], 'b', 100);


	// send process message to client
	verb_printf("Send RAW_DATA_MSG (%u bytes) to client (%s:%u): ", 208, inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));
	ret = send_data(sockfd, TYPE_RAW_DATA_MSG, 208, proc_msg);
	free(proc_msg);
	if (ret) {
		verb_printf("failed (%s)\n", strerror(errno));
		if (verbose == 0) err_printf("ERROR: Can't send RAW_DATA_MSG (%u) to client (%s:%u): (%s)\n", 208, inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), strerror(errno));
		close(sockfd);
		return 4;
	}
	else {
		verb_printf("successfull\n");
	}

	close(sockfd);

	return ret;
}
