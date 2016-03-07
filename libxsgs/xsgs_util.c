#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <gmp.h>
#include <string.h>
#include "xsgs.h"

void get_rand_buf(BYTE* buf, DWORD len) {
	int rndDev = open("/dev/urandom", O_RDONLY);
	DWORD ret = 0;
	while (ret != len) {
		ret += read(rndDev, &buf[ret], len - ret);
	}
	close(rndDev);
	return;
}

void init_rand(gmp_randstate_t rand_state, DWORD bytes) {
	void* buf;
	mpz_t s;

	buf = malloc(bytes);
	get_rand_buf(buf, bytes);

	gmp_randinit_default(rand_state);
	mpz_init(s);
	mpz_import(s, bytes, 1, 1, 0, 0, buf);
	gmp_randseed(rand_state, s);
	mpz_clear(s);

	free(buf);
}

DWORD mpz_to_bytes(unsigned char *data, mpz_t z) {
	size_t n;
	mpz_export(data, &n, 1, 1, 1, 0, z);
	return (DWORD) n;
}

DWORD mpz_length_in_bytes(mpz_t z) {
	size_t n;
	mpz_export(NULL, &n, 1, 1, 1, 0, z);
	return (DWORD) n;
	//return (mpz_sizeinbase(z, 2) + 7) / 8;
}

void mpz_from_bytes(mpz_t z, unsigned char *data, DWORD len) {
	mpz_import(z, len, 1, 1, 1, 0, data);
	return;
}

void mpz_from_hash(mpz_t z, void *data, DWORD len) {
	mpz_import(z, len, -1, 1, -1, 0, data);
	return;
}

int print_dir_selection(char* dir, DWORD idx, char* filter, DWORD flen) {
	DIR *dp;
	struct dirent *ep;

	dp = opendir(dir);

	if (dp != NULL) {
		ep = readdir(dp);
		while (ep != NULL) {

			if (strncmp(ep->d_name, filter, flen) == 0) {
				printf("[%u] %s\n", idx, ep->d_name);
				idx++;
			}
			ep = readdir(dp);
		}

		closedir(dp);
	} else {
		printf("Error opening directory: %s (%s)\n", strerror(errno), dir);
		return -1;
	}

	return 0;
}

char* get_selected_filename(char* dir, DWORD idx, char* filter, DWORD flen,
		DWORD choice) {
	DIR *dp;
	struct dirent *ep;
	char* filename = NULL;
	DWORD dlen = strlen(dir), len = 0;

	dp = opendir(dir);

	if (dp != NULL) {
		ep = readdir(dp);
		while (ep != NULL) {

			if (strncmp(ep->d_name, filter, flen) == 0) {
				if (choice == idx) {
					len = dlen + strlen(ep->d_name);
					filename = (char*) malloc(len + 1);
					memset(filename, 0, len + 1);
					memcpy(filename, dir, dlen);
					memcpy(&filename[dlen], ep->d_name, len - dlen);
					break;
				}
				idx++;
			}
			ep = readdir(dp);
		}

		closedir(dp);
	} else {
		printf("Error opening directory: %s (%s)\n", strerror(errno), dir);
		return NULL;
	}

	return filename;
}
