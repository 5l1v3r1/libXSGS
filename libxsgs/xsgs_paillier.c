#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include "xsgs.h"

// paillier public key generation
XSGS_PAILLIER_PUBKEY* xsgs_paillier_gen(int mbits) {
	mpz_t p, q;
	gmp_randstate_t rnd_state;
	XSGS_PAILLIER_PUBKEY* ppk = (XSGS_PAILLIER_PUBKEY*) malloc(
			sizeof(XSGS_PAILLIER_PUBKEY));

	// initialize gmp vars
	mpz_init(ppk->n);
	mpz_init(ppk->g);
	mpz_init(ppk->n_squared);
	mpz_init(p);
	mpz_init(q);

	// initialize gmp random state
	init_rand(rnd_state, mbits / 8 + 1);

	// pick random (mbits/2)-bit primes p and q
	do {
		do {
			mpz_urandomb(p, rnd_state, mbits / 2);
		} while (!mpz_probab_prime_p(p, 10));

		do {
			mpz_urandomb(q, rnd_state, mbits / 2);
		} while (!mpz_probab_prime_p(q, 10));

		// compute public modulus n = p * q
		mpz_mul(ppk->n, p, q);
	} while (!mpz_tstbit(ppk->n, mbits - 1));

	// compute squared public modulus n^2
	mpz_mul(ppk->n_squared, ppk->n, ppk->n);
	// compute public base g = n + 1
	mpz_add_ui(ppk->g, ppk->n, 1);

	mpz_clear(p);
	mpz_clear(q);
	gmp_randclear(rnd_state);

	return ppk;
}

// pailler public key import/export
XSGS_PAILLIER_PUBKEY* xsgs_ppk_import_buf(BYTE* data) {
	DWORD len;
	XSGS_PAILLIER_PUBKEY* ppk = (XSGS_PAILLIER_PUBKEY*) malloc(
			sizeof(XSGS_PAILLIER_PUBKEY));

	// n
	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(ppk->n);
	mpz_from_bytes(ppk->n, data, len);
	data += len;

	// g
	mpz_init(ppk->g);
	mpz_add_ui(ppk->g, ppk->n, 1);

	// n^2
	mpz_init(ppk->n_squared);
	mpz_mul(ppk->n_squared, ppk->n, ppk->n);

	return ppk;
}

DWORD xsgs_ppk_export_buf(BYTE** data, XSGS_PAILLIER_PUBKEY* ppk) {

	DWORD buf_len = 4 + mpz_length_in_bytes(ppk->n);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// n
	*(int*) buf = htonl(mpz_length_in_bytes(ppk->n));
	buf += 4;
	buf += mpz_to_bytes(buf, ppk->n);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_PAILLIER_PUBKEY* xsgs_ppk_import_file(char* filename) {
	FILE* fp = fopen(filename, "rb");

	if (fp == NULL) {
		printf("Error opening ppk import file: %s (%s)\n", strerror(errno),
				filename);
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	DWORD len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(len + 1);
	len = fread(data, 1, len, fp);

	fclose(fp);

	XSGS_PAILLIER_PUBKEY* ppk = xsgs_ppk_import_buf(data);

	free(data);

	return ppk;
}

int xsgs_ppk_export_file(char* filename, XSGS_PAILLIER_PUBKEY* ppk) {
	FILE* fp = fopen(filename, "w+b");

	if (fp == NULL) {
		printf("Error opening ppk export file: %s (%s)\n", strerror(errno),
				filename);
		return 1;
	}

	BYTE* buf;
	DWORD buf_len = xsgs_ppk_export_buf(&buf, ppk);

	DWORD file_len = fwrite(buf, 1, buf_len, fp);

	fclose(fp);
	free(buf);

	return (buf_len - file_len);
}

// paillier public key clear
void ppk_clear(XSGS_PAILLIER_PUBKEY* ppk) {
	mpz_clear(ppk->n);
	mpz_clear(ppk->g);
	mpz_clear(ppk->n_squared);
	free(ppk);
	return;
}
