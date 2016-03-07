#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <math.h>
#include <errno.h>
#include "xsgs.h"

EVP_PKEY* xsgs_rsa_get_pkey_from_file(char* pem_file, BYTE type) {

	EVP_PKEY *pkey;

	if (type) {
		RSA *rsa_pkey = NULL;

		FILE* privateKeyFP = fopen(pem_file, "rb");
		if (!privateKeyFP) {
			printf("Error opening RSA private key File: %s (%s)\n",
					strerror(errno), pem_file);
			return NULL;
		}

		if (!PEM_read_RSAPrivateKey(privateKeyFP, &rsa_pkey, NULL, NULL)) {
			printf("Error loading RSA private key file.\n");
			return NULL;
		}

		fclose(privateKeyFP);
		pkey = EVP_PKEY_new();

		if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey)) {
			printf("EVP_PKEY_assign_RSA: failed.\n");
			return NULL;
		}
	} else {
		X509* x509 = NULL;
		FILE* pem_fp = fopen(pem_file, "rb");
		if (!pem_fp) {
			printf("Error opening RSA cert File: %s (%s)\n", strerror(errno),
					pem_file);
			return NULL;
		}

		PEM_read_X509(pem_fp, &x509, NULL, NULL);
		fclose(pem_fp);

		if (!x509) {
			printf("Error reading x509 data from RSA cert file\n");
			return NULL;
		}

		pkey = X509_get_pubkey(x509);
		X509_free(x509);

		if (!pkey) {
			printf("Error loading public key.\n");
			return NULL;
		} else if (pkey->type != EVP_PKEY_RSA) {
			printf("Key is not a RSA public key\n");
			EVP_PKEY_free(pkey);
			return NULL;
		}
	}

	return pkey;
}

int xsgs_rsa_get_size(char* pem_file, BYTE type) {
	EVP_PKEY* pkey;
	int ret;

	pkey = xsgs_rsa_get_pkey_from_file(pem_file, type);
	if (pkey == NULL) {
		return -1;
	}

	ret = EVP_PKEY_size(pkey) * 8;
	EVP_PKEY_free(pkey);

	return ret;
}

int xsgs_rsa_sign(char* pem_file, BYTE* msg, DWORD msg_len, BYTE** sig, DWORD* sig_len) {
	EVP_PKEY* pkey;
	EVP_MD_CTX ctx;

	pkey = xsgs_rsa_get_pkey_from_file(pem_file, RSA_PRV_KEY);
	if (pkey == NULL) {
		return 1;
	}

	EVP_MD_CTX_init(&ctx);

	if (!EVP_SignInit(&ctx, EVP_sha256())) {
		printf("EVP_SignInit: failed.\n");
		EVP_PKEY_free(pkey);
		return 2;
	}

	if (!EVP_SignUpdate(&ctx, msg, msg_len)) {
		printf("EVP_SignUpdate: failed.\n");
		EVP_PKEY_free(pkey);
		return 3;
	}

	*sig = (BYTE*) malloc(EVP_PKEY_size(pkey));

	if (EVP_SignFinal(&ctx, *sig, sig_len, pkey) != 1) {
		printf("EVP_SignFinal: failed.\n");
		EVP_PKEY_free(pkey);
		return 4;
	}

	EVP_PKEY_free(pkey);

	return 0;
}

int xsgs_rsa_verify(char* pem_file, BYTE* msg, DWORD msg_len, BYTE* sig, DWORD sig_len) {
	EVP_PKEY* pkey;
	EVP_MD_CTX ctx;

	pkey = xsgs_rsa_get_pkey_from_file(pem_file, RSA_PUB_KEY);
	if (pkey == NULL) {
		return 1;
	}

	EVP_MD_CTX_init(&ctx);

	if (!EVP_VerifyInit(&ctx, EVP_sha256())) {
		printf("EVP_SignInit: failed.\n");
		EVP_PKEY_free(pkey);
		return 2;
	}

	if (!EVP_VerifyUpdate(&ctx, msg, msg_len)) {
		printf("EVP_SignUpdate: failed.\n");
		EVP_PKEY_free(pkey);
		return 3;
	}

	if (EVP_VerifyFinal(&ctx, sig, sig_len, pkey) != 1) {
		fprintf(stderr, "EVP_VerifyFinal: failed.\n");
		EVP_PKEY_free(pkey);
		return 4;
	}

	EVP_PKEY_free(pkey);
	return 0;
}

int xsgs_rsa_encrypt(char* pem_file, BYTE* pt, DWORD pt_len, BYTE** ct, DWORD* ct_len) {
	EVP_PKEY* pkey;
	EVP_CIPHER_CTX ctx;
	DWORD pt_block, ct_block, block_count;
	int ret, i;

	pkey = xsgs_rsa_get_pkey_from_file(pem_file, RSA_PUB_KEY);
	if (pkey == NULL) {
		return 1;
	}

	EVP_CIPHER_CTX_init(&ctx);

	pt_block = EVP_PKEY_size(pkey) - 42;
	ct_block = EVP_PKEY_size(pkey);
	block_count = pt_len / pt_block;
	if (block_count * pt_block < pt_len) {
		block_count++;
	}

	*ct = (BYTE*) malloc(ct_block * block_count);

	for (*ct_len = 0, i = 0; pt_len >= pt_block; *ct_len += ret, pt_len -= pt_block, i += pt_block) {
		ret = RSA_public_encrypt(pt_block, &pt[i], &((BYTE*) *ct)[*ct_len], pkey->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
		if (ret == -1) {
			printf("RSA_public_encrypt: failed.\n");
			EVP_PKEY_free(pkey);
			return 2;
		}
	}

	if (pt_len > 0) {
		ret = RSA_public_encrypt(pt_len, &pt[i], &((BYTE*) *ct)[*ct_len], pkey->pkey.rsa, RSA_PKCS1_OAEP_PADDING);

		if (ret == -1) {
			printf("RSA_public_encrypt: failed.\n");
			EVP_PKEY_free(pkey);
			return 3;
		}
		*ct_len += ret;
	}

	EVP_PKEY_free(pkey);

	return 0;
}

int xsgs_rsa_decrypt(char* pem_file, BYTE* ct, DWORD ct_len, BYTE** pt, DWORD* pt_len) {
	EVP_PKEY* pkey;
	EVP_CIPHER_CTX ctx;
	DWORD pt_block, ct_block, block_count;
	int ret, i;

	pkey = xsgs_rsa_get_pkey_from_file(pem_file, RSA_PRV_KEY);
	if (pkey == NULL) {
		return 1;
	}

	EVP_CIPHER_CTX_init(&ctx);

	pt_block = EVP_PKEY_size(pkey) - 42;
	ct_block = EVP_PKEY_size(pkey);
	block_count = ct_len / ct_block;

	*pt = (BYTE*) malloc(pt_block * block_count);

	for (*pt_len = 0, i = 0; ct_len > 0;
			*pt_len += ret, ct_len -= ct_block, i += ct_block) {
		ret = RSA_private_decrypt(ct_block, &ct[i], &((BYTE*) *pt)[*pt_len], pkey->pkey.rsa, RSA_PKCS1_OAEP_PADDING);
		if (ret == -1) {
			printf("RSA_private_decrypt: failed.\n");
			EVP_PKEY_free(pkey);
			return 8;
		}
	}

	EVP_PKEY_free(pkey);

	return 0;
}
