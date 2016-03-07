#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include "xsgs.h"

// system parameter import/export
pbc_param_ptr xsgs_param_import_buf(BYTE* buf) {
	pbc_param_ptr params = (pbc_param_ptr) malloc(sizeof(pbc_param_t));
	pbc_param_init_set_str(params, (char*) buf);
	return params;
}

DWORD xsgs_param_export_buf(BYTE** buf, pbc_param_ptr p) {
	FILE* fp = fopen("xsgs.param", "w+b");

	if (fp == NULL) {
		printf("Error opening param tmp file: %s (%s)\n", strerror(errno),
				"xsgs.param");
		*buf = NULL;
		return 0;
	}

	pbc_param_out_str(fp, p);

	fseek(fp, 0L, SEEK_END);
	DWORD buf_len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(buf_len + 1);
	buf_len = fread(data, 1, buf_len, fp);
	data[buf_len] = 0;

	fclose(fp);
	remove("xsgs.param");

	*buf = data;

	return buf_len + 1;
}

pbc_param_ptr xsgs_param_import_file(char* filename) {
	FILE* fp = fopen(filename, "rb");

	if (fp == NULL) {
		printf("Error opening param import file: %s (%s)\n", strerror(errno),
				filename);
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	DWORD len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(len + 1);
	len = fread(data, 1, len, fp);
	data[len] = 0;

	fclose(fp);

	pbc_param_ptr param = xsgs_param_import_buf(data);

	free(data);

	return param;
}

int xsgs_param_export_file(char* filename, pbc_param_ptr p) {
	FILE* fp = fopen(filename, "w+b");

	if (fp == NULL) {
		printf("Error opening param export file: %s (%s)\n", strerror(errno),
				filename);
		return 1;
	}

	pbc_param_out_str(fp, p);
	fclose(fp);
	return 0;
}

d_param_ptr xsgs_param_import_experimental(BYTE* data) {
	DWORD d, i, len;

	if (data[0] != 'd') {
		return NULL;
	}
	data++;

	d_param_ptr param = (d_param_ptr) malloc(sizeof(d_param_t));

	param->k = ntohl(*(DWORD*) data);
	data += 4;

	d = param->k / 2;

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->q);
	mpz_from_bytes(param->q, data, len);
	data += len;

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->n);
	mpz_from_bytes(param->n, data, len);
	data += len;

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->h);
	mpz_from_bytes(param->h, data, len);
	data += len;

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->r);
	mpz_from_bytes(param->r, data, len);
	data += len;

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->a);
	mpz_from_bytes(param->a, data, len);
	data += len;

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->b);
	mpz_from_bytes(param->b, data, len);
	data += len;

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->nk);
	mpz_from_bytes(param->nk, data, len);
	data += len;

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->hk);
	mpz_from_bytes(param->hk, data, len);
	data += len;

	param->coeff = (mpz_t*) malloc(sizeof(mpz_t) * d);
	for (i = 0; i < d; i++) {
		len = ntohl(*(DWORD*) data);
		data += 4;
		mpz_init(param->coeff[i]);
		mpz_from_bytes(param->coeff[i], data, len);
		data += len;
	}

	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(param->nqr);
	mpz_from_bytes(param->nqr, data, len);
	data += len;

	return param;
}

DWORD xsgs_param_export_experimental(BYTE** data, pbc_param_ptr p) {
	d_param_ptr param = (d_param_ptr) p->data;
	DWORD d = param->k / 2;
	DWORD i, len;

	len = 1
			+				      // type 'd'
			4
			+				      // embedding degree k
			4 + mpz_length_in_bytes(param->q)
			+    // curve defined over F_q
			4 + mpz_length_in_bytes(param->n)
			+    // has order n (= q - t + 1) in F_q
			4 + mpz_length_in_bytes(param->h)
			+    // h * r = n, r is prime
			4 + mpz_length_in_bytes(param->r)
			+    // order of G1, G2, GT and Zr
			4 + mpz_length_in_bytes(param->a)
			+    // curve equation is y^2 = x^3 + ax + b
			4 + mpz_length_in_bytes(param->b) + 4
			+ mpz_length_in_bytes(param->nk) +   // order of curve over F_q^k
			4 + mpz_length_in_bytes(param->hk);    // hk * r^2 = nk

	for (i = 0; i < d; i++) {
		len += 4 + mpz_length_in_bytes(param->coeff[i]); // coefficients of polynomial used to extend F_q by k/2
	}

	len += 4 + mpz_length_in_bytes(param->nqr); // a quadratic nonresidue in F_q^d that lies in F_q

	BYTE* buf = (BYTE*) malloc(len);

	if (buf == NULL) {
		*data = NULL;
		return 0;
	}

	*buf = 'd';
	buf++;

	*(int*) buf = htonl(param->k);
	buf += 4;

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->q));
	buf += 4;
	buf += mpz_to_bytes(buf, param->q);

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->n));
	buf += 4;
	buf += mpz_to_bytes(buf, param->n);

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->h));
	buf += 4;
	buf += mpz_to_bytes(buf, param->h);

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->r));
	buf += 4;
	buf += mpz_to_bytes(buf, param->r);

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->a));
	buf += 4;
	buf += mpz_to_bytes(buf, param->a);

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->b));
	buf += 4;
	buf += mpz_to_bytes(buf, param->b);

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->nk));
	buf += 4;
	buf += mpz_to_bytes(buf, param->nk);

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->hk));
	buf += 4;
	buf += mpz_to_bytes(buf, param->hk);

	for (i = 0; i < d; i++) {
		*(DWORD*) buf = htonl(mpz_length_in_bytes(param->coeff[i]));
		buf += 4;
		buf += mpz_to_bytes(buf, param->coeff[i]);
	}

	*(DWORD*) buf = htonl(mpz_length_in_bytes(param->nqr));
	buf += 4;
	buf += mpz_to_bytes(buf, param->nqr);

	buf -= len;
	*data = buf;

	return len;
}

// generation data import/export
XSGS_PUBLIC_KEY* xsgs_gd1_import_buf(BYTE* data) {
	DWORD len;
	XSGS_PUBLIC_KEY* gpk = (XSGS_PUBLIC_KEY*) malloc(sizeof(XSGS_PUBLIC_KEY));

	// system parameter
	len = ntohl(*(DWORD*) data);
	data += 4;
	BYTE* buf = (BYTE*) malloc(len);
	memcpy(buf, data, len);
	data += len;
	gpk->param = xsgs_param_import_buf(buf);
	free(buf);

	// pairing
	gpk->pairing = (pairing_ptr) malloc(sizeof(pairing_t));
	pairing_init_pbc_param(gpk->pairing, gpk->param);

	// G1
	element_init_G1(gpk->G1, gpk->pairing);
	data += element_from_bytes_compressed(gpk->G1, data);

	// K
	element_init_G1(gpk->K, gpk->pairing);
	data += element_from_bytes_compressed(gpk->K, data);

	// G2
	element_init_G2(gpk->G2, gpk->pairing);
	data += element_from_bytes(gpk->G2, data);

	// W
	element_init_G2(gpk->W, gpk->pairing);
	data += element_from_bytes(gpk->W, data);

	return gpk;
}

DWORD xsgs_gd1_export_buf(BYTE** data, XSGS_PUBLIC_KEY* gpk) {
	// system parameter
	BYTE* param_buf;
	DWORD param_len = xsgs_param_export_buf(&param_buf, gpk->param);

	DWORD buf_len = 4 + param_len + element_length_in_bytes_compressed(gpk->G1)
			+ element_length_in_bytes_compressed(gpk->K)
			+ element_length_in_bytes_compressed(gpk->H)
			+ element_length_in_bytes_compressed(gpk->G)
			+ element_length_in_bytes(gpk->G2)
			+ element_length_in_bytes(gpk->W);

	BYTE* buf = (BYTE*) malloc(buf_len);

	*(int*) buf = htonl(param_len);
	buf += 4;
	memcpy(buf, param_buf, param_len);
	buf += param_len;

	free(param_buf);

	// G1
	buf += element_to_bytes(buf, gpk->G1);

	// K
	buf += element_to_bytes(buf, gpk->K);

	// G2
	buf += element_to_bytes(buf, gpk->G2);

	// W
	buf += element_to_bytes(buf, gpk->W);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

void xsgs_gd2_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	// H
	element_init_G1(gpk->H, gpk->pairing);
	data += element_from_bytes_compressed(gpk->H, data);

	// G
	element_init_G1(gpk->G, gpk->pairing);
	data += element_from_bytes_compressed(gpk->G, data);

	return;
}

DWORD xsgs_gd2_export_buf(BYTE** data, XSGS_PUBLIC_KEY* gpk) {

	DWORD buf_len = element_length_in_bytes_compressed(gpk->H)
			+ element_length_in_bytes_compressed(gpk->G);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// H
	buf += element_to_bytes_compressed(buf, gpk->H);

	// G
	buf += element_to_bytes_compressed(buf, gpk->G);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

// group public key import/export
XSGS_PUBLIC_KEY* xsgs_gpk_import_buf(BYTE* data) {
	DWORD len;
	XSGS_PUBLIC_KEY* gpk = (XSGS_PUBLIC_KEY*) malloc(sizeof(XSGS_PUBLIC_KEY));

	// system parameter
	len = ntohl(*(DWORD*) data);
	data += 4;
	BYTE* buf = (BYTE*) malloc(len);
	memcpy(buf, data, len);
	data += len;
	gpk->param = xsgs_param_import_buf(buf);
	free(buf);

	// pairing
	gpk->pairing = (pairing_ptr) malloc(sizeof(pairing_t));
	pairing_init_pbc_param(gpk->pairing, gpk->param);

	// G1
	element_init_G1(gpk->G1, gpk->pairing);
	data += element_from_bytes_compressed(gpk->G1, data);

	// K
	element_init_G1(gpk->K, gpk->pairing);
	data += element_from_bytes_compressed(gpk->K, data);

	// H
	element_init_G1(gpk->H, gpk->pairing);
	data += element_from_bytes_compressed(gpk->H, data);

	// G
	element_init_G1(gpk->G, gpk->pairing);
	data += element_from_bytes_compressed(gpk->G, data);

	// G2
	element_init_G2(gpk->G2, gpk->pairing);
	data += element_from_bytes(gpk->G2, data);

	// W
	element_init_G2(gpk->W, gpk->pairing);
	data += element_from_bytes(gpk->W, data);

	return gpk;
}

DWORD xsgs_gpk_export_buf(BYTE** data, XSGS_PUBLIC_KEY* gpk) {
	// system parameter
	BYTE* param_buf;
	DWORD param_len = xsgs_param_export_buf(&param_buf, gpk->param);

	DWORD buf_len = 4 + param_len + element_length_in_bytes_compressed(gpk->G1)
			+ element_length_in_bytes_compressed(gpk->K)
			+ element_length_in_bytes_compressed(gpk->H)
			+ element_length_in_bytes_compressed(gpk->G)
			+ element_length_in_bytes(gpk->G2)
			+ element_length_in_bytes(gpk->W);

	BYTE* buf = (BYTE*) malloc(buf_len);

	*(int*) buf = htonl(param_len);
	buf += 4;
	memcpy(buf, param_buf, param_len);
	buf += param_len;

	free(param_buf);

	// G1
	buf += element_to_bytes_compressed(buf, gpk->G1);

	// K
	buf += element_to_bytes_compressed(buf, gpk->K);

	// H
	buf += element_to_bytes_compressed(buf, gpk->H);

	// G
	buf += element_to_bytes_compressed(buf, gpk->G);

	// G2
	buf += element_to_bytes(buf, gpk->G2);

	// W
	buf += element_to_bytes(buf, gpk->W);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_PUBLIC_KEY* xsgs_gpk_import_file(char* filename) {
	FILE* fp = fopen(filename, "rb");

	if (fp == NULL) {
		printf("Error opening gpk import file: %s (%s)\n", strerror(errno),
				filename);
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	DWORD len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(len + 1);
	len = fread(data, 1, len, fp);

	fclose(fp);

	XSGS_PUBLIC_KEY* gpk = xsgs_gpk_import_buf(data);

	free(data);

	return gpk;
}

int xsgs_gpk_export_file(char* filename, XSGS_PUBLIC_KEY* gpk) {
	FILE* fp = fopen(filename, "w+b");

	if (fp == NULL) {
		printf("Error opening gpk export file: %s (%s)\n", strerror(errno),
				filename);
		return 1;
	}

	BYTE* buf;
	DWORD buf_len = xsgs_gpk_export_buf(&buf, gpk);

	DWORD file_len = fwrite(buf, 1, buf_len, fp);

	fclose(fp);
	free(buf);

	return (buf_len - file_len);
}

// group manager key import/export
XSGS_ISSUER_KEY* xsgs_ik_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_ISSUER_KEY* ik = (XSGS_ISSUER_KEY*) malloc(sizeof(XSGS_ISSUER_KEY));

	// gamma
	element_init_Zr(ik->gamma, gpk->pairing);
	data += element_from_bytes(ik->gamma, data);

	return ik;
}

DWORD xsgs_ik_export_buf(BYTE** data, XSGS_ISSUER_KEY* ik) {

	DWORD buf_len = element_length_in_bytes(ik->gamma);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// gamma
	buf += element_to_bytes(buf, ik->gamma);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_ISSUER_KEY* xsgs_ik_import_file(XSGS_PUBLIC_KEY* gpk, char* filename) {
	FILE* fp = fopen(filename, "rb");

	if (fp == NULL) {
		printf("Error opening ik import file: %s (%s)\n", strerror(errno),
				filename);
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	DWORD len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(len + 1);
	len = fread(data, 1, len, fp);

	fclose(fp);

	XSGS_ISSUER_KEY* ik = xsgs_ik_import_buf(gpk, data);

	free(data);

	return ik;
}

int xsgs_ik_export_file(char* filename, XSGS_ISSUER_KEY* ik) {
	FILE* fp = fopen(filename, "w+b");

	if (fp == NULL) {
		printf("Error opening ik export file: %s (%s)\n", strerror(errno),
				filename);
		return 1;
	}

	BYTE* buf;
	DWORD buf_len = xsgs_ik_export_buf(&buf, ik);

	DWORD file_len = fwrite(buf, 1, buf_len, fp);

	fclose(fp);
	free(buf);

	return (buf_len - file_len);
}

// opener key import/export
XSGS_OPENER_KEY* xsgs_ok_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_OPENER_KEY* ok = (XSGS_OPENER_KEY*) malloc(sizeof(XSGS_OPENER_KEY));

	// xi1
	element_init_Zr(ok->xi1, gpk->pairing);
	data += element_from_bytes(ok->xi1, data);

	// xi2
	element_init_Zr(ok->xi2, gpk->pairing);
	data += element_from_bytes(ok->xi2, data);

	return ok;
}

DWORD xsgs_ok_export_buf(BYTE** data, XSGS_OPENER_KEY* ok) {

	DWORD buf_len = element_length_in_bytes(ok->xi1)
			+ element_length_in_bytes(ok->xi2);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// xi1
	buf += element_to_bytes(buf, ok->xi1);

	// xi2
	buf += element_to_bytes(buf, ok->xi2);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_OPENER_KEY* xsgs_ok_import_file(XSGS_PUBLIC_KEY* gpk, char* filename) {
	FILE* fp = fopen(filename, "rb");

	if (fp == NULL) {
		printf("Error opening ok import file: %s (%s)\n", strerror(errno),
				filename);
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	DWORD len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(len + 1);
	len = fread(data, 1, len, fp);

	fclose(fp);

	XSGS_OPENER_KEY* ok = xsgs_ok_import_buf(gpk, data);

	free(data);

	return ok;
}

int xsgs_ok_export_file(char* filename, XSGS_OPENER_KEY* ok) {
	FILE* fp = fopen(filename, "w+b");

	if (fp == NULL) {
		printf("Error opening ok export file: %s (%s)\n", strerror(errno),
				filename);
		return 1;
	}

	BYTE* buf;
	DWORD buf_len = xsgs_ok_export_buf(&buf, ok);

	DWORD file_len = fwrite(buf, 1, buf_len, fp);

	fclose(fp);
	free(buf);

	return (buf_len - file_len);
}

// user cert import/export
XSGS_USER_CERT* xsgs_ucert_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_USER_CERT* ucert = (XSGS_USER_CERT*) malloc(sizeof(XSGS_USER_CERT));

	// A
	element_init_G1(ucert->A, gpk->pairing);
	data += element_from_bytes_compressed(ucert->A, data);

	// x
	element_init_Zr(ucert->x, gpk->pairing);
	data += element_from_bytes(ucert->x, data);

	return ucert;
}

DWORD xsgs_ucert_export_buf(BYTE** data, XSGS_USER_CERT* ucert) {

	DWORD buf_len = element_length_in_bytes_compressed(ucert->A)
			+ element_length_in_bytes(ucert->x);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// A
	buf += element_to_bytes_compressed(buf, ucert->A);

	// x
	buf += element_to_bytes(buf, ucert->x);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_USER_CERT* xsgs_ucert_import_file(XSGS_PUBLIC_KEY* gpk, char* filename) {
	FILE* fp = fopen(filename, "rb");

	if (fp == NULL) {
		printf("Error opening ucert import file: %s (%s)\n", strerror(errno),
				filename);
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	DWORD len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(len + 1);
	len = fread(data, 1, len, fp);

	fclose(fp);

	XSGS_USER_CERT* ucert = xsgs_ucert_import_buf(gpk, data);

	free(data);

	return ucert;
}

int xsgs_ucert_export_file(char* filename, XSGS_USER_CERT* ucert) {
	FILE* fp = fopen(filename, "wb");

	if (fp == NULL) {
		printf("Error opening ucert export file: %s (%s)\n", strerror(errno), filename);
		return -1;
	}

	BYTE* buf;
	DWORD buf_len = xsgs_ucert_export_buf(&buf, ucert);

	DWORD file_len = fwrite(buf, 1, buf_len, fp);

	fclose(fp);
	free(buf);

	return (buf_len - file_len);
}

// user key import/export
XSGS_USER_KEY* xsgs_uk_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_USER_KEY* uk = (XSGS_USER_KEY*) malloc(sizeof(XSGS_USER_KEY));

	// y
	element_init_Zr(uk->y, gpk->pairing);
	data += element_from_bytes(uk->y, data);

	return uk;
}

DWORD xsgs_uk_export_buf(BYTE** data, XSGS_USER_KEY* uk) {
	DWORD buf_len = element_length_in_bytes(uk->y);
	BYTE* buf = (BYTE*) malloc(buf_len);

	// y
	buf += element_to_bytes(buf, uk->y);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_USER_KEY* xsgs_uk_import_file(XSGS_PUBLIC_KEY* gpk, char* filename) {
	FILE* fp = fopen(filename, "rb");

	if (fp == NULL) {
		printf("Error opening uk import file: %s (%s)\n", strerror(errno),
				filename);
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	DWORD len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(len + 1);
	len = fread(data, 1, len, fp);

	fclose(fp);

	XSGS_USER_KEY* uk = xsgs_uk_import_buf(gpk, data);

	free(data);

	return uk;
}

int xsgs_uk_export_file(char* filename, XSGS_USER_KEY* uk) {
	FILE* fp = fopen(filename, "w+b");

	if (fp == NULL) {
		printf("Error opening uk export file: %s (%s)\n", strerror(errno),
				filename);
		return 1;
	}

	BYTE* buf;
	DWORD buf_len = xsgs_uk_export_buf(&buf, uk);

	DWORD file_len = fwrite(buf, 1, buf_len, fp);

	fclose(fp);
	free(buf);

	return (buf_len - file_len);
}

// user database entry import/export
XSGS_USER_DB_ENTRY* xsgs_udbe_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_USER_DB_ENTRY* udbe = (XSGS_USER_DB_ENTRY*) malloc(
			sizeof(XSGS_USER_DB_ENTRY));

	// A
	element_init_G1(udbe->UCert.A, gpk->pairing);
	data += element_from_bytes_compressed(udbe->UCert.A, data);

	// x
	element_init_Zr(udbe->UCert.x, gpk->pairing);
	data += element_from_bytes(udbe->UCert.x, data);

	// C
	element_init_G1(udbe->C, gpk->pairing);
	data += element_from_bytes_compressed(udbe->C, data);

	// S
	udbe->S.len = ntohl(*(DWORD*) data);
	data += 4;
	udbe->S.sig = (BYTE*) malloc(udbe->S.len);
	memcpy(udbe->S.sig, data, udbe->S.len);
	data += udbe->S.len;

	return udbe;
}

DWORD xsgs_udbe_export_buf(BYTE** data, XSGS_USER_DB_ENTRY* udbe) {
	DWORD buf_len = element_length_in_bytes_compressed(udbe->UCert.A)
			+ element_length_in_bytes(udbe->UCert.x)
			+ element_length_in_bytes_compressed(udbe->C) + 4 + udbe->S.len;

	BYTE* buf = (BYTE*) malloc(buf_len);

	// A
	buf += element_to_bytes_compressed(buf, udbe->UCert.A);

	// x
	buf += element_to_bytes(buf, udbe->UCert.x);

	// C
	buf += element_to_bytes_compressed(buf, udbe->C);

	// S
	*(int*) buf = htonl(udbe->S.len);
	buf += 4;
	memcpy(buf, udbe->S.sig, udbe->S.len);
	buf += udbe->S.len;

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_USER_DB_ENTRY* xsgs_udbe_import_file(XSGS_PUBLIC_KEY* gpk, char* filename) {
	FILE* fp = fopen(filename, "rb");

	if (fp == NULL) {
		printf("Error opening udbe import file: %s (%s)\n", strerror(errno),
				filename);
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	DWORD len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	BYTE* data = (BYTE*) malloc(len + 1);
	len = fread(data, 1, len, fp);

	fclose(fp);

	XSGS_USER_DB_ENTRY* udbe = xsgs_udbe_import_buf(gpk, data);

	free(data);

	return udbe;
}

int xsgs_udbe_export_file(char* filename, XSGS_USER_DB_ENTRY* udbe) {
	FILE* fp = fopen(filename, "w+b");

	if (fp == NULL) {
		printf("Error opening udbe export file: %s (%s)\n", strerror(errno),
				filename);
		return 1;
	}

	BYTE* buf;
	DWORD buf_len = xsgs_udbe_export_buf(&buf, udbe);

	DWORD file_len = fwrite(buf, 1, buf_len, fp);

	fclose(fp);
	free(buf);

	return (buf_len - file_len);
}

// join phase data 1-4 import/export
XSGS_JOIN_PHASE1* xsgs_jpd1_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	DWORD len;
	XSGS_JOIN_PHASE1* jpd1 = (XSGS_JOIN_PHASE1*) malloc(
			sizeof(XSGS_JOIN_PHASE1));

	// C
	element_init_G1(jpd1->C, gpk->pairing);
	data += element_from_bytes_compressed(jpd1->C, data);

	// c
	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(jpd1->U.c);
	mpz_from_bytes(jpd1->U.c, data, len);
	data += len;

	// hash
	jpd1->U.hash = (BYTE*) malloc(JOIN_HASH_BITS / 8);
	memcpy(jpd1->U.hash, data, JOIN_HASH_BITS / 8);
	data += JOIN_HASH_BITS / 8;

	// s
	len = ntohl(*(DWORD*) data);
	data += 4;
	mpz_init(jpd1->U.s);
	mpz_from_bytes(jpd1->U.s, data, len);
	data += len;

	return jpd1;
}

DWORD xsgs_jpd1_export_buf(BYTE** data, XSGS_JOIN_PHASE1* jpd1) {

	DWORD buf_len = element_length_in_bytes_compressed(jpd1->C) + 4
			+ mpz_length_in_bytes(jpd1->U.c) +
			JOIN_HASH_BITS / 8 + 4 + mpz_length_in_bytes(jpd1->U.s);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// C
	buf += element_to_bytes_compressed(buf, jpd1->C);

	// c
	//printf("c len: %d\n", mpz_length_in_bytes(jpd1->U.c));
	*(int*) buf = htonl(mpz_length_in_bytes(jpd1->U.c));
	buf += 4;
	buf += mpz_to_bytes(buf, jpd1->U.c);

	// hash
	memcpy(buf, jpd1->U.hash, JOIN_HASH_BITS / 8);
	buf += JOIN_HASH_BITS / 8;

	// s
	//printf("s len: %d\n", mpz_length_in_bytes(jpd1->U.s));
	*(int*) buf = htonl(mpz_length_in_bytes(jpd1->U.s));
	buf += 4;
	buf += mpz_to_bytes(buf, jpd1->U.s);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_JOIN_PHASE2* xsgs_jpd2_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_JOIN_PHASE2* jpd2 = (XSGS_JOIN_PHASE2*) malloc(
			sizeof(XSGS_JOIN_PHASE2));

	// A
	element_init_G1(jpd2->A, gpk->pairing);
	data += element_from_bytes_compressed(jpd2->A, data);

	// T1
	element_init_GT(jpd2->V.T1, gpk->pairing);
	data += element_from_bytes(jpd2->V.T1, data);

	// T2
	element_init_GT(jpd2->V.T2, gpk->pairing);
	data += element_from_bytes(jpd2->V.T2, data);

	// hash
	jpd2->V.hash = (BYTE*) malloc(JOIN_HASH_BITS / 8);
	memcpy(jpd2->V.hash, data, JOIN_HASH_BITS / 8);
	data += JOIN_HASH_BITS / 8;

	// s
	element_init_Zr(jpd2->V.s, gpk->pairing);
	data += element_from_bytes(jpd2->V.s, data);

	return jpd2;
}

DWORD xsgs_jpd2_export_buf(BYTE** data, XSGS_JOIN_PHASE2* jpd2) {
	DWORD buf_len = element_length_in_bytes_compressed(jpd2->A)
			+ element_length_in_bytes(jpd2->V.T1)
			+ element_length_in_bytes(jpd2->V.T2) +
			JOIN_HASH_BITS / 8 + element_length_in_bytes(jpd2->V.s);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// A
	buf += element_to_bytes_compressed(buf, jpd2->A);

	// T1
	buf += element_to_bytes(buf, jpd2->V.T1);

	// T2
	buf += element_to_bytes(buf, jpd2->V.T2);

	// hash
	memcpy(buf, jpd2->V.hash, JOIN_HASH_BITS / 8);
	buf += JOIN_HASH_BITS / 8;

	// s
	buf += element_to_bytes(buf, jpd2->V.s);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_JOIN_PHASE3* xsgs_jpd3_import_buf(BYTE* data) {
	XSGS_JOIN_PHASE3* jpd3 = (XSGS_JOIN_PHASE3*) malloc(
			sizeof(XSGS_JOIN_PHASE3));

	// S
	jpd3->S.len = ntohl(*(DWORD*) data);
	data += 4;
	jpd3->S.sig = (BYTE*) malloc(jpd3->S.len);
	memcpy(jpd3->S.sig, data, jpd3->S.len);
	data += jpd3->S.len;

	return jpd3;
}

DWORD xsgs_jpd3_export_buf(BYTE** data, XSGS_JOIN_PHASE3* jpd3) {

	DWORD buf_len = 4 + jpd3->S.len;

	BYTE* buf = (BYTE*) malloc(buf_len);

	// S
	*(int*) buf = htonl(jpd3->S.len);
	buf += 4;
	memcpy(buf, jpd3->S.sig, jpd3->S.len);
	buf += jpd3->S.len;

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_JOIN_PHASE4* xsgs_jpd4_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_JOIN_PHASE4* jpd4 = (XSGS_JOIN_PHASE4*) malloc(
			sizeof(XSGS_JOIN_PHASE4));

	// x
	element_init_Zr(jpd4->x, gpk->pairing);
	element_from_bytes(jpd4->x, data);

	return jpd4;
}

DWORD xsgs_jpd4_export_buf(BYTE** data, XSGS_JOIN_PHASE4* jpd4) {
	DWORD buf_len = element_length_in_bytes(jpd4->x);
	BYTE* buf = (BYTE*) malloc(buf_len);

	// x
	buf += element_to_bytes(buf, jpd4->x);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

// revocation data import/export
XSGS_REVOKE_PHASE1* xsgs_rpd1_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_REVOKE_PHASE1* rpd1 = (XSGS_REVOKE_PHASE1*) malloc(
			sizeof(XSGS_REVOKE_PHASE1));

	// x
	element_init_Zr(rpd1->x, gpk->pairing);
	data += element_from_bytes(rpd1->x, data);

	// G1
	element_init_G1(rpd1->G1, gpk->pairing);
	data += element_from_bytes_compressed(rpd1->G1, data);

	// K
	element_init_G1(rpd1->K, gpk->pairing);
	data += element_from_bytes_compressed(rpd1->K, data);

	// H
	element_init_G1(rpd1->H, gpk->pairing);
	data += element_from_bytes_compressed(rpd1->H, data);

	// G
	element_init_G1(rpd1->G, gpk->pairing);
	data += element_from_bytes_compressed(rpd1->G, data);

	// G2
	element_init_G2(rpd1->G2, gpk->pairing);
	data += element_from_bytes(rpd1->G2, data);

	return rpd1;
}

DWORD xsgs_rpd1_export_buf(BYTE** data, XSGS_REVOKE_PHASE1* rpd1) {

	DWORD buf_len = element_length_in_bytes(rpd1->x)
			+ element_length_in_bytes_compressed(rpd1->G1)
			+ element_length_in_bytes_compressed(rpd1->K)
			+ element_length_in_bytes_compressed(rpd1->H)
			+ element_length_in_bytes_compressed(rpd1->G)
			+ element_length_in_bytes(rpd1->G2);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// x
	buf += element_to_bytes(buf, rpd1->x);

	// G1
	buf += element_to_bytes_compressed(buf, rpd1->G1);

	// K
	buf += element_to_bytes_compressed(buf, rpd1->K);

	// H
	buf += element_to_bytes_compressed(buf, rpd1->H);

	// G
	buf += element_to_bytes_compressed(buf, rpd1->G);

	// G2
	buf += element_to_bytes(buf, rpd1->G2);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_REVOKE_PHASE2* xsgs_rpd2_import_buf(BYTE* data) {
	XSGS_REVOKE_PHASE2* rpd2 = (XSGS_REVOKE_PHASE2*) malloc(
			sizeof(XSGS_REVOKE_PHASE2));

	// S
	rpd2->S.len = ntohl(*(DWORD*) data);
	data += 4;
	rpd2->S.sig = (BYTE*) malloc(rpd2->S.len);
	memcpy(rpd2->S.sig, data, rpd2->S.len);
	data += rpd2->S.len;

	return rpd2;
}

DWORD xsgs_rpd2_export_buf(BYTE** data, XSGS_REVOKE_PHASE2* rpd2) {

	DWORD buf_len = 4 + rpd2->S.len;

	BYTE* buf = (BYTE*) malloc(buf_len);

	// S
	*(int*) buf = htonl(rpd2->S.len);
	buf += 4;
	memcpy(buf, rpd2->S.sig, rpd2->S.len);
	buf += rpd2->S.len;

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

// signed message import/export
XSGS_SIGNED_MSG* xsgs_sm_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_SIGNED_MSG* sm = (XSGS_SIGNED_MSG*) malloc(sizeof(XSGS_SIGNED_MSG));

	// M
	sm->msg_len = ntohl(*(DWORD*) data);
	data += 4;
	sm->msg = (BYTE*) malloc(sm->msg_len);
	memcpy(sm->msg, data, sm->msg_len);
	data += sm->msg_len;

	// T1
	element_init_G1(sm->sigma.T1, gpk->pairing);
	data += element_from_bytes_compressed(sm->sigma.T1, data);

	// T2
	element_init_G1(sm->sigma.T2, gpk->pairing);
	data += element_from_bytes_compressed(sm->sigma.T2, data);

	// T3

	element_init_G1(sm->sigma.T3, gpk->pairing);
	data += element_from_bytes_compressed(sm->sigma.T3, data);

	// T4
	element_init_G1(sm->sigma.T4, gpk->pairing);
	data += element_from_bytes_compressed(sm->sigma.T4, data);

	// c
	sm->sigma.c = (BYTE*) malloc(SIGNATURE_HASH_BITS / 8);
	memcpy(sm->sigma.c, data, SIGNATURE_HASH_BITS / 8);
	data += SIGNATURE_HASH_BITS / 8;

	// s_alpha
	element_init_Zr(sm->sigma.s_alpha, gpk->pairing);
	data += element_from_bytes(sm->sigma.s_alpha, data);

	// s_beta
	element_init_Zr(sm->sigma.s_beta, gpk->pairing);
	data += element_from_bytes(sm->sigma.s_beta, data);

	// s_x
	element_init_Zr(sm->sigma.s_x, gpk->pairing);
	data += element_from_bytes(sm->sigma.s_x, data);

	// s_z
	element_init_Zr(sm->sigma.s_z, gpk->pairing);
	data += element_from_bytes(sm->sigma.s_z, data);

	return sm;
}

DWORD xsgs_sm_export_buf(BYTE** data, XSGS_SIGNED_MSG* sm) {

	DWORD buf_len = 4 + sm->msg_len
			+ element_length_in_bytes_compressed(sm->sigma.T1)
			+ element_length_in_bytes_compressed(sm->sigma.T2)
			+ element_length_in_bytes_compressed(sm->sigma.T3)
			+ element_length_in_bytes_compressed(sm->sigma.T4) +
			SIGNATURE_HASH_BITS / 8 + element_length_in_bytes(sm->sigma.s_alpha)
			+ element_length_in_bytes(sm->sigma.s_beta)
			+ element_length_in_bytes(sm->sigma.s_x)
			+ element_length_in_bytes(sm->sigma.s_z);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// M
	*(int*) buf = htonl(sm->msg_len);
	buf += 4;
	memcpy(buf, sm->msg, sm->msg_len);
	buf += sm->msg_len;

	// T1
	buf += element_to_bytes_compressed(buf, sm->sigma.T1);

	// T2
	buf += element_to_bytes_compressed(buf, sm->sigma.T2);

	// T3
	buf += element_to_bytes_compressed(buf, sm->sigma.T3);

	// T4
	buf += element_to_bytes_compressed(buf, sm->sigma.T4);

	// c
	memcpy(buf, sm->sigma.c, SIGNATURE_HASH_BITS / 8);
	buf += SIGNATURE_HASH_BITS / 8;

	// s_alpha
	buf += element_to_bytes(buf, sm->sigma.s_alpha);

	// s_beta
	buf += element_to_bytes(buf, sm->sigma.s_beta);

	// s_x
	buf += element_to_bytes(buf, sm->sigma.s_x);

	// s_z
	buf += element_to_bytes(buf, sm->sigma.s_z);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

XSGS_BATCH_SIGNED_MSG* xsgs_bsm_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_BATCH_SIGNED_MSG* bsm = (XSGS_BATCH_SIGNED_MSG*) malloc(
			sizeof(XSGS_BATCH_SIGNED_MSG));

	// M
	bsm->msg_len = ntohl(*(DWORD*) data);
	data += 4;
	bsm->msg = (BYTE*) malloc(bsm->msg_len);
	memcpy(bsm->msg, data, bsm->msg_len);
	data += bsm->msg_len;

	// T1
	element_init_G1(bsm->sigma.T1, gpk->pairing);
	data += element_from_bytes_compressed(bsm->sigma.T1, data);

	// T2
	element_init_G1(bsm->sigma.T2, gpk->pairing);
	data += element_from_bytes_compressed(bsm->sigma.T2, data);

	// T3
	element_init_G1(bsm->sigma.T3, gpk->pairing);
	data += element_from_bytes_compressed(bsm->sigma.T3, data);

	// T4
	element_init_G1(bsm->sigma.T4, gpk->pairing);
	data += element_from_bytes_compressed(bsm->sigma.T4, data);

	// R1
	element_init_G1(bsm->sigma.R1, gpk->pairing);
	data += element_from_bytes_compressed(bsm->sigma.R1, data);

	// R2
	element_init_GT(bsm->sigma.R2, gpk->pairing);
	data += element_from_bytes(bsm->sigma.R2, data);
	//data += element_from_bytes_compressed(bsm->sigma.R2, data);

	// R3
	element_init_G1(bsm->sigma.R3, gpk->pairing);
	data += element_from_bytes_compressed(bsm->sigma.R3, data);

	// R4
	element_init_G1(bsm->sigma.R4, gpk->pairing);
	data += element_from_bytes_compressed(bsm->sigma.R4, data);

	// s_alpha
	element_init_Zr(bsm->sigma.s_alpha, gpk->pairing);
	data += element_from_bytes(bsm->sigma.s_alpha, data);

	// s_beta
	element_init_Zr(bsm->sigma.s_beta, gpk->pairing);
	data += element_from_bytes(bsm->sigma.s_beta, data);

	// s_x
	element_init_Zr(bsm->sigma.s_x, gpk->pairing);
	data += element_from_bytes(bsm->sigma.s_x, data);

	// s_z
	element_init_Zr(bsm->sigma.s_z, gpk->pairing);
	data += element_from_bytes(bsm->sigma.s_z, data);

	return bsm;
}

DWORD xsgs_bsm_export_buf(BYTE** data, XSGS_BATCH_SIGNED_MSG* bsm) {

	DWORD buf_len = 4 + bsm->msg_len
			+ element_length_in_bytes_compressed(bsm->sigma.T1)
			+ element_length_in_bytes_compressed(bsm->sigma.T2)
			+ element_length_in_bytes_compressed(bsm->sigma.T3)
			+ element_length_in_bytes_compressed(bsm->sigma.T4)
			+ element_length_in_bytes_compressed(bsm->sigma.R1)
			+ element_length_in_bytes(bsm->sigma.R2)
			+
			//element_length_in_bytes_compressed(bsm->sigma.R2) +
			element_length_in_bytes_compressed(bsm->sigma.R3)
			+ element_length_in_bytes_compressed(bsm->sigma.R4)
			+ element_length_in_bytes(bsm->sigma.s_alpha)
			+ element_length_in_bytes(bsm->sigma.s_beta)
			+ element_length_in_bytes(bsm->sigma.s_x)
			+ element_length_in_bytes(bsm->sigma.s_z);

	BYTE* buf = (BYTE*) malloc(buf_len);

	// M
	*(int*) buf = htonl(bsm->msg_len);
	buf += 4;
	memcpy(buf, bsm->msg, bsm->msg_len);
	buf += bsm->msg_len;

	// T1
	buf += element_to_bytes_compressed(buf, bsm->sigma.T1);

	// T2
	buf += element_to_bytes_compressed(buf, bsm->sigma.T2);

	// T3
	buf += element_to_bytes_compressed(buf, bsm->sigma.T3);

	// T4
	buf += element_to_bytes_compressed(buf, bsm->sigma.T4);

	// R1
	buf += element_to_bytes_compressed(buf, bsm->sigma.R1);

	// R2
	buf += element_to_bytes(buf, bsm->sigma.R2);
	//buf += element_to_bytes_compressed(buf, bsm->sigma.R2);

	// R3
	buf += element_to_bytes_compressed(buf, bsm->sigma.R3);

	// R4
	buf += element_to_bytes_compressed(buf, bsm->sigma.R4);

	// s_alpha
	buf += element_to_bytes(buf, bsm->sigma.s_alpha);

	// s_beta
	buf += element_to_bytes(buf, bsm->sigma.s_beta);

	// s_x
	buf += element_to_bytes(buf, bsm->sigma.s_x);

	// s_z
	buf += element_to_bytes(buf, bsm->sigma.s_z);

	buf -= buf_len;
	*data = buf;

	return buf_len;
}

// open data import/export
XSGS_OPEN_DATA* xsgs_od_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data) {
	XSGS_OPEN_DATA* od = (XSGS_OPEN_DATA*) malloc(sizeof(XSGS_OPEN_DATA));

	// A
	element_init_G1(od->A, gpk->pairing);
	data += element_from_bytes_compressed(od->A, data);

	// hash
	od->tau.hash = (BYTE*) malloc(OPEN_HASH_BITS / 8);
	memcpy(od->tau.hash, data, OPEN_HASH_BITS / 8);
	data += OPEN_HASH_BITS / 8;

	// s_alpha
	element_init_Zr(od->tau.s_alpha, gpk->pairing);
	data += element_from_bytes(od->tau.s_alpha, data);

	// s_beta
	element_init_Zr(od->tau.s_beta, gpk->pairing);
	data += element_from_bytes(od->tau.s_beta, data);

	// s_gamma
	element_init_Zr(od->tau.s_gamma, gpk->pairing);
	data += element_from_bytes(od->tau.s_gamma, data);

	// s_delta
	element_init_Zr(od->tau.s_delta, gpk->pairing);
	data += element_from_bytes(od->tau.s_delta, data);

	// S
	od->S.len = ntohl(*(DWORD*) data);
	data += 4;
	od->S.sig = (BYTE*) malloc(od->S.len);
	memcpy(od->S.sig, data, od->S.len);
	data += od->S.len;

	return od;
}

DWORD xsgs_od_export_buf(BYTE** data, XSGS_OPEN_DATA* od) {

	DWORD buf_len = element_length_in_bytes_compressed(od->A) +
	OPEN_HASH_BITS / 8 + element_length_in_bytes(od->tau.s_alpha)
			+ element_length_in_bytes(od->tau.s_beta)
			+ element_length_in_bytes(od->tau.s_gamma)
			+ element_length_in_bytes(od->tau.s_delta) + 4 + od->S.len;

	BYTE* buf = (BYTE*) malloc(buf_len);

	// A
	buf += element_to_bytes_compressed(buf, od->A);

	// hash
	memcpy(buf, od->tau.hash, OPEN_HASH_BITS / 8);
	buf += OPEN_HASH_BITS / 8;

	// s_alpha
	buf += element_to_bytes(buf, od->tau.s_alpha);

	// s_beta
	buf += element_to_bytes(buf, od->tau.s_beta);

	// s_gamma
	buf += element_to_bytes(buf, od->tau.s_gamma);

	// s_delta
	buf += element_to_bytes(buf, od->tau.s_delta);

	// S
	*(int*) buf = htonl(od->S.len);
	buf += 4;
	memcpy(buf, od->S.sig, od->S.len);
	buf += od->S.len;

	buf -= buf_len;
	*data = buf;

	return buf_len;
}
