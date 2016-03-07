#include <string.h>
#include "xsgs.h"

// OPEN SIGNATURE
XSGS_OPEN_DATA* xsgs_open_sig(XSGS_PUBLIC_KEY* gpk, XSGS_OPENER_KEY* ok,
		XSGS_SIGNED_MSG* sig) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	element_t A1, A2, R1, R2, R3, R4, r_alpha, r_beta, r_gamma, r_delta, h;
	XSGS_OPEN_DATA* od = NULL;

	// 1) recover A: using the opening key ok = (xi1, xi2)
	element_init(h, Fp);
	element_init(A1, G1);
	element_init(A2, G1);
	element_neg(h, ok->xi1);
	element_pow_naf(A1, sig->sigma.T1, h);
	element_neg(h, ok->xi2);
	element_pow_naf(A2, sig->sigma.T3, h);
	element_mul(A1, sig->sigma.T2, A1);
	element_mul(A2, sig->sigma.T4, A2);

	if (!element_cmp(A1, A2)) {
		od = (XSGS_OPEN_DATA*) malloc(sizeof(XSGS_OPEN_DATA));

		element_init(od->A, G1);
		element_set(od->A, A1);

		// 2) provide a publicly verifiable proof tau
		// r_alpha, r_beta, r_gamma, r_delta eR Zp
		element_init(r_alpha, Fp);
		element_init(r_beta, Fp);
		element_init(r_gamma, Fp);
		element_init(r_delta, Fp);
		element_random(r_alpha);
		element_random(r_beta);
		element_random(r_gamma);
		element_random(r_delta);

		// R1 = K^r_alpha
		element_init(R1, G1);
		element_pow_naf(R1, gpk->K, r_alpha);

		// R2 = T1^r_beta
		element_init(R2, G1);
		element_pow_naf(R2, sig->sigma.T1, r_beta);

		// R3 = K^r_gamma
		element_init(R3, G1);
		element_pow_naf(R3, gpk->K, r_gamma);

		// R4 = T3^r_delta
		element_init(R4, G1);
		element_pow_naf(R4, sig->sigma.T3, r_delta);

		// h = H(K, H, G, T1, T2, T3, T4, A, R1, R2, R3, R4)
		DWORD data_len = element_length_in_bytes(gpk->K)
				+ element_length_in_bytes(gpk->H)
				+ element_length_in_bytes(gpk->G)
				+ element_length_in_bytes(sig->sigma.T1)
				+ element_length_in_bytes(sig->sigma.T2)
				+ element_length_in_bytes(sig->sigma.T3)
				+ element_length_in_bytes(sig->sigma.T4)
				+ element_length_in_bytes(od->A) + element_length_in_bytes(R1)
				+ element_length_in_bytes(R2) + element_length_in_bytes(R3)
				+ element_length_in_bytes(R4);

		BYTE* data_buf = (BYTE*) malloc(data_len);
		data_buf += element_to_bytes(data_buf, gpk->K);
		data_buf += element_to_bytes(data_buf, gpk->H);
		data_buf += element_to_bytes(data_buf, gpk->G);
		data_buf += element_to_bytes(data_buf, sig->sigma.T1);
		data_buf += element_to_bytes(data_buf, sig->sigma.T2);
		data_buf += element_to_bytes(data_buf, sig->sigma.T3);
		data_buf += element_to_bytes(data_buf, sig->sigma.T4);
		data_buf += element_to_bytes(data_buf, od->A);
		data_buf += element_to_bytes(data_buf, R1);
		data_buf += element_to_bytes(data_buf, R2);
		data_buf += element_to_bytes(data_buf, R3);
		data_buf += element_to_bytes(data_buf, R4);
		data_buf -= data_len;

		od->tau.hash = (BYTE*) malloc(OPEN_HASH_BITS / 8);
		xsgs_hash(data_buf, data_len * 8, od->tau.hash, OPEN_HASH_BITS);

		element_from_hash(h, od->tau.hash, OPEN_HASH_BITS / 8);

		free(data_buf);
		element_clear(R1);
		element_clear(R2);
		element_clear(R3);
		element_clear(R4);

		// s_alpha = r_alpha + hash * xi1
		element_init(od->tau.s_alpha, Fp);
		element_mul(od->tau.s_alpha, h, ok->xi1);
		element_add(od->tau.s_alpha, od->tau.s_alpha, r_alpha);

		// s_beta = r_beta + hash * xi1
		element_init(od->tau.s_beta, Fp);
		element_mul(od->tau.s_beta, h, ok->xi1);
		element_add(od->tau.s_beta, od->tau.s_beta, r_beta);

		// s_gamma = r_gamma + hash * xi2
		element_init(od->tau.s_gamma, Fp);
		element_mul(od->tau.s_gamma, h, ok->xi2);
		element_add(od->tau.s_gamma, od->tau.s_gamma, r_gamma);

		// s_delta = r_delta + hash * xi2
		element_init(od->tau.s_delta, Fp);
		element_mul(od->tau.s_delta, h, ok->xi2);
		element_add(od->tau.s_delta, od->tau.s_delta, r_delta);
	}

	element_clear(h);

	// return OD = { A, tau =(h, s_alpha, s_beta, s_gamma, s_delta) }
	return od;
}

XSGS_OPEN_DATA* xsgs_open_batch_sig(XSGS_PUBLIC_KEY* gpk, XSGS_OPENER_KEY* ok,
		XSGS_BATCH_SIGNED_MSG* sig) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	element_t A1, A2, R1, R2, R3, R4, r_alpha, r_beta, r_gamma, r_delta, h;
	XSGS_OPEN_DATA* od = NULL;

	// 1) recover A: using the opening key ok = (xi1, xi2)
	element_init(h, Fp);
	element_init(A1, G1);
	element_init(A2, G1);
	element_neg(h, ok->xi1);
	element_pow_naf(A1, sig->sigma.T1, h);
	element_neg(h, ok->xi2);
	element_pow_naf(A2, sig->sigma.T3, h);
	element_mul(A1, sig->sigma.T2, A1);
	element_mul(A2, sig->sigma.T4, A2);

	if (!element_cmp(A1, A2)) {
		od = (XSGS_OPEN_DATA*) malloc(sizeof(XSGS_OPEN_DATA));

		element_init(od->A, G1);
		element_set(od->A, A1);

		// 2) provide a publicly verifiable proof tau
		// r_alpha, r_beta, r_gamma, r_delta eR Zp
		element_init(r_alpha, Fp);
		element_init(r_beta, Fp);
		element_init(r_gamma, Fp);
		element_init(r_delta, Fp);
		element_random(r_alpha);
		element_random(r_beta);
		element_random(r_gamma);
		element_random(r_delta);

		// R1 = K^r_alpha
		element_init(R1, G1);
		element_pow_naf(R1, gpk->K, r_alpha);

		// R2 = T1^r_beta
		element_init(R2, G1);
		element_pow_naf(R2, sig->sigma.T1, r_beta);

		// R3 = K^r_gamma
		element_init(R3, G1);
		element_pow_naf(R3, gpk->K, r_gamma);

		// R4 = T3^r_delta
		element_init(R4, G1);
		element_pow_naf(R4, sig->sigma.T3, r_delta);

		// h = H(K, H, G, T1, T2, T3, T4, A, R1, R2, R3, R4)
		DWORD data_len = element_length_in_bytes(gpk->K)
				+ element_length_in_bytes(gpk->H)
				+ element_length_in_bytes(gpk->G)
				+ element_length_in_bytes(sig->sigma.T1)
				+ element_length_in_bytes(sig->sigma.T2)
				+ element_length_in_bytes(sig->sigma.T3)
				+ element_length_in_bytes(sig->sigma.T4)
				+ element_length_in_bytes(od->A) + element_length_in_bytes(R1)
				+ element_length_in_bytes(R2) + element_length_in_bytes(R3)
				+ element_length_in_bytes(R4);

		BYTE* data_buf = (BYTE*) malloc(data_len);
		data_buf += element_to_bytes(data_buf, gpk->K);
		data_buf += element_to_bytes(data_buf, gpk->H);
		data_buf += element_to_bytes(data_buf, gpk->G);
		data_buf += element_to_bytes(data_buf, sig->sigma.T1);
		data_buf += element_to_bytes(data_buf, sig->sigma.T2);
		data_buf += element_to_bytes(data_buf, sig->sigma.T3);
		data_buf += element_to_bytes(data_buf, sig->sigma.T4);
		data_buf += element_to_bytes(data_buf, od->A);
		data_buf += element_to_bytes(data_buf, R1);
		data_buf += element_to_bytes(data_buf, R2);
		data_buf += element_to_bytes(data_buf, R3);
		data_buf += element_to_bytes(data_buf, R4);
		data_buf -= data_len;

		od->tau.hash = (BYTE*) malloc(OPEN_HASH_BITS / 8);
		xsgs_hash(data_buf, data_len * 8, od->tau.hash, OPEN_HASH_BITS);

		element_from_hash(h, od->tau.hash, OPEN_HASH_BITS / 8);

		free(data_buf);
		element_clear(R1);
		element_clear(R2);
		element_clear(R3);
		element_clear(R4);

		// s_alpha = r_alpha + hash * xi1
		element_init(od->tau.s_alpha, Fp);
		element_mul(od->tau.s_alpha, h, ok->xi1);
		element_add(od->tau.s_alpha, od->tau.s_alpha, r_alpha);

		// s_beta = r_beta + hash * xi1
		element_init(od->tau.s_beta, Fp);
		element_mul(od->tau.s_beta, h, ok->xi1);
		element_add(od->tau.s_beta, od->tau.s_beta, r_beta);

		// s_gamma = r_gamma + hash * xi2
		element_init(od->tau.s_gamma, Fp);
		element_mul(od->tau.s_gamma, h, ok->xi2);
		element_add(od->tau.s_gamma, od->tau.s_gamma, r_gamma);

		// s_delta = r_delta + hash * xi2
		element_init(od->tau.s_delta, Fp);
		element_mul(od->tau.s_delta, h, ok->xi2);
		element_add(od->tau.s_delta, od->tau.s_delta, r_delta);
	}

	element_clear(h);

	// return OD = { A, tau =(h, s_alpha, s_beta, s_gamma, s_delta) }
	return od;
}

// JUDGE OPENED SIGNATURE
int xsgs_judge_sig(XSGS_PUBLIC_KEY* gpk, XSGS_SIGNED_MSG* sig,
		XSGS_OPEN_DATA* od, char* upk_pem_filename) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	element_t R1, R2, R3, R4, z1, z2;
	int ret;

	// hash mod p
	element_init(z1, Fp);
	element_init(z2, Fp);
	element_from_hash(z1, od->tau.hash, OPEN_HASH_BITS / 8);
	element_neg(z2, z1);

	// R1 = K^s_alpha / H^hash
	element_init(R1, G1);
	element_pow_naf2(R1, gpk->K, od->tau.s_alpha, gpk->H, z2);

	// R2 = T1^s_beta / (T2 / A)^hash = T1^s_beta * A^hash * T2^-hash
	element_init(R2, G1);
	element_pow_naf3(R2, sig->sigma.T1, od->tau.s_beta, od->A, z1,
			sig->sigma.T2, z2);

	// R3 = K^s_gamma / G^hash
	element_init(R3, G1);
	element_pow_naf2(R3, gpk->K, od->tau.s_gamma, gpk->G, z2);

	// R4 = T3^s_delta / (T4 / A)^hash = T3^s_delta * A^hash * T4^-hash
	element_init(R4, G1);
	element_pow_naf3(R4, sig->sigma.T3, od->tau.s_delta, od->A, z1,
			sig->sigma.T4, z2);

	// clear tmp
	element_clear(z1);
	element_clear(z2);

	// h = H(K, H, G, T1, T2, T3, T4, A, R1, R2, R3, R4)
	DWORD data_len = element_length_in_bytes(gpk->K)
			+ element_length_in_bytes(gpk->H) + element_length_in_bytes(gpk->G)
			+ element_length_in_bytes(sig->sigma.T1)
			+ element_length_in_bytes(sig->sigma.T2)
			+ element_length_in_bytes(sig->sigma.T3)
			+ element_length_in_bytes(sig->sigma.T4)
			+ element_length_in_bytes(od->A) + element_length_in_bytes(R1)
			+ element_length_in_bytes(R2) + element_length_in_bytes(R3)
			+ element_length_in_bytes(R4);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	data_buf += element_to_bytes(data_buf, gpk->K);
	data_buf += element_to_bytes(data_buf, gpk->H);
	data_buf += element_to_bytes(data_buf, gpk->G);
	data_buf += element_to_bytes(data_buf, sig->sigma.T1);
	data_buf += element_to_bytes(data_buf, sig->sigma.T2);
	data_buf += element_to_bytes(data_buf, sig->sigma.T3);
	data_buf += element_to_bytes(data_buf, sig->sigma.T4);
	data_buf += element_to_bytes(data_buf, od->A);
	data_buf += element_to_bytes(data_buf, R1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf += element_to_bytes(data_buf, R3);
	data_buf += element_to_bytes(data_buf, R4);
	data_buf -= data_len;

	BYTE* hash = (BYTE*) malloc(OPEN_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, hash, OPEN_HASH_BITS);

	free(data_buf);
	element_clear(R1);
	element_clear(R2);
	element_clear(R3);
	element_clear(R4);

	// compare hashes
	ret = memcmp(od->tau.hash, hash, OPEN_HASH_BITS / 8);
	free(hash);
	if (!ret) {
		// verify S = sign_usk(A)
		DWORD msg_len = element_length_in_bytes(od->A);
		BYTE* msg = (BYTE*) malloc(msg_len);
		element_to_bytes(msg, od->A);

		ret = xsgs_rsa_verify(upk_pem_filename, msg, msg_len, od->S.sig,
				od->S.len);
		free(msg);
	}

	return ret;
}

int xsgs_judge_batch_sig(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG* sig,
		XSGS_OPEN_DATA* od, char* upk_pem_filename) {
	int ret;
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	element_t R1, R2, R3, R4, z1, z2;

	// hash mod p
	element_init(z1, Fp);
	element_init(z2, Fp);
	element_from_hash(z1, od->tau.hash, OPEN_HASH_BITS / 8);
	element_neg(z2, z1);

	// R1 = K^s_alpha / H^hash
	element_init_G1(R1, pairing);
	element_pow_naf2(R1, gpk->K, od->tau.s_alpha, gpk->H, z2);

	// R2 = T1^s_beta / (T2 / A)^hash = T1^s_beta * A^hash * T2^-hash
	element_init_G1(R2, pairing);
	element_pow_naf3(R2, sig->sigma.T1, od->tau.s_beta, od->A, z1,
			sig->sigma.T2, z2);

	// R3 = K^s_gamma / G^hash
	element_init_G1(R3, pairing);
	element_pow_naf2(R3, gpk->K, od->tau.s_gamma, gpk->G, z2);

	// R4 = T3^s_delta / (T4 / A)^hash = T3^s_delta * A^hash * T4^-hash
	element_init_G1(R4, pairing);
	element_pow_naf3(R4, sig->sigma.T3, od->tau.s_delta, od->A, z1,
			sig->sigma.T4, z2);

	// clear tmp
	element_clear(z1);
	element_clear(z2);

	// hash = H(K, H, G, T1, T2, T3, T4, A, R1, R2, R3, R4)
	DWORD data_len = element_length_in_bytes(gpk->K)
			+ element_length_in_bytes(gpk->H) + element_length_in_bytes(gpk->G)
			+ element_length_in_bytes(sig->sigma.T1)
			+ element_length_in_bytes(sig->sigma.T2)
			+ element_length_in_bytes(sig->sigma.T3)
			+ element_length_in_bytes(sig->sigma.T4)
			+ element_length_in_bytes(od->A) + element_length_in_bytes(R1)
			+ element_length_in_bytes(R2) + element_length_in_bytes(R3)
			+ element_length_in_bytes(R4);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	data_buf += element_to_bytes(data_buf, gpk->K);
	data_buf += element_to_bytes(data_buf, gpk->H);
	data_buf += element_to_bytes(data_buf, gpk->G);
	data_buf += element_to_bytes(data_buf, sig->sigma.T1);
	data_buf += element_to_bytes(data_buf, sig->sigma.T2);
	data_buf += element_to_bytes(data_buf, sig->sigma.T3);
	data_buf += element_to_bytes(data_buf, sig->sigma.T4);
	data_buf += element_to_bytes(data_buf, od->A);
	data_buf += element_to_bytes(data_buf, R1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf += element_to_bytes(data_buf, R3);
	data_buf += element_to_bytes(data_buf, R4);
	data_buf -= data_len;

	BYTE* hash = (BYTE*) malloc(OPEN_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, hash, OPEN_HASH_BITS);

	free(data_buf);
	element_clear(R1);
	element_clear(R2);
	element_clear(R3);
	element_clear(R4);

	// compare hashes
	ret = memcmp(od->tau.hash, hash, OPEN_HASH_BITS / 8);
	free(hash);
	if (!ret) {
		// verify S = sign_usk(A)
		DWORD msg_len = element_length_in_bytes(od->A);
		BYTE* msg = (BYTE*) malloc(msg_len);
		element_to_bytes(msg, od->A);

		ret = xsgs_rsa_verify(upk_pem_filename, msg, msg_len, od->S.sig,
				od->S.len);
		free(msg);
	}

	return ret;
}
