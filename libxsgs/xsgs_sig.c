#include <string.h>
#include <math.h>
#include "xsgs.h"

// SIGN (msg_len in bytes)
void xsgs_sign(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_SIGNED_MSG* sig_msg) {
	element_t alpha, beta;
	element_t r_alpha, r_beta, r_x, r_z;
	element_t R1, R2, R3, R4;
	element_t z, g1, g12, gt;
	element_t c;
	field_ptr Zr = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr GT = gpk->pairing->GT;

	// 1. choose alpha, beta e Zp at random
	element_init(alpha, Zr);
	element_random(alpha);
	element_init(beta, Zr);
	element_random(beta);

	// initialize  T1, T2, T3 and T4 e Group1
	element_init(sig_msg->sigma.T1, G1);
	element_init(sig_msg->sigma.T2, G1);
	element_init(sig_msg->sigma.T3, G1);
	element_init(sig_msg->sigma.T4, G1);

	// 2. T1 = K^alpha,
	element_pow_naf(sig_msg->sigma.T1, gpk->K, alpha);
	// T2 = A * H^alpha,
	element_pow_naf(sig_msg->sigma.T2, gpk->H, alpha);
	element_mul(sig_msg->sigma.T2, ucert->A, sig_msg->sigma.T2);
	// T3 = K^beta,
	element_pow_naf(sig_msg->sigma.T3, gpk->K, beta);
	// T4 = A * G^beta,
	element_pow_naf(sig_msg->sigma.T4, gpk->G, beta);
	element_mul(sig_msg->sigma.T4, ucert->A, sig_msg->sigma.T4);
	// 3. select r_alpha, r_beta, r_x, r_z e Zp* at random
	element_init(r_alpha, Zr);
	element_random(r_alpha);
	element_init(r_beta, Zr);
	element_random(r_beta);
	element_init(r_x, Zr);
	element_random(r_x);
	element_init(r_z, Zr);
	element_random(r_z);

	// 4. compute R1, R2, R3 and R4
	element_init(R1, G1);
	element_init(R2, GT);
	element_init(R3, G1);
	element_init(R4, G1);

	// tmp
	element_init(gt, GT);
	element_init(g1, G1);
	element_init(g12, G1);
	element_init(z, Zr);

	// R1 = K^r_alpha
	element_pow_naf(R1, gpk->K, r_alpha);
	// R3 = K^r_beta
	element_pow_naf(R3, gpk->K, r_beta);
	// R4 = H^r_alpha * G^-r_beta
	element_neg(z, r_beta);
	element_pow_naf2(R4, gpk->H, r_alpha, gpk->G, z);
	// R2 = [e(T2, G2)^r_x] * [e(H, W)^-r_alpha] * [e(H, G2)^-r_z]
	// = e(T2^r_x * H^-r_z, G2) * e(H^-r_alpha, W)
	element_neg(z, r_z);
	element_pow_naf2(g1, sig_msg->sigma.T2, r_x, gpk->H, z);
	element_neg(z, r_alpha);
	element_pow_naf(g12, gpk->H, z);
	element_pairing(R2, g1, gpk->G2);
	element_pairing(gt, g12, gpk->W);
	element_mul(R2, R2, gt);

	// clear tmp
	element_clear(gt);
	element_clear(g1);
	element_clear(g12);

	// 5. compute hash c <- H(M, T1, T2, T3, T4, R1, R2, R3, R4)
	DWORD data_len = sig_msg->msg_len
			+ element_length_in_bytes(sig_msg->sigma.T1)
			+ element_length_in_bytes(sig_msg->sigma.T2)
			+ element_length_in_bytes(sig_msg->sigma.T3)
			+ element_length_in_bytes(sig_msg->sigma.T4)
			+ element_length_in_bytes(R1) + element_length_in_bytes(R2)
			+ element_length_in_bytes(R3) + element_length_in_bytes(R4);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	memcpy(data_buf, sig_msg->msg, sig_msg->msg_len);
	data_buf += sig_msg->msg_len;
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T1);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T2);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T3);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T4);
	data_buf += element_to_bytes(data_buf, R1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf += element_to_bytes(data_buf, R3);
	data_buf += element_to_bytes(data_buf, R4);
	data_buf -= data_len;

	element_clear(R1);
	element_clear(R2);
	element_clear(R3);
	element_clear(R4);

	sig_msg->sigma.c = (BYTE*) malloc(SIGNATURE_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, sig_msg->sigma.c, SIGNATURE_HASH_BITS);

	free(data_buf);

	element_init(c, Zr);
	element_from_hash(c, sig_msg->sigma.c, SIGNATURE_HASH_BITS / 8);
	//element_printf("hash c = %B\n", c);

	// 6. compute s_alpha, s_beta, s_x, s_z
	element_init(sig_msg->sigma.s_alpha, Zr);
	element_init(sig_msg->sigma.s_beta, Zr);
	element_init(sig_msg->sigma.s_x, Zr);
	element_init(sig_msg->sigma.s_z, Zr);

	// z = x * alpha + y
	element_mul(z, ucert->x, alpha);
	element_add(z, z, uk->y);

	// s_alpha = r_alpha + c * alpha mod p
	element_mul(sig_msg->sigma.s_alpha, c, alpha);
	element_add(sig_msg->sigma.s_alpha, sig_msg->sigma.s_alpha, r_alpha);
	// s_beta = r_beta + c * beta mod p
	element_mul(sig_msg->sigma.s_beta, c, beta);
	element_add(sig_msg->sigma.s_beta, sig_msg->sigma.s_beta, r_beta);
	// s_x = r_x + c * x mod p
	element_mul(sig_msg->sigma.s_x, c, ucert->x);
	element_add(sig_msg->sigma.s_x, sig_msg->sigma.s_x, r_x);
	// s_z = r_z + c * z mod p
	element_mul(sig_msg->sigma.s_z, c, z);
	element_add(sig_msg->sigma.s_z, sig_msg->sigma.s_z, r_z);

	element_clear(alpha);
	element_clear(beta);
	element_clear(r_alpha);
	element_clear(r_beta);
	element_clear(r_x);
	element_clear(r_z);
	element_clear(z);
	element_clear(c);

	return;
}

void xsgs_sign_cache(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, XSGS_SIGNED_MSG* sig_msg) {
	element_t alpha, beta;
	element_t r_alpha, r_beta, r_x, r_z;
	element_t R1, R2, R3, R4;
	element_t z, g1, c;
	field_ptr Zr = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr GT = gpk->pairing->GT;

	// 1. choose alpha, beta e Zp at random
	element_init(alpha, Zr);
	element_random(alpha);
	element_init(beta, Zr);
	element_random(beta);

	// initialize  T1, T2, T3 and T4 e Group1
	element_init(sig_msg->sigma.T1, G1);
	element_init(sig_msg->sigma.T2, G1);
	element_init(sig_msg->sigma.T3, G1);
	element_init(sig_msg->sigma.T4, G1);

	// 2. T1 = K^alpha,
	fixed_base_exp_naf(sig_msg->sigma.T1, cache->LUT_K, alpha);
	// T2 = A * H^alpha,
	fixed_base_exp_naf(sig_msg->sigma.T2, cache->LUT_H, alpha);
	element_mul(sig_msg->sigma.T2, ucert->A, sig_msg->sigma.T2);
	// T3 = K^beta,
	fixed_base_exp_naf(sig_msg->sigma.T3, cache->LUT_K, beta);
	// T4 = A * G^beta,
	fixed_base_exp_naf(sig_msg->sigma.T4, cache->LUT_G, beta);
	element_mul(sig_msg->sigma.T4, ucert->A, sig_msg->sigma.T4);

	// 3. select r_alpha, r_beta, r_x, r_z e Zp* at random
	element_init(r_alpha, Zr);
	element_random(r_alpha);
	element_init(r_beta, Zr);
	element_random(r_beta);
	element_init(r_x, Zr);
	element_random(r_x);
	element_init(r_z, Zr);
	element_random(r_z);

	// 4. compute R1, R2, R3 and R4
	element_init(R1, G1);
	element_init(R2, GT);
	element_init(R3, G1);
	element_init(R4, G1);
	// tmp
	element_init(g1, G1);
	element_init(z, Zr);

	// R1 = K^r_alpha
	fixed_base_exp_naf(R1, cache->LUT_K, r_alpha);
	// R3 = K^r_beta
	fixed_base_exp_naf(R3, cache->LUT_K, r_beta);
	// R4 = H^r_alpha * G^-r_beta
	element_neg(z, r_beta);
	fixed_base_exp_naf2(R4, cache->LUT_H, r_alpha, cache->LUT_G, z);
	// R2 = [e(T2, G2)^r_x] * [e(H, W)^-r_alpha] * [e(H, G2)^-r_z]
	// = e(A, G2)^r_x * e(H, G2)^{alpha * r_x - r_z} * e(H, W)^{-r_alpha}
	element_mul(z, alpha, r_x);
	element_sub(z, z, r_z);
	element_neg(r_alpha, r_alpha);
	fixed_base_exp_naf3(R2, cache->LUT_A_G2, r_x, cache->LUT_H_G2, z,
			cache->LUT_H_W, r_alpha);
	element_neg(r_alpha, r_alpha);

	// clear tmp
	element_clear(g1);
	//element_clear(z);

	// 4) compute hash c <- H(M, T1, T2, T3, T4, R1, R2, R3, R4)
	DWORD data_len = sig_msg->msg_len
			+ element_length_in_bytes(sig_msg->sigma.T1)
			+ element_length_in_bytes(sig_msg->sigma.T2)
			+ element_length_in_bytes(sig_msg->sigma.T3)
			+ element_length_in_bytes(sig_msg->sigma.T4)
			+ element_length_in_bytes(R1) + element_length_in_bytes(R2)
			+ element_length_in_bytes(R3) + element_length_in_bytes(R4);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	memcpy(data_buf, sig_msg->msg, sig_msg->msg_len);
	data_buf += sig_msg->msg_len;
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T1);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T2);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T3);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T4);
	data_buf += element_to_bytes(data_buf, R1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf += element_to_bytes(data_buf, R3);
	data_buf += element_to_bytes(data_buf, R4);
	data_buf -= data_len;

	element_clear(R1);
	element_clear(R2);
	element_clear(R3);
	element_clear(R4);

	sig_msg->sigma.c = (BYTE*) malloc(SIGNATURE_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, sig_msg->sigma.c, SIGNATURE_HASH_BITS);

	free(data_buf);

	element_init(c, Zr);
	element_from_hash(c, sig_msg->sigma.c, SIGNATURE_HASH_BITS / 8);
	//element_printf("hash c = %B\n", c);

	// 5) compute s_alpha, s_beta, s_x, s_z
	element_init(sig_msg->sigma.s_alpha, Zr);
	element_init(sig_msg->sigma.s_beta, Zr);
	element_init(sig_msg->sigma.s_x, Zr);
	element_init(sig_msg->sigma.s_z, Zr);

	// z = x * alpha + y
	//element_init(z, Zr);
	element_mul(z, ucert->x, alpha);
	element_add(z, z, uk->y);

	// s_alpha = r_alpha + c * alpha mod p
	element_mul(sig_msg->sigma.s_alpha, c, alpha);
	element_add(sig_msg->sigma.s_alpha, sig_msg->sigma.s_alpha, r_alpha);
	// s_beta = r_beta + c * beta mod p
	element_mul(sig_msg->sigma.s_beta, c, beta);
	element_add(sig_msg->sigma.s_beta, sig_msg->sigma.s_beta, r_beta);
	// s_x = r_x + c * x mod p
	element_mul(sig_msg->sigma.s_x, c, ucert->x);
	element_add(sig_msg->sigma.s_x, sig_msg->sigma.s_x, r_x);
	// s_z = r_z + c * z mod p
	element_mul(sig_msg->sigma.s_z, c, z);
	element_add(sig_msg->sigma.s_z, sig_msg->sigma.s_z, r_z);

	element_clear(alpha);
	element_clear(beta);
	element_clear(r_alpha);
	element_clear(r_beta);
	element_clear(r_x);
	element_clear(r_z);
	element_clear(z);
	element_clear(c);

	return;
}

// BATCH SIGN (msg_len in bytes)
void xsgs_batch_sign(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_BATCH_SIGNED_MSG** sig_msg_list,
		DWORD list_size) {
	element_t alpha, beta;
	element_t r_alpha, r_beta, r_x, r_z;
	element_t z, g1, g12, gt;
	element_t c;
	field_ptr Zr = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr GT = gpk->pairing->GT;
	DWORD data_len;
	BYTE *data_buf, *hash_buf;

	element_init(alpha, Zr);
	element_init(beta, Zr);
	element_init(r_alpha, Zr);
	element_init(r_beta, Zr);
	element_init(r_x, Zr);
	element_init(r_z, Zr);
	element_init(c, Zr);
	element_init(z, Zr);
	element_init(g1, G1);
	element_init(g12, G1);
	element_init(gt, GT);

	for (DWORD i = 0; i < list_size; i++) {
		// 1. choose alpha, beta e Zp at random
		element_random(alpha);
		element_random(beta);

		// initialize  T1, T2, T3 and T4 e Group1
		element_init(sig_msg_list[i]->sigma.T1, G1);
		element_init(sig_msg_list[i]->sigma.T2, G1);
		element_init(sig_msg_list[i]->sigma.T3, G1);
		element_init(sig_msg_list[i]->sigma.T4, G1);

		// 2. T1 = K^alpha,
		element_pow_naf(sig_msg_list[i]->sigma.T1, gpk->K, alpha);
		// T2 = A * H^alpha,
		element_pow_naf(sig_msg_list[i]->sigma.T2, gpk->H, alpha);
		element_mul(sig_msg_list[i]->sigma.T2, ucert->A,
				sig_msg_list[i]->sigma.T2);
		// T3 = K^beta,
		element_pow_naf(sig_msg_list[i]->sigma.T3, gpk->K, beta);
		// T4 = A * G^beta,
		element_pow_naf(sig_msg_list[i]->sigma.T4, gpk->G, beta);
		element_mul(sig_msg_list[i]->sigma.T4, ucert->A,
				sig_msg_list[i]->sigma.T4);

		// 3. select r_alpha, r_beta, r_x, r_z e Zp* at random
		element_random(r_alpha);
		element_random(r_beta);
		element_random(r_x);
		element_random(r_z);

		// 4. compute R1, R2, R3 and R4
		element_init(sig_msg_list[i]->sigma.R1, G1);
		element_init(sig_msg_list[i]->sigma.R2, GT);
		element_init(sig_msg_list[i]->sigma.R3, G1);
		element_init(sig_msg_list[i]->sigma.R4, G1);

		// R1 = K^r_alpha
		element_pow_naf(sig_msg_list[i]->sigma.R1, gpk->K, r_alpha);
		// R3 = K^r_beta
		element_pow_naf(sig_msg_list[i]->sigma.R3, gpk->K, r_beta);
		// R4 =  H^r_alpha * G^-r_beta
		element_neg(z, r_beta);
		element_pow_naf2(sig_msg_list[i]->sigma.R4, gpk->H, r_alpha, gpk->G, z);
		// R2 = [e(T2, G2)^r_x] * [e(H, W)^-r_alpha] * [e(H, G2)^-r_z]
		// = e(T2^r_x * H^-r_z, G2) / e(H^r_alpha, W)
		element_neg(z, r_z);
		element_pow_naf2(g1, sig_msg_list[i]->sigma.T2, r_x, gpk->H, z);
		element_neg(z, r_alpha);
		element_pow_naf(g12, gpk->H, z);
		element_pairing(sig_msg_list[i]->sigma.R2, g1, gpk->G2);
		element_pairing(gt, g12, gpk->W);
		element_mul(sig_msg_list[i]->sigma.R2, sig_msg_list[i]->sigma.R2, gt);

		// 5. compute hash c <- H(M, T1, T2, T3, T4, R1, R2, R3, R4)
		data_len = sig_msg_list[i]->msg_len;
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.T1);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.T2);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.T3);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.T4);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.R1);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.R2);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.R3);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.R4);

		data_buf = (BYTE*) malloc(data_len);
		memcpy(data_buf, sig_msg_list[i]->msg, sig_msg_list[i]->msg_len);
		data_buf += sig_msg_list[i]->msg_len;
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.T1);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.T2);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.T3);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.T4);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.R1);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.R2);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.R3);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.R4);
		data_buf -= data_len;

		hash_buf = (BYTE*) malloc(BATCH_SIGNATURE_HASH_BITS / 8);
		xsgs_hash(data_buf, data_len * 8, hash_buf, BATCH_SIGNATURE_HASH_BITS);

		free(data_buf);

		element_from_hash(c, hash_buf, BATCH_SIGNATURE_HASH_BITS / 8);
		//element_printf("hash c = %B\n", c);

		free(hash_buf);

		// 6. compute s_alpha, s_beta, s_x, s_z
		element_init(sig_msg_list[i]->sigma.s_alpha, Zr);
		element_init(sig_msg_list[i]->sigma.s_beta, Zr);
		element_init(sig_msg_list[i]->sigma.s_x, Zr);
		element_init(sig_msg_list[i]->sigma.s_z, Zr);

		// z = x * alpha + y
		element_mul(z, ucert->x, alpha);
		element_add(z, z, uk->y);

		// s_alpha = r_alpha + c * alpha mod p
		element_mul(sig_msg_list[i]->sigma.s_alpha, c, alpha);
		element_add(sig_msg_list[i]->sigma.s_alpha,
				sig_msg_list[i]->sigma.s_alpha, r_alpha);
		// s_beta = r_beta + c * beta mod p
		element_mul(sig_msg_list[i]->sigma.s_beta, c, beta);
		element_add(sig_msg_list[i]->sigma.s_beta,
				sig_msg_list[i]->sigma.s_beta, r_beta);
		// s_x = r_x + c * x mod p
		element_mul(sig_msg_list[i]->sigma.s_x, c, ucert->x);
		element_add(sig_msg_list[i]->sigma.s_x, sig_msg_list[i]->sigma.s_x,
				r_x);
		// s_z = r_z + c * z mod p
		element_mul(sig_msg_list[i]->sigma.s_z, c, z);
		element_add(sig_msg_list[i]->sigma.s_z, sig_msg_list[i]->sigma.s_z,
				r_z);
	}

	element_clear(alpha);
	element_clear(beta);
	element_clear(r_alpha);
	element_clear(r_beta);
	element_clear(r_x);
	element_clear(r_z);
	element_clear(c);
	element_clear(z);
	element_clear(gt);
	element_clear(g1);
	element_clear(g12);

	return;
}

void xsgs_batch_sign_cache(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG** sig_msg_list, DWORD list_size) {
	element_t alpha, beta;
	element_t r_alpha, r_beta, r_x, r_z;
	element_t z, g1;
	element_t c;
	field_ptr Zr = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr GT = gpk->pairing->GT;
	DWORD data_len;
	BYTE *data_buf, *hash_buf;

	element_init(alpha, Zr);
	element_init(beta, Zr);
	element_init(r_alpha, Zr);
	element_init(r_beta, Zr);
	element_init(r_x, Zr);
	element_init(r_z, Zr);
	element_init(c, Zr);
	element_init(z, Zr);
	element_init(g1, G1);

	for (DWORD i = 0; i < list_size; i++) {
		// 1. choose alpha, beta e Zp at random
		element_random(alpha);
		element_random(beta);

		// initialize  T1, T2, T3 and T4 e Group1
		element_init(sig_msg_list[i]->sigma.T1, G1);
		element_init(sig_msg_list[i]->sigma.T2, G1);
		element_init(sig_msg_list[i]->sigma.T3, G1);
		element_init(sig_msg_list[i]->sigma.T4, G1);

		// 2. T1 = K^alpha,
		fixed_base_exp_naf(sig_msg_list[i]->sigma.T1, cache->LUT_K, alpha);
		// T2 = A * H^alpha,
		fixed_base_exp_naf(sig_msg_list[i]->sigma.T2, cache->LUT_H, alpha);
		element_mul(sig_msg_list[i]->sigma.T2, ucert->A,
				sig_msg_list[i]->sigma.T2);
		// T3 = K^beta,
		fixed_base_exp_naf(sig_msg_list[i]->sigma.T3, cache->LUT_K, beta);
		// T4 = A * G^beta,
		fixed_base_exp_naf(sig_msg_list[i]->sigma.T4, cache->LUT_G, beta);
		element_mul(sig_msg_list[i]->sigma.T4, ucert->A,
				sig_msg_list[i]->sigma.T4);

		// 3. select r_alpha, r_beta, r_x, r_z e Zp* at random
		element_random(r_alpha);
		element_random(r_beta);
		element_random(r_x);
		element_random(r_z);

		// 4. compute R1, R2, R3 and R4
		element_init(sig_msg_list[i]->sigma.R1, G1);
		element_init(sig_msg_list[i]->sigma.R2, GT);
		element_init(sig_msg_list[i]->sigma.R3, G1);
		element_init(sig_msg_list[i]->sigma.R4, G1);

		// R1 = K^r_alpha
		fixed_base_exp_naf(sig_msg_list[i]->sigma.R1, cache->LUT_K, r_alpha);
		// R3 = K^r_beta
		fixed_base_exp_naf(sig_msg_list[i]->sigma.R3, cache->LUT_K, r_beta);
		// R4 = H^r_alpha * G^-r_beta
		element_neg(z, r_beta);
		fixed_base_exp_naf2(sig_msg_list[i]->sigma.R4, cache->LUT_H, r_alpha,
				cache->LUT_G, z);
		// R2 = [e(T2, G2)^r_x] * [e(H, W)^-r_alpha] * [e(H, G2)^-r_z]
		// = e(A, G2)^r_x * e(H, G2)^{alpha * r_x - r_z} * e(H, W)^{-r_alpha}
		element_mul(z, alpha, r_x);
		element_sub(z, z, r_z);
		element_neg(r_alpha, r_alpha);
		fixed_base_exp_naf3(sig_msg_list[i]->sigma.R2, cache->LUT_A_G2, r_x,
				cache->LUT_H_G2, z, cache->LUT_H_W, r_alpha);
		element_neg(r_alpha, r_alpha);

		// 4) compute hash c <- H(M, T1, T2, T3, T4, R1, R2, R3, R4)
		data_len = sig_msg_list[i]->msg_len;
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.T1);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.T2);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.T3);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.T4);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.R1);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.R2);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.R3);
		data_len += element_length_in_bytes(sig_msg_list[i]->sigma.R4);

		data_buf = (BYTE*) malloc(data_len);
		memcpy(data_buf, sig_msg_list[i]->msg, sig_msg_list[i]->msg_len);
		data_buf += sig_msg_list[i]->msg_len;
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.T1);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.T2);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.T3);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.T4);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.R1);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.R2);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.R3);
		data_buf += element_to_bytes(data_buf, sig_msg_list[i]->sigma.R4);
		data_buf -= data_len;

		hash_buf = (BYTE*) malloc(BATCH_SIGNATURE_HASH_BITS / 8);
		xsgs_hash(data_buf, data_len * 8, hash_buf, BATCH_SIGNATURE_HASH_BITS);

		free(data_buf);

		element_from_hash(c, hash_buf, BATCH_SIGNATURE_HASH_BITS / 8);
		//element_printf("hash c = %B\n", c);

		free(hash_buf);

		// 5) compute s_alpha, s_beta, s_x, s_z
		element_init(sig_msg_list[i]->sigma.s_alpha, Zr);
		element_init(sig_msg_list[i]->sigma.s_beta, Zr);
		element_init(sig_msg_list[i]->sigma.s_x, Zr);
		element_init(sig_msg_list[i]->sigma.s_z, Zr);

		// z = x * alpha + y
		element_mul(z, ucert->x, alpha);
		element_add(z, z, uk->y);

		// s_alpha = r_alpha + c * alpha mod p
		element_mul(sig_msg_list[i]->sigma.s_alpha, c, alpha);
		element_add(sig_msg_list[i]->sigma.s_alpha,
				sig_msg_list[i]->sigma.s_alpha, r_alpha);
		// s_beta = r_beta + c * beta mod p
		element_mul(sig_msg_list[i]->sigma.s_beta, c, beta);
		element_add(sig_msg_list[i]->sigma.s_beta,
				sig_msg_list[i]->sigma.s_beta, r_beta);
		// s_x = r_x + c * x mod p
		element_mul(sig_msg_list[i]->sigma.s_x, c, ucert->x);
		element_add(sig_msg_list[i]->sigma.s_x, sig_msg_list[i]->sigma.s_x,
				r_x);
		// s_z = r_z + c * z mod p
		element_mul(sig_msg_list[i]->sigma.s_z, c, z);
		element_add(sig_msg_list[i]->sigma.s_z, sig_msg_list[i]->sigma.s_z,
				r_z);
	}

	element_clear(alpha);
	element_clear(beta);
	element_clear(r_alpha);
	element_clear(r_beta);
	element_clear(r_x);
	element_clear(r_z);
	element_clear(c);
	element_clear(z);
	element_clear(g1);

	return;
}

// VERIFY (msg_len in bytes)
int xsgs_verify(XSGS_PUBLIC_KEY* gpk, XSGS_SIGNED_MSG* sig_msg) {
	element_t R1, R2, R3, R4;
	element_t g1, g12, g2, gt, z, z2;
	element_t c;
	field_ptr Zr = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	field_ptr GT = gpk->pairing->GT;
	int ret;

	// 1. compute R1, R2, R3 and R4
	element_init(R1, G1);
	element_init(R2, GT);
	element_init(R3, G1);
	element_init(R4, G1);

	// tmp
	element_init(c, Zr);
	element_init(z, Zr);
	element_init(z2, Zr);
	element_init(g1, G1);
	element_init(g12, G1);
	element_init(g2, G2);
	element_init(gt, GT);

	element_from_hash(c, sig_msg->sigma.c, SIGNATURE_HASH_BITS / 8);
	//element_printf("hash c = %B\n", c);

	// R1 = K^s_alpha * T1^-c
	element_neg(z, c);
	element_pow_naf2(R1, gpk->K, sig_msg->sigma.s_alpha, sig_msg->sigma.T1, z);
	// R3 = K^s_beta * T3^-c
	element_pow_naf2(R3, gpk->K, sig_msg->sigma.s_beta, sig_msg->sigma.T3, z);
	// R4 = H^s_alpha * G^-s_beta * (T4 / T2)^c
	element_div(g1, sig_msg->sigma.T4, sig_msg->sigma.T2);
	element_neg(z2, sig_msg->sigma.s_beta);
	element_pow_naf3(R4, gpk->H, sig_msg->sigma.s_alpha, gpk->G, z2, g1, c);
	// R2 = [e(T2, G2)^s_x] * [e(H, W)^-s_alpha] * [e(H, G2)^-s_z] * { [e(G1, G2) / e(T2, W)]^-c }
	// = e(T2^s_x * H^-s_z * G1^-c, G2) * e(T2^c * H^-s_alpha, W)
	element_neg(z2, sig_msg->sigma.s_z);
	element_pow_naf3(g1, sig_msg->sigma.T2, sig_msg->sigma.s_x, gpk->H, z2,
			gpk->G1, z);
	element_neg(z2, sig_msg->sigma.s_alpha);
	element_pow_naf2(g12, sig_msg->sigma.T2, c, gpk->H, z2);
	element_pairing(R2, g1, gpk->G2);
	element_pairing(gt, g12, gpk->W);
	element_mul(R2, R2, gt);

	// clear tmp
	element_clear(c);
	element_clear(z);
	element_clear(z2);
	element_clear(g1);
	element_clear(g12);
	element_clear(g2);
	element_clear(gt);

	// 2. compute hash c <- H(M, T1, T2, T3, T4, R1, R2, R3, R4)
	DWORD data_len = sig_msg->msg_len
			+ element_length_in_bytes(sig_msg->sigma.T1)
			+ element_length_in_bytes(sig_msg->sigma.T2)
			+ element_length_in_bytes(sig_msg->sigma.T3)
			+ element_length_in_bytes(sig_msg->sigma.T4)
			+ element_length_in_bytes(R1) + element_length_in_bytes(R2)
			+ element_length_in_bytes(R3) + element_length_in_bytes(R4);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	memcpy(data_buf, sig_msg->msg, sig_msg->msg_len);
	data_buf += sig_msg->msg_len;
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T1);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T2);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T3);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T4);
	data_buf += element_to_bytes(data_buf, R1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf += element_to_bytes(data_buf, R3);
	data_buf += element_to_bytes(data_buf, R4);
	data_buf -= data_len;

	element_clear(R1);
	element_clear(R2);
	element_clear(R3);
	element_clear(R4);

	BYTE* hash_buf = (BYTE*) malloc(SIGNATURE_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, hash_buf, SIGNATURE_HASH_BITS);

	free(data_buf);

	// check hash
	ret = !memcmp(hash_buf, sig_msg->sigma.c, SIGNATURE_HASH_BITS / 8);

	free(hash_buf);

	return ret;
}

int xsgs_verify_cache(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_SIGNED_MSG* sig_msg) {
	element_t R1, R2, R3, R4;
	element_t g1, g2, gt, z, z1, z2;
	element_t c;
	field_ptr Zr = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	field_ptr GT = gpk->pairing->GT;
	int ret;

	// 1. compute R1, R2, R3 and R4
	element_init(R1, G1);
	element_init(R2, GT);
	element_init(R3, G1);
	element_init(R4, G1);

	// tmp
	element_init(c, Zr);
	element_init(z, Zr);
	element_init(z1, Zr);
	element_init(z2, Zr);
	element_init(g1, G1);
	element_init(g2, G2);
	element_init(gt, GT);

	element_from_hash(c, sig_msg->sigma.c, SIGNATURE_HASH_BITS / 8);
	//element_printf("hash c = %B\n", c);

	// R1 = K^s_alpha * T1^-c
	element_neg(z, c);
	fixed_base_exp_naf(R1, cache->LUT_K, sig_msg->sigma.s_alpha);
	element_pow_naf(g1, sig_msg->sigma.T1, z);
	element_mul(R1, R1, g1);
	// R3 = K^s_beta * T3^-c
	fixed_base_exp_naf(R3, cache->LUT_K, sig_msg->sigma.s_beta);
	element_pow_naf(g1, sig_msg->sigma.T3, z);
	element_mul(R3, R3, g1);
	// R4 = H^s_alpha * G^-s_beta * (T4 / T2)^c
	element_neg(z1, sig_msg->sigma.s_beta);
	element_div(g1, sig_msg->sigma.T4, sig_msg->sigma.T2);
	element_pow_naf3(R4, gpk->H, sig_msg->sigma.s_alpha, gpk->G, z1, g1, c);
	// R2 = [e(T2, G2)^s_x] * [e(H, W)^-s_alpha] * [e(H, G2)^-s_z] * { [e(G1, G2) / e(T2, W)]^-c }
	//    = e(H, W)^{-s_alpha} * e(H, G2)^{-s_z} * e(G1, G2)^{-c} * e(T2, G2^s_x * W^c)
	element_neg(z1, sig_msg->sigma.s_alpha);
	element_neg(z2, sig_msg->sigma.s_z);
	fixed_base_exp_naf3(R2, cache->LUT_H_W, z1, cache->LUT_H_G2, z2,
			cache->LUT_G1_G2, z);
	fixed_base_exp_naf2(g2, cache->LUT_G2, sig_msg->sigma.s_x, cache->LUT_W, c);
	element_pairing(gt, sig_msg->sigma.T2, g2);
	element_mul(R2, R2, gt);

	// clear tmp
	element_clear(c);
	element_clear(z);
	element_clear(z1);
	element_clear(z2);
	element_clear(g1);
	element_clear(g2);
	element_clear(gt);

	// 2). compute hash c <- H(M, T1, T2, T3, T4, R1, R2, R3, R4)
	DWORD data_len = sig_msg->msg_len
			+ element_length_in_bytes(sig_msg->sigma.T1)
			+ element_length_in_bytes(sig_msg->sigma.T2)
			+ element_length_in_bytes(sig_msg->sigma.T3)
			+ element_length_in_bytes(sig_msg->sigma.T4)
			+ element_length_in_bytes(R1) + element_length_in_bytes(R2)
			+ element_length_in_bytes(R3) + element_length_in_bytes(R4);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	memcpy(data_buf, sig_msg->msg, sig_msg->msg_len);
	data_buf += sig_msg->msg_len;
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T1);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T2);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T3);
	data_buf += element_to_bytes(data_buf, sig_msg->sigma.T4);
	data_buf += element_to_bytes(data_buf, R1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf += element_to_bytes(data_buf, R3);
	data_buf += element_to_bytes(data_buf, R4);
	data_buf -= data_len;

	element_clear(R1);
	element_clear(R2);
	element_clear(R3);
	element_clear(R4);

	BYTE* hash_buf = (BYTE*) malloc(SIGNATURE_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, hash_buf, SIGNATURE_HASH_BITS);

	free(data_buf);

	// check hash
	ret = !memcmp(hash_buf, sig_msg->sigma.c, SIGNATURE_HASH_BITS / 8);

	free(hash_buf);

	return ret;
}

// BATCH VERIFY - non pairing checks of signature verification
int xsgs_batch_verify_internal1(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG* sig, element_t c) {
	int ret = 0;
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	element_t R, g1, z;

	// 1. compute hash c <- H(M, T1, T2, T3, T4, R1, R2, R3, R4)
	DWORD data_len = sig->msg_len + element_length_in_bytes(sig->sigma.T1)
			+ element_length_in_bytes(sig->sigma.T2)
			+ element_length_in_bytes(sig->sigma.T3)
			+ element_length_in_bytes(sig->sigma.T4)
			+ element_length_in_bytes(sig->sigma.R1)
			+ element_length_in_bytes(sig->sigma.R2)
			+ element_length_in_bytes(sig->sigma.R3)
			+ element_length_in_bytes(sig->sigma.R4);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	memcpy(data_buf, sig->msg, sig->msg_len);
	data_buf += sig->msg_len;
	data_buf += element_to_bytes(data_buf, sig->sigma.T1);
	data_buf += element_to_bytes(data_buf, sig->sigma.T2);
	data_buf += element_to_bytes(data_buf, sig->sigma.T3);
	data_buf += element_to_bytes(data_buf, sig->sigma.T4);
	data_buf += element_to_bytes(data_buf, sig->sigma.R1);
	data_buf += element_to_bytes(data_buf, sig->sigma.R2);
	data_buf += element_to_bytes(data_buf, sig->sigma.R3);
	data_buf += element_to_bytes(data_buf, sig->sigma.R4);
	data_buf -= data_len;

	BYTE* hash_buf = (BYTE*) malloc(BATCH_SIGNATURE_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, hash_buf, BATCH_SIGNATURE_HASH_BITS);

	free(data_buf);

	element_from_hash(c, hash_buf, BATCH_SIGNATURE_HASH_BITS / 8);

	free(hash_buf);

	// 2. compute and check non-pairing equations for R1, R3 and R4
	// tmp
	element_init_G1(R, pairing);
	element_init_G1(g1, pairing);
	element_init(z, Fp);

	// R1 = K^s_alpha * T1^-c
	element_neg(z, c);
	element_pow_naf2(R, gpk->K, sig->sigma.s_alpha, sig->sigma.T1, z);

	ret = element_cmp(R, sig->sigma.R1);
	if (!ret) {
		// R3 = K^s_beta * T3^-c
		element_pow_naf2(R, gpk->K, sig->sigma.s_beta, sig->sigma.T3, z);

		ret = element_cmp(R, sig->sigma.R3);
		if (!ret) {
			// R4 = H^s_alpha * G^-s_beta * (T4 / T2)^c
			element_neg(z, sig->sigma.s_beta);
			element_div(g1, sig->sigma.T4, sig->sigma.T2);
			element_pow_naf3(R, gpk->H, sig->sigma.s_alpha, gpk->G, z, g1, c);

			ret = element_cmp(R, sig->sigma.R4);
		}
	}

	// clear tmp
	element_clear(R);
	element_clear(g1);
	element_clear(z);

	return ret;
}

int xsgs_batch_verify_internal1_cache(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG* sig, element_t c) {
	int ret = 0;
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	element_t R, g1, z;

	// 1. compute hash c <- H(M, T1, T2, T3, T4, R1, R2, R3, R4)
	DWORD data_len = sig->msg_len + element_length_in_bytes(sig->sigma.T1)
			+ element_length_in_bytes(sig->sigma.T2)
			+ element_length_in_bytes(sig->sigma.T3)
			+ element_length_in_bytes(sig->sigma.T4)
			+ element_length_in_bytes(sig->sigma.R1)
			+ element_length_in_bytes(sig->sigma.R2)
			+ element_length_in_bytes(sig->sigma.R3)
			+ element_length_in_bytes(sig->sigma.R4);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	memcpy(data_buf, sig->msg, sig->msg_len);
	data_buf += sig->msg_len;
	data_buf += element_to_bytes(data_buf, sig->sigma.T1);
	data_buf += element_to_bytes(data_buf, sig->sigma.T2);
	data_buf += element_to_bytes(data_buf, sig->sigma.T3);
	data_buf += element_to_bytes(data_buf, sig->sigma.T4);
	data_buf += element_to_bytes(data_buf, sig->sigma.R1);
	data_buf += element_to_bytes(data_buf, sig->sigma.R2);
	data_buf += element_to_bytes(data_buf, sig->sigma.R3);
	data_buf += element_to_bytes(data_buf, sig->sigma.R4);
	data_buf -= data_len;

	BYTE* hash_buf = (BYTE*) malloc(BATCH_SIGNATURE_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, hash_buf, BATCH_SIGNATURE_HASH_BITS);

	free(data_buf);

	element_from_hash(c, hash_buf, BATCH_SIGNATURE_HASH_BITS / 8);

	free(hash_buf);

	// 2. compute and check non-pairing equations for R1, R3 and R4
	// tmp
	element_init_G1(R, pairing);
	element_init_G1(g1, pairing);
	element_init(z, Fp);

	// R1 = K^s_alpha * T1^-c
	element_neg(z, c);
	fixed_base_exp_naf(R, cache->LUT_K, sig->sigma.s_alpha);
	element_pow_naf(g1, sig->sigma.T1, z);
	element_mul(R, R, g1);

	ret = element_cmp(R, sig->sigma.R1);
	if (!ret) {
		// R3 = K^s_beta * T3^-c
		fixed_base_exp_naf(R, cache->LUT_K, sig->sigma.s_beta);
		element_pow_naf(g1, sig->sigma.T3, z);
		element_mul(R, R, g1);

		ret = element_cmp(R, sig->sigma.R3);
		if (!ret) {
			// R4 = H^s_alpha * G^-s_beta * (T4 / T2)^c
			element_neg(z, sig->sigma.s_beta);
			element_div(g1, sig->sigma.T4, sig->sigma.T2);
			element_pow_naf3(R, gpk->H, sig->sigma.s_alpha, gpk->G, z, g1, c);

			ret = element_cmp(R, sig->sigma.R4);
		}
	}

	// clear tmp
	element_clear(R);
	element_clear(g1);
	element_clear(z);

	return ret;
}

// BATCH VERIFY - precompute values X, Y, Z for pairing check
void xsgs_batch_verify_internal2(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG* sig, element_t c, element_t X, element_t Y, element_t Z) {
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	element_t delta, z1, z2, z3;

	element_init(delta, Fp);
	element_init(z1, Fp);
	element_init(z2, Fp);
	element_init(z3, Fp);

	// 3. a. choose delta e Zp at random
	element_random(delta);

	// c. Y <- (T2^c * H^-s_alpha)^delta = T2^{c * delta} * H^{-s_alpha * delta}
	element_mul(z1, delta, c);
	element_mul(z2, delta, sig->sigma.s_alpha);
	element_neg(z2, z2);
	element_pow_naf2(Y, sig->sigma.T2, z1, gpk->H, z2);

	// b. X <- (T2^s_x * H^-s_z * G1^-c)^delta = G1^{-c * delta} * T2^{s_x * delta} * H^{-s_z * delta}
	element_neg(z1, z1);
	element_mul(z2, delta, sig->sigma.s_x);
	element_mul(z3, delta, sig->sigma.s_z);
	element_neg(z3, z3);
	element_pow_naf3(X, gpk->G1, z1, sig->sigma.T2, z2, gpk->H, z3);

	// d. Z <- R2^delta
	element_pow_zn(Z, sig->sigma.R2, delta);

	// clear tmp
	element_clear(delta);
	element_clear(z1);
	element_clear(z2);
	element_clear(z3);

	return;
}

void xsgs_batch_verify_internal2_cache(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG* sig, element_t c, element_t X, element_t Y, element_t Z) {
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	element_t delta, z1, z2, z3, g1;

	element_init(delta, Fp);
	element_init(z1, Fp);
	element_init(z2, Fp);
	element_init(z3, Fp);
	element_init(g1, pairing->G1);

	// 3. a. choose delta e Zp at random
	element_random(delta);

	// c. Y <- (T2^c * H^-s_alpha)^delta = T2^{c * delta} * H^{-s_alpha * delta}
	element_mul(z1, delta, c);
	element_mul(z2, delta, sig->sigma.s_alpha);
	element_neg(z2, z2);
	element_pow_naf(Y, sig->sigma.T2, z1);
	fixed_base_exp_naf(g1, cache->LUT_H, z2);
	element_mul(Y, Y, g1);

	// b. X <- (T2^s_x * H^-s_z * G1^-c)^delta = G1^{-c * delta} * H^{-s_z * delta} * T2^{s_x * delta}
	element_neg(z1, z1);
	element_mul(z2, delta, sig->sigma.s_z);
	element_neg(z2, z2);
	element_mul(z3, delta, sig->sigma.s_x);
	element_pow_naf3(X, gpk->G1, z1, gpk->H, z2, sig->sigma.T2, z3);

	// d. Z <- R2^delta
	element_pow_zn(Z, sig->sigma.R2, delta);

	// clear tmp
	element_clear(delta);
	element_clear(z1);
	element_clear(z2);
	element_clear(z3);
	element_clear(g1);

	return;
}

// BATCH VERIFY - pairing check of signature verification
int xsgs_batch_verify_internal3a(XSGS_PUBLIC_KEY* gpk, element_t X, element_t Y, element_t Z, element_t U, element_t V, element_t A) {
	field_ptr GT = gpk->pairing->GT;
	element_t gt;

	element_init(gt, GT);

	// A0 = e(X_product, U = -G2) * e(Y_product, V = -W) * Z_product
	element_neg(U, gpk->G2);
	element_neg(V, gpk->W);
	element_pairing(A, X, U);
	element_pairing(gt, Y, V);
	element_mul(A, A, gt);
	element_mul(A, A, Z);

	element_clear(gt);

	return element_is1(A);
}

int xsgs_batch_verify_internal3b(XSGS_PUBLIC_KEY* gpk, element_t X, element_t Y, element_t Z) {
	element_t A0, gt;

	element_init_GT(A0, gpk->pairing);
	element_init_GT(gt, gpk->pairing);

	// 4. check Z = e(X, G2) * e(Y, W)
	element_pairing(A0, X, gpk->G2);
	element_pairing(gt, Y, gpk->W);
	element_mul(A0, A0, gt);
	int ret = element_cmp(A0, Z);

	element_clear(A0);
	element_clear(gt);

	return ret;
}

int xsgs_batch_verify_internal3c(XSGS_PUBLIC_KEY* gpk, element_t X, element_t Y, element_t Z, element_t U, element_t V, element_t A) {
	field_ptr GT = gpk->pairing->GT;
	element_t gt;

	element_init(gt, GT);

	// A0 = e(X_product, U = -G2) * e(Y_product, V = -W) * Z_product
	element_pairing(A, X, U);
	element_pairing(gt, Y, V);
	element_mul(A, A, gt);
	element_mul(A, A, Z);

	element_clear(gt);

	return element_is1(A);
}

// BATCH VERIFY - INTERNAL 4
// find invalid signatures with quick binary search
void xsgs_batch_verify_internal4a(XSGS_PUBLIC_KEY* gpk, BYTE* sig_status, DWORD* rem_list, DWORD list_size, element_t* X, element_t* Y, element_t* Z, element_t U, element_t V, element_t A) {
	field_ptr G1 = gpk->pairing->G1;
	field_ptr GT = gpk->pairing->GT;
	element_t X_product, Y_product, Z_product, A1, A2;
	DWORD i, j, remain_list_size1, remain_list_size2;
	DWORD* remain_list;

	element_init(A1, GT);
	element_init(A2, GT);

	if (list_size > 1) {
		if (list_size > 2) {
			BYTE first_pass = 1, second_pass = 0;
			element_init(X_product, G1);
			element_init(Y_product, G1);
			element_init(Z_product, GT);

			remain_list_size1 = list_size >> 1;
			remain_list = (DWORD*) malloc(remain_list_size1 * sizeof(DWORD));

			// initialize remain_lists
			for (i = 0; i < remain_list_size1; i++) {
				remain_list[i] = rem_list[i];
			}

			element_set1(X_product);
			element_set1(Y_product);
			element_set1(Z_product);

			// calculate products
			for (j = 0; j < remain_list_size1; j++) {
				i = remain_list[j];
				element_mul(X_product, X_product, X[i]);
				element_mul(Y_product, Y_product, Y[i]);
				element_mul(Z_product, Z_product, Z[i]);
			}

			// batch test of first half
			if (!xsgs_batch_verify_internal3c(gpk, X_product, Y_product,
					Z_product, U, V, A1)) {
				if (remain_list_size1 > 1) {
					xsgs_batch_verify_internal4a(gpk, sig_status, remain_list,
							remain_list_size1, X, Y, Z, U, V, A1);

				} else {
					sig_status[remain_list[0]] = 0;
				}
				first_pass = 0;
				if (element_cmp(A, A1) == 0) {
					second_pass = 1;
				}
			}

			free(remain_list);

			if (second_pass == 0) {
				remain_list_size2 = list_size - remain_list_size1;
				remain_list = (DWORD*) malloc(
						remain_list_size2 * sizeof(DWORD));

				// initialize remain_lists
				for (i = 0, j = remain_list_size1; i < remain_list_size2; i++) {
					remain_list[i] = rem_list[j++];
				}

				if (remain_list_size2 > 1) {
					if (first_pass == 0) {
						element_set0(X_product);
						element_set0(Y_product);
						element_set1(Z_product);

						// calculate sums and product
						for (j = 0; j < remain_list_size2; j++) {
							i = remain_list[j];
							element_mul(X_product, X_product, X[i]);
							element_mul(Y_product, Y_product, Y[i]);
							element_mul(Z_product, Z_product, Z[i]);
						}

						// batch test of second half
						if (!xsgs_batch_verify_internal3c(gpk, X_product,
								Y_product, Z_product, U, V, A2)) {
							xsgs_batch_verify_internal4a(gpk, sig_status,
									remain_list, remain_list_size2, X, Y, Z, U,
									V, A2);
						}
					} else {
						xsgs_batch_verify_internal4a(gpk, sig_status,
								remain_list, remain_list_size2, X, Y, Z, U, V,
								A);
					}
				} else {
					sig_status[remain_list[0]] = 0;
				}

				free(remain_list);
			}

			element_clear(X_product);
			element_clear(Y_product);
			element_clear(Z_product);
		} else if (!xsgs_batch_verify_internal3c(gpk, X[rem_list[0]],
				Y[rem_list[0]], Z[rem_list[0]], U, V, A1)) {
			sig_status[rem_list[0]] = 0;
			if (element_cmp(A, A1) != 0) {
				sig_status[rem_list[1]] = 0;
			}
		} else {
			sig_status[rem_list[1]] = 0;
		}
	}

	element_clear(A1);
	element_clear(A2);

	return;
}
// find invalid signatures with the method of Kitae Kim et al.
// Law et al.'s method with Daniel Shanks' Baby-step Giant-step algorithm for w < 3 and exhaustive search for w >= 3
int xsgs_batch_verify_internal4b(XSGS_PUBLIC_KEY* gpk, BYTE* sig_status, DWORD* remain_list, DWORD remain_list_size, element_t* X, element_t* Y, element_t* Z, element_t U, element_t V, element_t A_0, DWORD k_max) {
	field_ptr G1 = gpk->pairing->G1;
	field_ptr GT = gpk->pairing->GT;
	mpz_t jk, p, f;
	element_t X_product, Y_product, Z_product, A_product, A_inv_product, gt, *A;
	DWORD i, idx, k, t, *jw;
	int found_jw = 0;

	jw = (DWORD*) malloc((remain_list_size - 1) * sizeof(DWORD));
	A = (element_t*) malloc(remain_list_size * sizeof(element_t));
	memcpy(&A[0], A_0, sizeof(*A_0));

	mpz_init(jk);
	mpz_init(f);
	mpz_init(p);
	mpz_init_set(p, gpk->pairing->r);

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);
	element_init(A_product, GT);
	element_init(A_inv_product, GT);
	element_init(gt, GT);

	// search for faulty j_1 ... j_w
	for (k = 1; (k <= k_max) && (found_jw == 0); k++) {
		element_set1(X_product);
		element_set1(Y_product);
		element_set1(Z_product);

		// calculate products of X^(j^k), Y^(j^k), Z^(j^k)
		for (i = 0; i < remain_list_size; i++) {
			mpz_set_ui(jk, i + 1);
			idx = remain_list[i];

			element_pow_naf_mpz(X[idx], X[idx], jk);
			element_pow_naf_mpz(Y[idx], Y[idx], jk);
			element_pow_mpz(Z[idx], Z[idx], jk);

			element_mul(X_product, X_product, X[idx]);
			element_mul(Y_product, Y_product, Y[idx]);
			element_mul(Z_product, Z_product, Z[idx]);
		}

		// A_k = e(X_product, U = -G2) * e(Y_product, V = -W) * Z_product
		element_init(A[k], GT);
		element_pairing(A[k], X_product, U);
		element_pairing(gt, Y_product, V);
		element_mul(A[k], A[k], gt);
		element_mul(A[k], A[k], Z_product);

		// initialize j_1 ... j_k
		for (i = 0; i < k; i++) {
			jw[i] = i + 1;
		}

		switch (k) {
		// search for j_1 (Baby-step Giant-step)
		case 1: {
			DWORD max = round(sqrt(remain_list_size));
			element_t A_inv, A_c, *A_d = (element_t*) malloc(
					(max + 1) * sizeof(element_t));

			// initialize A_d[sqrt(N)+1]
			for (i = 0; i <= max; i++) {
				element_init(A_d[i], GT);
			}
			// A_d = A_0^{d*sqrt(N)} for d = { 0, ..., sqrt(N) }
			element_set1(A_d[0]);
			mpz_t tmp;
			mpz_init_set_ui(tmp, max);
			element_pow_mpz(A_d[1], A[0], tmp);
			mpz_clear(tmp);
			for (DWORD d = 2; d <= max; d++) {
				element_mul(A_d[d], A_d[d - 1], A_d[1]);
			}

			// initialize A_inv, A_c
			element_init(A_inv, GT);
			element_init(A_c, GT);
			// A_inv = A_0^-1
			element_invert(A_inv, A[0]);
			// A_c = A_1 * A_0^-c for c = { 1, ..., sqrt(N) }
			element_set(A_c, A[1]);
			for (DWORD c = 1; (c <= max) && (found_jw == 0); c++) {
				element_mul(A_c, A_c, A_inv);

				for (DWORD d = 0; d <= max; d++) {
					if (element_cmp(A_c, A_d[d]) == 0) {
						jw[0] = c + d * max;
						sig_status[remain_list[jw[0] - 1]] = 0;
						found_jw = 1;
						break;
					}
				}
			}

			// clear A_in, A_c, A_d[sqrt(N)+1]
			element_clear(A_inv);
			element_clear(A_c);
			for (i = 0; i <= max; i++) {
				element_clear(A_d[i]);
			}
			free(A_d);
			break;
		}
			// search for j_2 (Baby-step Giant-step)
		case 2: {
			DWORD max_1 = round(sqrt(2 * remain_list_size)), max_2 =
					remain_list_size;
			element_t A_inv, A_c, A_tmp, **A_d = (element_t**) malloc(
					(max_1 + 1) * sizeof(element_t*));

			// initialize A_d[sqrt(2*N)+1][N+1]
			for (DWORD d_1 = 0; d_1 <= max_1; d_1++) {
				A_d[d_1] = (element_t*) malloc((max_2 - 1) * sizeof(element_t));
				for (DWORD d_2 = 0; d_2 <= max_2 - 2; d_2++) {
					element_init(A_d[d_1][d_2], GT);
				}
			}
			// A_d[d_1][d_2] = A_1^{d_1 * sqrt(2*N)} * A_0^{-d_2*N}
			// for d_1 = { 0, ..., sqrt(2*N) }, d_2 = { 0, ..., N }
			for (DWORD d_1 = 0; d_1 <= max_1; d_1++) {
				for (DWORD d_2 = 0; d_2 <= max_2 - 2; d_2++) {
					if (d_2 == 0) {
						if (d_1 == 0) {
							element_set1(A_d[0][0]);
						} else if (d_1 == 1) {
							mpz_t tmp;
							mpz_init_set_ui(tmp, max_1);
							element_pow_mpz(A_d[1][0], A[1], tmp);
							mpz_clear(tmp);
						} else {
							element_mul(A_d[d_1][0], A_d[d_1 - 1][0],
									A_d[1][0]);
						}
					} else if ((d_2 == 1) && (d_1 == 0)) {
						mpz_t tmp;
						mpz_init_set_ui(tmp, max_2);
						element_pow_mpz(A_d[0][1], A[0], tmp);
						element_invert(A_d[0][1], A_d[0][1]);
						mpz_clear(tmp);
					} else {
						element_mul(A_d[d_1][d_2], A_d[d_1][d_2 - 1],
								A_d[0][1]);
					}
				}
			}

			// initialize A_inv, A_c, A_tmp
			element_init(A_inv, GT);
			element_init(A_c, GT);
			element_init(A_tmp, GT);
			// A_inv = A_1^-1
			element_invert(A_inv, A[1]);
			// A_c = A[2] * A_1^-c1 * A_0^c2
			// for c_1 = { 1, ..., sqrt(2*N) }, c_2 = { 1, ..., N }
			element_mul(A_tmp, A[2], A[0]);
			for (DWORD c_1 = 1; (c_1 <= max_1) && (found_jw == 0); c_1++) {
				for (DWORD c_2 = 1; (c_2 <= max_2) && (found_jw == 0); c_2++) {
					if (c_2 == 1) {
						element_mul(A_tmp, A_tmp, A_inv);
						element_set(A_c, A_tmp);
					} else {
						element_mul(A_c, A_c, A[0]);
					}

					for (DWORD d_1 = 0; (d_1 <= max_1) && (found_jw == 0);
							d_1++) {
						for (DWORD d_2 = 0; d_2 <= max_2 - 2; d_2++) {
							if (element_cmp(A_c, A_d[d_1][d_2]) == 0) {
								DWORD p_1 = c_1 + d_1 * max_1;
								DWORD p_2 = c_2 + d_2 * max_2;
								p_2 = sqrt(p_1 * p_1 - 4 * p_2);
								jw[0] = (p_1 - p_2) / 2;
								jw[1] = (p_1 + p_2) / 2;
								sig_status[remain_list[jw[0] - 1]] = 0;
								sig_status[remain_list[jw[1] - 1]] = 0;
								found_jw = 1;
								break;
							}
						}
					}
				}
			}

			// clear A_inv, A_c1, A_c2, A_d[sqrt(2*N)+1][N+1]
			element_clear(A_inv);
			element_clear(A_c);
			element_clear(A_tmp);
			for (DWORD d_1 = 0; d_1 <= max_1; d_1++) {
				for (DWORD d_2 = 0; d_2 <= max_2 - 2; d_2++) {
					element_clear(A_d[d_1][d_2]);
				}
				free(A_d[d_1]);
			}
			free(A_d);
			break;
		}
			// search for j_3 ... j_k (exhaustive search)
		default: {
			do {
				element_set1(A_product);
				element_set1(A_inv_product);
				// ...
				for (t = 1; t <= k; t++) {
					mpz_set_ui(f, get_elem_sym_poly(t, jw, k));
					element_pow_mpz(gt, A[k - t], f);
					if (((t - 1) % 2) == 1) {
						element_mul(A_inv_product, A_inv_product, gt);
					} else {
						element_mul(A_product, A_product, gt);
					}
				}
				if (!element_is1(A_inv_product)) {
					element_invert(A_inv_product, A_inv_product);
					element_mul(A_product, A_product, A_inv_product);
				}

				// check, if right combination of jw is found
				if (element_cmp(A[k], A_product) == 0) {
					// set status of invalid signatures
					for (i = 0; i < k; i++) {
						sig_status[remain_list[jw[i] - 1]] = 0;
					}
					found_jw = 1;
					k++;
					break;
				}
				// get next possible combination for jw
			} while (count_up(jw, k, remain_list_size));
			break;
		}
		}
	}

	mpz_clear(jk);
	mpz_clear(f);
	mpz_clear(p);
	element_clear(X_product);
	element_clear(Y_product);
	element_clear(Z_product);
	element_clear(gt);
	for (i = 1; i < k - 1; i++) {
		element_clear(A[i]);
	}
	free(A);
	free(jw);

	return found_jw;
}

// BATCH VERIFY (msg_len in bytes)
void xsgs_batch_verify(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	field_ptr GT = gpk->pairing->GT;
	element_t X_product, Y_product, Z_product;

	if (!list_size) {
		return;
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	// batch test
	if (list_size == 1) {
		element_t c;
		element_init(c, Fp);

		sig_status[0] = !xsgs_batch_verify_internal1(gpk, sig_list[0], c);
		xsgs_batch_verify_internal2(gpk, sig_list[0], c, X_product, Y_product,
				Z_product);
		sig_status[0] = !xsgs_batch_verify_internal3b(gpk, X_product, Y_product,
				Z_product);
		element_clear(c);
	} else {
		element_t *c, *X, *Y, *Z;
		element_t A, U, V;
		DWORD i, idx, remain_list_size;
		DWORD* remain_list;

		c = (element_t*) malloc(list_size * sizeof(element_t));
		X = (element_t*) malloc(list_size * sizeof(element_t));
		Y = (element_t*) malloc(list_size * sizeof(element_t));
		Z = (element_t*) malloc(list_size * sizeof(element_t));

		// non pairing checks
		for (i = 0; i < list_size; i++) {
			element_init(c[i], Fp);
			element_init(X[i], G1);
			element_init(Y[i], G1);
			element_init(Z[i], GT);
			sig_status[i] = !xsgs_batch_verify_internal1(gpk, sig_list[i],
					c[i]);
			//sig_status[i] = 1; // for testing
		}

		// find remaining possible valid signatures
		for (i = 0, remain_list_size = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list_size++;
			}
		}

		remain_list = (DWORD*) malloc(remain_list_size * sizeof(DWORD));

		// initialize remain_list
		for (i = 0, idx = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list[idx++] = i;
			}
		}

		element_set1(X_product);
		element_set1(Y_product);
		element_set1(Z_product);

		// calculate products
		for (i = 0; i < remain_list_size; i++) {
			idx = remain_list[i];
			xsgs_batch_verify_internal2(gpk, sig_list[idx], c[idx], X[idx],
					Y[idx], Z[idx]);
			element_mul(X_product, X_product, X[idx]);
			element_mul(Y_product, Y_product, Y[idx]);
			element_mul(Z_product, Z_product, Z[idx]);
		}

		element_init(U, G2);
		element_init(V, G2);
		element_init(A, GT);

		// batch test
		if (!xsgs_batch_verify_internal3a(gpk, X_product, Y_product, Z_product,
				U, V, A)) {
			// batch test unsuccessful -> find faulty signatures with the discrete logarithm method (Kitae Kim et al.)
			if (!xsgs_batch_verify_internal4b(gpk, sig_status, remain_list,
					remain_list_size, X, Y, Z, U, V, A, 2)) {
				// invalid signature count is greater than 2
				if (remain_list_size > 3) {
					// find more than 2 faulty signatures  with Quick Binary Search (Law et al.)
					xsgs_batch_verify_internal4a(gpk, sig_status, remain_list,
							remain_list_size, X, Y, Z, U, V, A);
				} else {
					// found no individual faulty signatures -> set all remaining signatures invalid
					for (i = 0; i < remain_list_size; i++) {
						sig_status[remain_list[i]] = 0;
					}
				}
			}
		}

		element_clear(X_product);
		element_clear(Y_product);
		element_clear(Z_product);
		element_clear(U);
		element_clear(V);
		element_clear(A);

		free(remain_list);

		// clear elements
		for (i = 0; i < list_size; i++) {
			element_clear(c[i]);
			element_clear(X[i]);
			element_clear(Y[i]);
			element_clear(Z[i]);
		}
		free(c);
		free(X);
		free(Y);
		free(Z);
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	return;
}
//find invalid signatures with quick binary search
void xsgs_batch_verify2(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	field_ptr GT = gpk->pairing->GT;
	element_t X_product, Y_product, Z_product;

	if (!list_size) {
		return;
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	// batch test
	if (list_size == 1) {
		element_t c;
		element_init(c, Fp);

		sig_status[0] = !xsgs_batch_verify_internal1(gpk, sig_list[0], c);
		xsgs_batch_verify_internal2(gpk, sig_list[0], c, X_product, Y_product,
				Z_product);
		sig_status[0] = !xsgs_batch_verify_internal3b(gpk, X_product, Y_product,
				Z_product);
		element_clear(c);
	} else {
		element_t *c, *X, *Y, *Z;
		element_t A, U, V;
		DWORD i, idx, remain_list_size;
		DWORD* remain_list;

		c = (element_t*) malloc(list_size * sizeof(element_t));
		X = (element_t*) malloc(list_size * sizeof(element_t));
		Y = (element_t*) malloc(list_size * sizeof(element_t));
		Z = (element_t*) malloc(list_size * sizeof(element_t));

		// non pairing checks
		for (i = 0; i < list_size; i++) {
			element_init(c[i], Fp);
			element_init(X[i], G1);
			element_init(Y[i], G1);
			element_init(Z[i], GT);
			sig_status[i] = !xsgs_batch_verify_internal1(gpk, sig_list[i],
					c[i]);
			//sig_status[i] = 1; // for testing
		}

		// find remaining possible valid signatures
		for (i = 0, remain_list_size = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list_size++;
			}
		}

		remain_list = (DWORD*) malloc(remain_list_size * sizeof(DWORD));

		// initialize remain_list
		for (i = 0, idx = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list[idx++] = i;
			}
		}

		element_set1(X_product);
		element_set1(Y_product);
		element_set1(Z_product);

		// calculate products
		for (i = 0; i < remain_list_size; i++) {
			idx = remain_list[i];
			xsgs_batch_verify_internal2(gpk, sig_list[idx], c[idx], X[idx],
					Y[idx], Z[idx]);
			element_mul(X_product, X_product, X[idx]);
			element_mul(Y_product, Y_product, Y[idx]);
			element_mul(Z_product, Z_product, Z[idx]);
		}

		element_init(U, G2);
		element_init(V, G2);
		element_init(A, GT);

		// batch test
		if (!xsgs_batch_verify_internal3a(gpk, X_product, Y_product, Z_product,
				U, V, A)) {
			// batch test unsuccessful -> find faulty signatures with Quick Binary Search
			xsgs_batch_verify_internal4a(gpk, sig_status, remain_list,
					remain_list_size, X, Y, Z, U, V, A);
		}

		element_clear(X_product);
		element_clear(Y_product);
		element_clear(Z_product);
		element_clear(U);
		element_clear(V);
		element_clear(A);

		free(remain_list);

		// clear elements
		for (i = 0; i < list_size; i++) {
			element_clear(c[i]);
			element_clear(X[i]);
			element_clear(Y[i]);
			element_clear(Z[i]);
		}
		free(c);
		free(X);
		free(Y);
		free(Z);
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	return;
}
// find invalid signatures with exponentiation method
void xsgs_batch_verify3(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	field_ptr GT = gpk->pairing->GT;
	element_t X_product, Y_product, Z_product;

	if (!list_size) {
		return;
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	// batch test
	if (list_size == 1) {
		element_t c;
		element_init(c, Fp);

		sig_status[0] = !xsgs_batch_verify_internal1(gpk, sig_list[0], c);
		xsgs_batch_verify_internal2(gpk, sig_list[0], c, X_product, Y_product,
				Z_product);
		sig_status[0] = !xsgs_batch_verify_internal3b(gpk, X_product, Y_product,
				Z_product);
		element_clear(c);
	} else {
		element_t *c, *X, *Y, *Z;
		element_t A, U, V;
		DWORD i, idx, remain_list_size;
		DWORD* remain_list;

		c = (element_t*) malloc(list_size * sizeof(element_t));
		X = (element_t*) malloc(list_size * sizeof(element_t));
		Y = (element_t*) malloc(list_size * sizeof(element_t));
		Z = (element_t*) malloc(list_size * sizeof(element_t));

		// non pairing checks
		for (i = 0; i < list_size; i++) {
			element_init(c[i], Fp);
			element_init(X[i], G1);
			element_init(Y[i], G1);
			element_init(Z[i], GT);
			sig_status[i] = !xsgs_batch_verify_internal1(gpk, sig_list[i],
					c[i]);
			//sig_status[i] = 1; // for testing
		}

		// find remaining possible valid signatures
		for (i = 0, remain_list_size = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list_size++;
			}
		}

		remain_list = (DWORD*) malloc(remain_list_size * sizeof(DWORD));

		// initialize remain_list
		for (i = 0, idx = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list[idx++] = i;
			}
		}

		element_set1(X_product);
		element_set1(Y_product);
		element_set1(Z_product);

		// calculate products
		for (i = 0; i < remain_list_size; i++) {
			idx = remain_list[i];
			xsgs_batch_verify_internal2(gpk, sig_list[idx], c[idx], X[idx],
					Y[idx], Z[idx]);
			element_mul(X_product, X_product, X[idx]);
			element_mul(Y_product, Y_product, Y[idx]);
			element_mul(Z_product, Z_product, Z[idx]);
		}

		element_init(U, G2);
		element_init(V, G2);
		element_init(A, GT);

		// batch test
		if (!xsgs_batch_verify_internal3a(gpk, X_product, Y_product, Z_product,
				U, V, A)) {
			// batch test unsuccessful -> find faulty signatures with exponentiation method
			if (!xsgs_batch_verify_internal4b(gpk, sig_status, remain_list,
					remain_list_size, X, Y, Z, U, V, A, remain_list_size - 1)) {
				// found no individual faulty signatures -> set all remaining signatures invalid
				for (i = 0; i < remain_list_size; i++) {
					sig_status[remain_list[i]] = 0;
				}
			}
		}

		element_clear(X_product);
		element_clear(Y_product);
		element_clear(Z_product);
		element_clear(U);
		element_clear(V);
		element_clear(A);

		free(remain_list);

		// clear elements
		for (i = 0; i < list_size; i++) {
			element_clear(c[i]);
			element_clear(X[i]);
			element_clear(Y[i]);
			element_clear(Z[i]);
		}
		free(c);
		free(X);
		free(Y);
		free(Z);
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	return;
}

void xsgs_batch_verify_cache(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	field_ptr GT = gpk->pairing->GT;
	element_t X_product, Y_product, Z_product;

	if (!list_size) {
		return;
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	// batch test
	if (list_size == 1) {
		element_t c;
		element_init(c, Fp);

		sig_status[0] = !xsgs_batch_verify_internal1_cache(gpk, cache,
				sig_list[0], c);
		xsgs_batch_verify_internal2_cache(gpk, cache, sig_list[0], c, X_product,
				Y_product, Z_product);
		sig_status[0] = !xsgs_batch_verify_internal3b(gpk, X_product, Y_product,
				Z_product);
		element_clear(c);
	} else {
		element_t *c, *X, *Y, *Z;
		element_t A, U, V;
		DWORD i, idx, remain_list_size;
		DWORD* remain_list;

		c = (element_t*) malloc(list_size * sizeof(element_t));
		X = (element_t*) malloc(list_size * sizeof(element_t));
		Y = (element_t*) malloc(list_size * sizeof(element_t));
		Z = (element_t*) malloc(list_size * sizeof(element_t));

		// non pairing checks
		for (i = 0; i < list_size; i++) {
			element_init(c[i], Fp);
			element_init(X[i], G1);
			element_init(Y[i], G1);
			element_init(Z[i], GT);
			sig_status[i] = !xsgs_batch_verify_internal1_cache(gpk, cache,
					sig_list[i], c[i]);
			//sig_status[i] = 1; // for testing
		}

		// find remaining possible valid signatures
		for (i = 0, remain_list_size = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list_size++;
			}
		}

		remain_list = (DWORD*) malloc(remain_list_size * sizeof(DWORD));

		// initialize remain_list
		for (i = 0, idx = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list[idx++] = i;
			}
		}

		element_set1(X_product);
		element_set1(Y_product);
		element_set1(Z_product);

		// calculate products
		for (i = 0; i < remain_list_size; i++) {
			idx = remain_list[i];
			xsgs_batch_verify_internal2_cache(gpk, cache, sig_list[idx], c[idx],
					X[idx], Y[idx], Z[idx]);
			element_mul(X_product, X_product, X[idx]);
			element_mul(Y_product, Y_product, Y[idx]);
			element_mul(Z_product, Z_product, Z[idx]);
		}

		element_init(U, G2);
		element_init(V, G2);
		element_init(A, GT);

		// batch test
		if (!xsgs_batch_verify_internal3a(gpk, X_product, Y_product, Z_product,
				U, V, A)) {
			// batch test unsuccessful -> find faulty signatures with the discrete logarithm method (Kitae Kim et al.)
			if (!xsgs_batch_verify_internal4b(gpk, sig_status, remain_list,
					remain_list_size, X, Y, Z, U, V, A, 2)) {
				// invalid signature count is greater than 2
				if (remain_list_size > 3) {
					// find more than 2 faulty signatures  with Quick Binary Search (Law et al.)
					xsgs_batch_verify_internal4a(gpk, sig_status, remain_list,
							remain_list_size, X, Y, Z, U, V, A);
				} else {
					// found no individual faulty signatures -> set all remaining signatures invalid
					for (i = 0; i < remain_list_size; i++) {
						sig_status[remain_list[i]] = 0;
					}
				}
			}
		}

		element_clear(X_product);
		element_clear(Y_product);
		element_clear(Z_product);
		element_clear(U);
		element_clear(V);
		element_clear(A);

		free(remain_list);

		// clear elements
		for (i = 0; i < list_size; i++) {
			element_clear(c[i]);
			element_clear(X[i]);
			element_clear(Y[i]);
			element_clear(Z[i]);
		}
		free(c);
		free(X);
		free(Y);
		free(Z);
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	return;
}

void xsgs_batch_verify_cache2(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	field_ptr GT = gpk->pairing->GT;
	element_t X_product, Y_product, Z_product;

	if (!list_size) {
		return;
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	// batch test
	if (list_size == 1) {
		element_t c;
		element_init(c, Fp);

		sig_status[0] = !xsgs_batch_verify_internal1_cache(gpk, cache,
				sig_list[0], c);
		xsgs_batch_verify_internal2_cache(gpk, cache, sig_list[0], c, X_product,
				Y_product, Z_product);
		sig_status[0] = !xsgs_batch_verify_internal3b(gpk, X_product, Y_product,
				Z_product);

		element_clear(c);
	} else {
		element_t *c, *X, *Y, *Z;
		element_t A, U, V;
		DWORD i, idx, remain_list_size;
		DWORD* remain_list;

		c = (element_t*) malloc(list_size * sizeof(element_t));
		X = (element_t*) malloc(list_size * sizeof(element_t));
		Y = (element_t*) malloc(list_size * sizeof(element_t));
		Z = (element_t*) malloc(list_size * sizeof(element_t));

		// non pairing checks
		for (i = 0; i < list_size; i++) {
			element_init(c[i], Fp);
			element_init(X[i], G1);
			element_init(Y[i], G1);
			element_init(Z[i], GT);
			sig_status[i] = !xsgs_batch_verify_internal1_cache(gpk, cache,
					sig_list[i], c[i]);
			//sig_status[i] = 1; // for testing
		}

		// find remaining possible valid signatures
		for (i = 0, remain_list_size = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list_size++;
			}
		}

		remain_list = (DWORD*) malloc(remain_list_size * sizeof(DWORD));

		// initialize remain_list
		for (i = 0, idx = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list[idx++] = i;
			}
		}

		element_set1(X_product);
		element_set1(Y_product);
		element_set1(Z_product);

		// calculate products
		for (i = 0; i < remain_list_size; i++) {
			idx = remain_list[i];
			xsgs_batch_verify_internal2_cache(gpk, cache, sig_list[idx], c[idx],
					X[idx], Y[idx], Z[idx]);
			element_mul(X_product, X_product, X[idx]);
			element_mul(Y_product, Y_product, Y[idx]);
			element_mul(Z_product, Z_product, Z[idx]);
		}

		element_init(U, G2);
		element_init(V, G2);
		element_init(A, GT);

		// batch test
		if (!xsgs_batch_verify_internal3a(gpk, X_product, Y_product, Z_product,
				U, V, A)) {
			// batch test unsuccessful -> find faulty signatures (Quick Binary Search)
			xsgs_batch_verify_internal4a(gpk, sig_status, remain_list,
					remain_list_size, X, Y, Z, U, V, A);
		}

		element_clear(X_product);
		element_clear(Y_product);
		element_clear(Z_product);
		element_clear(U);
		element_clear(V);
		element_clear(A);

		free(remain_list);

		// clear elements
		for (i = 0; i < list_size; i++) {
			element_clear(c[i]);
			element_clear(X[i]);
			element_clear(Y[i]);
			element_clear(Z[i]);
		}
		free(c);
		free(X);
		free(Y);
		free(Z);
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	return;
}

void xsgs_batch_verify_cache3(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	field_ptr GT = gpk->pairing->GT;
	element_t X_product, Y_product, Z_product;

	if (!list_size) {
		return;
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	// batch test
	if (list_size == 1) {
		element_t c;
		element_init(c, Fp);

		sig_status[0] = !xsgs_batch_verify_internal1_cache(gpk, cache,
				sig_list[0], c);
		xsgs_batch_verify_internal2_cache(gpk, cache, sig_list[0], c, X_product,
				Y_product, Z_product);
		sig_status[0] = !xsgs_batch_verify_internal3b(gpk, X_product, Y_product,
				Z_product);

		element_clear(c);
	} else {
		element_t *c, *X, *Y, *Z;
		element_t A, U, V;
		DWORD i, idx, remain_list_size;
		DWORD* remain_list;

		c = (element_t*) malloc(list_size * sizeof(element_t));
		X = (element_t*) malloc(list_size * sizeof(element_t));
		Y = (element_t*) malloc(list_size * sizeof(element_t));
		Z = (element_t*) malloc(list_size * sizeof(element_t));

		// non pairing checks
		for (i = 0; i < list_size; i++) {
			element_init(c[i], Fp);
			element_init(X[i], G1);
			element_init(Y[i], G1);
			element_init(Z[i], GT);
			sig_status[i] = !xsgs_batch_verify_internal1_cache(gpk, cache,
					sig_list[i], c[i]);
			//sig_status[i] = 1; // for testing
		}

		// find remaining possible valid signatures
		for (i = 0, remain_list_size = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list_size++;
			}
		}

		remain_list = (DWORD*) malloc(remain_list_size * sizeof(DWORD));

		// initialize remain_list
		for (i = 0, idx = 0; i < list_size; i++) {
			if (sig_status[i]) {
				remain_list[idx++] = i;
			}
		}

		element_set1(X_product);
		element_set1(Y_product);
		element_set1(Z_product);

		// calculate products
		for (i = 0; i < remain_list_size; i++) {
			idx = remain_list[i];
			xsgs_batch_verify_internal2_cache(gpk, cache, sig_list[idx], c[idx],
					X[idx], Y[idx], Z[idx]);
			element_mul(X_product, X_product, X[idx]);
			element_mul(Y_product, Y_product, Y[idx]);
			element_mul(Z_product, Z_product, Z[idx]);
		}

		element_init(U, G2);
		element_init(V, G2);
		element_init(A, GT);

		// batch test
		if (!xsgs_batch_verify_internal3a(gpk, X_product, Y_product, Z_product,
				U, V, A)) {
			// batch test unsuccessful -> find faulty signatures (exponentiation method)
			if (!xsgs_batch_verify_internal4b(gpk, sig_status, remain_list,
					remain_list_size, X, Y, Z, U, V, A, remain_list_size - 1)) {
				// found no individual faulty signatures -> set all signatures invalid
				for (i = 0; i < list_size; i++) {
					sig_status[i] = 0;
				}
			}
		}

		element_clear(X_product);
		element_clear(Y_product);
		element_clear(Z_product);
		element_clear(U);
		element_clear(V);
		element_clear(A);

		free(remain_list);

		// clear elements
		for (i = 0; i < list_size; i++) {
			element_clear(c[i]);
			element_clear(X[i]);
			element_clear(Y[i]);
			element_clear(Z[i]);
		}
		free(c);
		free(X);
		free(Y);
		free(Z);
	}

	element_init(X_product, G1);
	element_init(Y_product, G1);
	element_init(Z_product, GT);

	return;
}
