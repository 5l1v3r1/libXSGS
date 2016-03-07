#include <string.h>
#include "xsgs.h"

// USER JOIN PHASE 1 - user key generation (Join)
void xsgs_user_join_phase1(XSGS_PUBLIC_KEY* gpk, XSGS_USER_KEY* uk,
		XSGS_PAILLIER_PUBKEY* ppk, XSGS_JOIN_PHASE1* jpd1) {
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	gmp_randstate_t rnd_state;
	mpz_t y, r, R1, h;
	element_t R2;

	// 1.choose y e Zp at random and
	element_init(uk->y, Fp);
	element_random(uk->y);
	// compute C <- H^y
	element_init_G1(jpd1->C, pairing);
	element_pow_naf(jpd1->C, gpk->H, uk->y);

	// 2. U = (c=ext-commit(y), NIZKPEqDL(c, C, H))
	// c = ext-commit(y) = g^y mod n^2
	mpz_init(y);
	mpz_init(jpd1->U.c);

	element_to_mpz(y, uk->y);
	mpz_powm(jpd1->U.c, ppk->g, y, ppk->n_squared);

	// zero-knowledge proof of c, C and H
	init_rand(rnd_state, PAILLIER_MODULO_BITS / 8 + 1);
	mpz_init(r);
	mpz_urandomb(r, rnd_state, PAILLIER_MODULO_BITS);
	gmp_randclear(rnd_state);

	// R1 = g^r mod n^2
	mpz_init(R1);
	mpz_powm(R1, ppk->g, r, ppk->n_squared);

	// R2 = H^r
	element_init_G1(R2, pairing);
	element_pow_naf_mpz(R2, gpk->H, r);

	// h = H(g, n, c, C, H, R1, R2)
	DWORD data_len = mpz_length_in_bytes(ppk->g)
			+ mpz_length_in_bytes(ppk->n_squared)
			+
			//mpz_length_in_bytes(ppk->n) +
			mpz_length_in_bytes(jpd1->U.c) + element_length_in_bytes(jpd1->C)
			+ element_length_in_bytes(gpk->H) + mpz_length_in_bytes(R1)
			+ element_length_in_bytes(R2);

	BYTE* data_buf = (BYTE*) malloc(data_len);

	data_buf += mpz_to_bytes(data_buf, ppk->g);
	data_buf += mpz_to_bytes(data_buf, ppk->n_squared);
	//data_buf += mpz_to_bytes(data_buf, ppk->n);
	data_buf += mpz_to_bytes(data_buf, jpd1->U.c);
	data_buf += element_to_bytes(data_buf, jpd1->C);
	data_buf += element_to_bytes(data_buf, gpk->H);
	data_buf += mpz_to_bytes(data_buf, R1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf -= data_len;

	jpd1->U.hash = (BYTE*) malloc(JOIN_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, jpd1->U.hash, JOIN_HASH_BITS);

	free(data_buf);
	mpz_clear(R1);
	element_clear(R2);

	// s = r - h * y
	mpz_init(h);
	mpz_init(jpd1->U.s);
	mpz_from_hash(h, jpd1->U.hash, JOIN_HASH_BITS / 8);
	mpz_mul(jpd1->U.s, h, y);
	mpz_sub(jpd1->U.s, r, jpd1->U.s);

	mpz_clear(r);
	mpz_clear(y);
	mpz_clear(h);

	// return ( paillier = (pub, prv), C, U = (c, h, s) )
	return;
}

// USER JOIN PHASE 2 - user key generation (Join)
int xsgs_user_join_phase2(XSGS_PUBLIC_KEY* gpk, XSGS_USER_DB_ENTRY* udbe,
		XSGS_ISSUER_KEY* ik, XSGS_PAILLIER_PUBKEY* ppk, XSGS_JOIN_PHASE1* jpd1,
		XSGS_JOIN_PHASE2* jpd2) {
	int ret;
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	mpz_t r1, h; //, t;
	element_t R1, R2, g1, B, D, zp, gt, hp;

	mpz_init(h);
	mpz_from_hash(h, jpd1->U.hash, JOIN_HASH_BITS / 8);

	// 1. verify C e G1 and check U
	// R1 = g^s * c^h mod n^2
	mpz_init(r1);
	mpz_powm2(r1, ppk->g, jpd1->U.s, jpd1->U.c, h, ppk->n_squared);

	// R2 = H^s * C^h
	element_init_G1(R2, pairing);
	element_pow_naf2_mpz(R2, gpk->H, jpd1->U.s, jpd1->C, h);

	mpz_clear(h);

	// h = H(g, n, c, C, H, R1, R2)
	DWORD data_len = mpz_length_in_bytes(ppk->g)
			+ mpz_length_in_bytes(ppk->n_squared)
			+ mpz_length_in_bytes(jpd1->U.c) + element_length_in_bytes(jpd1->C)
			+ element_length_in_bytes(gpk->H) + mpz_length_in_bytes(r1)
			+ element_length_in_bytes(R2);

	BYTE* data_buf = (BYTE*) malloc(data_len);

	data_buf += mpz_to_bytes(data_buf, ppk->g);
	data_buf += mpz_to_bytes(data_buf, ppk->n_squared);
	data_buf += mpz_to_bytes(data_buf, jpd1->U.c);
	data_buf += element_to_bytes(data_buf, jpd1->C);
	data_buf += element_to_bytes(data_buf, gpk->H);
	data_buf += mpz_to_bytes(data_buf, r1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf -= data_len;

	BYTE* hash = (BYTE*) malloc(JOIN_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, hash, JOIN_HASH_BITS);

	free(data_buf);
	mpz_clear(r1);
	element_clear(R2);

	// compare hashes
	ret = memcmp(jpd1->U.hash, hash, JOIN_HASH_BITS / 8);
	free(hash);
	if (!ret) {
		element_t r;

		// initialization
		element_init(udbe->UCert.x, Fp);
		element_init_G1(udbe->UCert.A, pairing);
		element_init_G1(udbe->C, pairing);
		element_init_G1(jpd2->A, pairing);
		element_init_G1(g1, pairing);
		element_init_GT(B, pairing);
		element_init_GT(gt, pairing);
		element_init(zp, Fp);

		// save jpd1->C to ubde->C
		element_set(udbe->C, jpd1->C);

		// 2. x eR Zp and
		element_random(udbe->UCert.x);

		// A <- (G1 * C)^{1/(gamma + x)}
		element_add(zp, ik->gamma, udbe->UCert.x);
		element_invert(zp, zp);
		element_mul(jpd2->A, gpk->G1, jpd1->C);
		element_pow_naf(jpd2->A, jpd2->A, zp);
		element_set(udbe->UCert.A, jpd2->A);

		// 3. B <- e(G1 * C, G2) / e(A, W) = e(G1 * C, G2) * e(A^-1, W)
		element_mul(g1, gpk->G1, jpd1->C);
		element_pairing(B, g1, gpk->G2);
		element_invert(g1, jpd2->A);
		element_pairing(gt, g1, gpk->W);
		element_mul(B, B, gt);

		element_clear(g1);
		element_clear(zp);
		element_clear(gt);

		// 4. D <- e(A, G2)
		element_init_GT(D, pairing);
		element_pairing(D, jpd2->A, gpk->G2);

		// 5. V <- NIZKPoKDL(B, D)
		// T1 = B^gamma
		element_init_GT(jpd2->V.T1, pairing);
		element_pow_zn(jpd2->V.T1, B, ik->gamma);

		// T2 = D^gamma
		element_init_GT(jpd2->V.T2, pairing);
		element_pow_zn(jpd2->V.T2, D, ik->gamma);

		// r eR Zp
		element_init(r, Fp);
		element_random(r);

		// R1 = B^r
		element_init_GT(R1, pairing);
		element_pow_zn(R1, B, r);

		// R2 = D^r
		element_init_GT(R2, pairing);
		element_pow_zn(R2, D, r);

		// h = H(B, D, T1, T2, R1, R2)
		data_len = element_length_in_bytes(B) + element_length_in_bytes(D)
				+ element_length_in_bytes(jpd2->V.T1)
				+ element_length_in_bytes(jpd2->V.T2)
				+ element_length_in_bytes(R1) + element_length_in_bytes(R2);

		data_buf = (BYTE*) malloc(data_len);
		data_buf += element_to_bytes(data_buf, B);
		data_buf += element_to_bytes(data_buf, D);
		data_buf += element_to_bytes(data_buf, jpd2->V.T1);
		data_buf += element_to_bytes(data_buf, jpd2->V.T2);
		data_buf += element_to_bytes(data_buf, R1);
		data_buf += element_to_bytes(data_buf, R2);
		data_buf -= data_len;

		jpd2->V.hash = (BYTE*) malloc(JOIN_HASH_BITS / 8);
		xsgs_hash(data_buf, data_len * 8, jpd2->V.hash, JOIN_HASH_BITS);

		element_init(hp, Fp);
		element_from_hash(hp, jpd1->U.hash, JOIN_HASH_BITS / 8);

		free(data_buf);
		element_clear(B);
		element_clear(D);
		element_clear(R1);
		element_clear(R2);

		// s = r - hash * gamma mod p
		element_init(jpd2->V.s, Fp);
		element_mul(jpd2->V.s, hp, ik->gamma);
		element_add(jpd2->V.s, r, jpd2->V.s);

		element_clear(r);
		element_clear(hp);
	}

	// return (A, V = (T1, T2, hash, s) )
	return ret;
}

// USER JOIN PHASE 3 - user key generation (Join)
int xsgs_user_join_phase3(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert,
		XSGS_JOIN_PHASE1* jpd1, XSGS_JOIN_PHASE2* jpd2, XSGS_JOIN_PHASE3* jpd3,
		char* usk_pem_filename) {
	int ret;
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	element_t B, D, R1, R2, h, g1, gt;

	// B = e(G1 * C, G2) / e(A, W) = e(G1 * C, G2) * e(A^-1, W)
	element_init_GT(B, pairing);
	element_init_G1(g1, pairing);
	element_init_GT(gt, pairing);

	element_mul(g1, gpk->G1, jpd1->C);
	element_pairing(B, g1, gpk->G2);
	element_invert(g1, jpd2->A);
	element_pairing(gt, g1, gpk->W);
	element_mul(B, B, gt);

	// D = e(A, G2)
	element_init_GT(D, pairing);
	element_pairing(D, jpd2->A, gpk->G2);

	// verifies A e Group1, Checks V
	element_init(h, Fp);
	element_from_hash(h, jpd1->U.hash, JOIN_HASH_BITS / 8);
	element_neg(h, h);

	// R1 = B^s * T1^h
	element_init_GT(R1, pairing);
	element_pow_naf2(R1, B, jpd2->V.s, jpd2->V.T1, h);

	// R2 = D^s * T2^h
	element_init_GT(R2, pairing);
	element_pow_naf2(R2, D, jpd2->V.s, jpd2->V.T2, h);

	// clear tmp
	element_clear(g1);
	element_clear(gt);
	element_clear(h);

	// h = H(B, D, T1, T2, R1, R2)
	DWORD data_len = element_length_in_bytes(B) + element_length_in_bytes(D)
			+ element_length_in_bytes(jpd2->V.T1)
			+ element_length_in_bytes(jpd2->V.T2) + element_length_in_bytes(R1)
			+ element_length_in_bytes(R2);

	BYTE* data_buf = (BYTE*) malloc(data_len);
	data_buf += element_to_bytes(data_buf, B);
	data_buf += element_to_bytes(data_buf, D);
	data_buf += element_to_bytes(data_buf, jpd2->V.T1);
	data_buf += element_to_bytes(data_buf, jpd2->V.T2);
	data_buf += element_to_bytes(data_buf, R1);
	data_buf += element_to_bytes(data_buf, R2);
	data_buf -= data_len;

	BYTE* hash = (BYTE*) malloc(JOIN_HASH_BITS / 8);
	xsgs_hash(data_buf, data_len * 8, hash, JOIN_HASH_BITS);

	free(data_buf);
	element_clear(B);
	element_clear(D);
	element_clear(R1);
	element_clear(R2);

	// compare hashes
	ret = memcmp(jpd2->V.hash, hash, JOIN_HASH_BITS / 8);
	free(hash);
	if (!ret) {
		element_init_G1(ucert->A, pairing);
		element_set(ucert->A, jpd2->A);

		// S = sign(A)
		DWORD msg_len = element_length_in_bytes(ucert->A);
		BYTE* msg = (BYTE*) malloc(msg_len);
		element_to_bytes(msg, ucert->A);
		ret = xsgs_rsa_sign(usk_pem_filename, msg, msg_len, &(jpd3->S.sig), &(jpd3->S.len));
		free(msg);
	}

	// return ( S = (rsa signature length, rsa signature) )
	return ret;
}

// USER JOIN PHASE 4 - user key generation (Join)
int xsgs_user_join_phase4(XSGS_PUBLIC_KEY* gpk, XSGS_USER_DB_ENTRY* udbe,
		XSGS_JOIN_PHASE3* jpd3, XSGS_JOIN_PHASE4* jpd4, char* upk_pem_filename) {
	int ret;
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;

	DWORD msg_len = element_length_in_bytes(udbe->UCert.A);
	BYTE* msg = (BYTE*) malloc(msg_len);
	element_to_bytes(msg, udbe->UCert.A);

	/* TODO Verify_PK_CA(cert_user) */

	ret = xsgs_rsa_verify(upk_pem_filename, msg, msg_len, jpd3->S.sig,
			jpd3->S.len);
	free(msg);

	udbe->S.len = jpd3->S.len;
	udbe->S.sig = (BYTE*) malloc(udbe->S.len);
	memcpy(udbe->S.sig, jpd3->S.sig, udbe->S.len);

	element_init(jpd4->x, Fp);
	element_set(jpd4->x, udbe->UCert.x);

	return ret;
}

// USER JOIN PHASE 5 - user key generation (Join)
int xsgs_user_join_phase5(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert,
		XSGS_USER_KEY* uk, XSGS_JOIN_PHASE4* jpd4) {
	int ret;
	pairing_ptr pairing = gpk->pairing;
	field_ptr Fp = pairing->Zr;
	element_t gt1, gt2, y_neg, g1;

	element_init(ucert->x, Fp);
	element_set(ucert->x, jpd4->x);

	// check A^(x + gamma) = G1 * H^y
	// i.e.: e(A, G2)^x * e(A, W) * e(H, G2)^-y == e(G1, G2)
	element_init(y_neg, Fp);
	element_init_G1(g1, pairing);
	element_init_GT(gt1, pairing);
	element_init_GT(gt2, pairing);

	// gt1 = e(A, G2)^x * e(A, W) * e(H, G2)^-y
	//     = e(A^x * H^-y, G2) * e(A, W)
	element_neg(y_neg, uk->y);
	element_pow_naf2(g1, ucert->A, ucert->x, gpk->H, y_neg);
	element_pairing(gt1, g1, gpk->G2);
	element_pairing(gt2, ucert->A, gpk->W);
	element_mul(gt1, gt1, gt2);

	// gt2 = e(G1, G2)
	element_pairing(gt2, gpk->G1, gpk->G2);

	// check gt1 == gt2
	ret = element_cmp(gt1, gt2);

	element_clear(g1);
	element_clear(y_neg);
	element_clear(gt1);
	element_clear(gt2);

	return ret;
}

// XSGS USER JOIN - complete offline user join algorithm
int xsgs_user_join_offline(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik,
		XSGS_USER_CERT** ucert, XSGS_USER_KEY** uk, XSGS_USER_DB_ENTRY** udbe,
		char* usk_pem_filename) {
	element_t z, g11, g12;
	int ret = 0;

	*ucert = (XSGS_USER_CERT*) malloc(sizeof(XSGS_USER_CERT));
	*uk = (XSGS_USER_KEY*) malloc(sizeof(XSGS_USER_KEY));
	*udbe = (XSGS_USER_DB_ENTRY*) malloc(sizeof(XSGS_USER_DB_ENTRY));

	element_init(z, gpk->pairing->Zr);
	element_init(g11, gpk->pairing->G1);
	element_init(g12, gpk->pairing->G1);

	// 1. choose x, y e Zp at random
	element_init((*ucert)->x, gpk->pairing->Zr);
	element_init((*udbe)->UCert.x, gpk->pairing->Zr);
	element_init((*uk)->y, gpk->pairing->Zr);

	element_random((*ucert)->x);
	element_set((*udbe)->UCert.x, (*ucert)->x);

	element_random((*uk)->y);

	// 2. C <- H^y
	element_init((*udbe)->C, gpk->pairing->G1);
	element_pow_naf((*udbe)->C, gpk->H, (*uk)->y);

	// 3. A <- (G1 * C)^{1/(gamma + x)}
	element_init((*ucert)->A, gpk->pairing->G1);
	element_init((*udbe)->UCert.A, gpk->pairing->G1);

	element_add(z, ik->gamma, (*ucert)->x);
	element_invert(z, z);
	element_mul((*ucert)->A, gpk->G1, (*udbe)->C);
	element_pow_naf((*ucert)->A, (*ucert)->A, z);
	element_set((*udbe)->UCert.A, (*ucert)->A);

	// 4. S <- sign(A)
	DWORD msg_len = element_length_in_bytes((*ucert)->A);
	BYTE* msg = (BYTE*) malloc(msg_len);
	element_to_bytes(msg, (*ucert)->A);
	ret = xsgs_rsa_sign(usk_pem_filename, msg, msg_len, &((*udbe)->S.sig),
			&((*udbe)->S.len));
	free(msg);

	if (!ret) {
		// 5. check A^(x + gamma) = G1 * H^y
		element_add(z, ik->gamma, (*ucert)->x);
		element_pow_naf(g11, (*ucert)->A, z);

		element_pow_naf(g12, gpk->H, (*uk)->y);
		element_mul(g12, g12, gpk->G1);
		ret = element_cmp(g11, g12);
	}

	element_clear(z);
	element_clear(g11);
	element_clear(g12);

	return ret;
}
