#include "xsgs.h"
#include <string.h>

// update group public key with revoked user data
void xsgs_update_gpk(XSGS_PUBLIC_KEY* gpk, XSGS_REVOKE_PHASE1* rpd1) {
	// update G1: G1_new = G1*
	element_set(gpk->G1, rpd1->G1);

	// update K: K_new = K*
	element_set(gpk->K, rpd1->K);

	// update H: H_new = H*
	element_set(gpk->H, rpd1->H);

	// update G: G_new = G*
	element_set(gpk->G, rpd1->G);

	// update G2: G2_new = G2*
	element_set(gpk->G2, rpd1->G2);

	// update W: W_new = W*
	element_set(gpk->W, rpd1->W);

	return;
}

// USER REVOCATION PHASE 1 - generate revocation data of user' and update GPK (Revoke)
void xsgs_user_revoke_phase1(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik,
		XSGS_USER_DB_ENTRY* udbe, XSGS_REVOKE_PHASE1** rpd1) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr G1 = gpk->pairing->G1;
	field_ptr G2 = gpk->pairing->G2;
	element_t z;

	(*rpd1) = (XSGS_REVOKE_PHASE1*) malloc(sizeof(XSGS_REVOKE_PHASE1));

	// x' = x
	element_init((*rpd1)->x, Fp);
	element_set((*rpd1)->x, udbe->UCert.x);

	// z = 1 / (gamma + x')
	element_init(z, Fp);
	element_add(z, ik->gamma, (*rpd1)->x);
	element_invert(z, z);

	// G1* = G1^{1/(gamma + x')}
	element_init((*rpd1)->G1, G1);
	element_pow_naf((*rpd1)->G1, gpk->G1, z);

	// K* = K^{1/(gamma + x')}
	element_init((*rpd1)->K, G1);
	element_pow_naf((*rpd1)->K, gpk->K, z);

	// H* = H^{1/(gamma + x')}
	element_init((*rpd1)->H, G1);
	element_pow_naf((*rpd1)->H, gpk->H, z);

	// G* = G^{1/(gamma + x')}
	element_init((*rpd1)->G, G1);
	element_pow_naf((*rpd1)->G, gpk->G, z);

	// G2* = G2^{1/(gamma + x')}
	element_init((*rpd1)->G2, G2);
	element_pow_naf((*rpd1)->G2, gpk->G2, z);

	// W* = G2 * G2*^-x'
	element_init((*rpd1)->W, G2);
	element_neg(z, (*rpd1)->x);
	element_pow_naf((*rpd1)->W, (*rpd1)->G2, z);
	element_mul((*rpd1)->W, (*rpd1)->W, gpk->G2);

	element_clear(z);

	// update GPK
	xsgs_update_gpk(gpk, (*rpd1));

	return;
}

// USER REVOCATION PHASE 2 - update GPK, UCert and sign updated A of UCert (Revoke)
int xsgs_user_revoke_phase2(XSGS_PUBLIC_KEY* gpk, XSGS_USER_KEY* uk,
		XSGS_USER_CERT* ucert, char* usk_pem_filename, XSGS_REVOKE_PHASE1* rpd1,
		XSGS_REVOKE_PHASE2** rpd2) {
	field_ptr Fp = gpk->pairing->Zr;
	field_ptr GT = gpk->pairing->GT;
	field_ptr G1 = gpk->pairing->G1;
	element_t z1, z2, z3, g1, gt1, gt2;
	int ret;

	(*rpd2) = (XSGS_REVOKE_PHASE2*) malloc(sizeof(XSGS_REVOKE_PHASE2));

	// update GPK
	xsgs_update_gpk(gpk, rpd1);

	// update A: A_new = (G1_new * H_new^y)^{1/(x - x')} / A^{1/(x - x')}
	//			   = G1_new^{1/(x - x')} * H_new^{y/(x - x')} * A^{-1/(x - x')}
	element_init(z1, Fp);
	element_init(z2, Fp);
	element_init(z3, Fp);
	element_sub(z1, ucert->x, rpd1->x);
	element_invert(z1, z1);
	element_mul(z2, uk->y, z1);
	element_neg(z3, z1);
	element_pow_naf3(ucert->A, rpd1->G1, z1, rpd1->H, z2, ucert->A, z3);

	// check A_new: A_new^(x + gamma) == G1_new * H_new^y
	// e(A_new, G2_new)^x * e(A_new, W_new) * e(H_new, G2_new)^-y == e(G1_new, G2_new)
	element_init(g1, G1);
	element_init(gt1, GT);
	element_init(gt2, GT);

	// gt1 = e(A_new, G2_new)^x * e(A_new, W_new) * e(H_new, G2_new)^-y
	//     = e(A_new^x * H_new^-y, G2_new) * e(A_new, W_new)
	element_neg(z1, uk->y);
	element_pow_naf2(g1, ucert->A, ucert->x, gpk->H, z1);
	element_pairing(gt1, g1, gpk->G2);
	element_pairing(gt2, ucert->A, gpk->W);
	element_mul(gt1, gt1, gt2);

	// gt2 = e(G1_new, G2_new)
	element_pairing(gt2, gpk->G1, gpk->G2);

	// check gt1 == gt2
	ret = element_cmp(gt1, gt2);

	element_clear(z1);
	element_clear(z2);
	element_clear(z3);
	element_clear(g1);
	element_clear(gt1);
	element_clear(gt2);

	if (!ret) {
		// S* = sign_usk(A_new)
		DWORD msg_len = element_length_in_bytes(ucert->A);
		BYTE* msg = (BYTE*) malloc(msg_len);
		element_to_bytes(msg, ucert->A);
		ret = xsgs_rsa_sign(usk_pem_filename, msg, msg_len, &((*rpd2)->S.sig),
				&((*rpd2)->S.len));
		free(msg);
	}

	return ret;
}

// USER REVOCATION PHASE 3 - update user's database entry
int xsgs_user_revoke_phase3(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik,
		XSGS_USER_DB_ENTRY* udbe, char* upk_pem_filename,
		XSGS_REVOKE_PHASE1* rpd1, XSGS_REVOKE_PHASE2* rpd2) {
	field_ptr Fp = gpk->pairing->Zr;
	element_t z1, z2;
	int ret;

	element_init(z1, Fp);
	element_init(z2, Fp);

	// update C: C_new = H_new^y = H_new^{y/(gamma + x')} = C_new^{1/(gamma + x')}
	element_add(z1, ik->gamma, rpd1->x);
	element_invert(z1, z1);
	element_pow_naf(udbe->C, udbe->C, z1);

	// update A: A_new = (G1_new * H_new^y)^{1/(x - x')} / A^{1/(x - x')}
	//		 = G1_new^{1/(x - x')} * H_new^{y/(x - x')} * A^{-1/(x - x')}
	//		 = G1_new^{1/(x - x')} * C_new^{1/(x - x')} * A^{-1/(x - x')}
	element_sub(z1, udbe->UCert.x, rpd1->x);
	element_invert(z1, z1);
	element_neg(z2, z1);
	element_pow_naf3(udbe->UCert.A, gpk->G1, z1, udbe->C, z1, udbe->UCert.A,
			z2);

	element_clear(z1);
	element_clear(z2);

	// verify_upk(A, S*)
	DWORD msg_len = element_length_in_bytes(udbe->UCert.A);
	BYTE* msg = (BYTE*) malloc(msg_len);
	element_to_bytes(msg, udbe->UCert.A);

	ret = xsgs_rsa_verify(upk_pem_filename, msg, msg_len, rpd2->S.sig,
			rpd2->S.len);
	free(msg);

	if (!ret) {
		// update S: S_new <- S*
		udbe->S.len = rpd2->S.len;
		free(udbe->S.sig);
		udbe->S.sig = (BYTE*) malloc(udbe->S.len);
		memcpy(udbe->S.sig, rpd2->S.sig, udbe->S.len);
	}

	return ret;
}
