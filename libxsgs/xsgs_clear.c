#include "xsgs.h"

// CLEAR FUNCTIONS
void gpk_clear(XSGS_PUBLIC_KEY* gpk) {
	element_clear(gpk->G);
	element_clear(gpk->G1);
	element_clear(gpk->G2);
	element_clear(gpk->H);
	element_clear(gpk->K);
	element_clear(gpk->W);
	//pairing_clear(gpk->pairing);	// segmentation fault
	pbc_param_clear(gpk->param);
	free(gpk->pairing);
	free(gpk->param);
	free(gpk);
	return;
}

void ik_clear(XSGS_ISSUER_KEY* ik) {
	element_clear(ik->gamma);
	free(ik);
	return;
}

void ok_clear(XSGS_OPENER_KEY* ok) {
	element_clear(ok->xi1);
	element_clear(ok->xi2);
	free(ok);
	return;
}

void ucert_clear(XSGS_USER_CERT* ucert) {
	element_clear(ucert->A);
	element_clear(ucert->x);
	free(ucert);
	return;
}

void uk_clear(XSGS_USER_KEY* uk) {
	element_clear(uk->y);
	free(uk);
	return;
}

void udbe_clear(XSGS_USER_DB_ENTRY* udbe) {
	element_clear(udbe->UCert.A);
	element_clear(udbe->UCert.x);
	element_clear(udbe->C);
	free(udbe->S.sig);
	free(udbe);
	return;
}

void sm_clear(XSGS_SIGNED_MSG* sig) {
	free(sig->msg);
	free(sig->sigma.c);
	element_clear(sig->sigma.s_alpha);
	element_clear(sig->sigma.s_beta);
	element_clear(sig->sigma.s_x);
	element_clear(sig->sigma.s_z);
	element_clear(sig->sigma.T1);
	element_clear(sig->sigma.T2);
	element_clear(sig->sigma.T3);
	element_clear(sig->sigma.T4);
	free(sig);
	return;
}

void bsm_clear(XSGS_BATCH_SIGNED_MSG* bsig) {
	free(bsig->msg);
	element_clear(bsig->sigma.T1);
	element_clear(bsig->sigma.T2);
	element_clear(bsig->sigma.T3);
	element_clear(bsig->sigma.T4);
	element_clear(bsig->sigma.R1);
	element_clear(bsig->sigma.R2);
	element_clear(bsig->sigma.R3);
	element_clear(bsig->sigma.R4);
	element_clear(bsig->sigma.s_alpha);
	element_clear(bsig->sigma.s_beta);
	element_clear(bsig->sigma.s_x);
	element_clear(bsig->sigma.s_z);
	free(bsig);
	return;
}

void jpd1_clear(XSGS_JOIN_PHASE1* jpd) {
	element_clear(jpd->C);
	mpz_clear(jpd->U.c);
	free(jpd->U.hash);
	mpz_clear(jpd->U.s);
	free(jpd);
	return;
}

void jpd2_clear(XSGS_JOIN_PHASE2* jpd) {
	element_clear(jpd->A);
	element_clear(jpd->V.T1);
	element_clear(jpd->V.T2);
	free(jpd->V.hash);
	element_clear(jpd->V.s);
	free(jpd);
	return;
}

void jpd3_clear(XSGS_JOIN_PHASE3* jpd) {
	free(jpd->S.sig);
	free(jpd);
	return;
}

void jpd4_clear(XSGS_JOIN_PHASE4* jpd) {
	element_clear(jpd->x);
	free(jpd);
	return;
}

void od_clear(XSGS_OPEN_DATA* od) {
	element_clear(od->A);
	free(od->tau.hash);
	element_clear(od->tau.s_alpha);
	element_clear(od->tau.s_beta);
	element_clear(od->tau.s_gamma);
	element_clear(od->tau.s_delta);
	free(od->S.sig);
	free(od);
	return;
}

void rpd1_clear(XSGS_REVOKE_PHASE1* rpd) {
	element_clear(rpd->x);
	element_clear(rpd->G1);
	element_clear(rpd->K);
	element_clear(rpd->H);
	element_clear(rpd->G2);
	free(rpd);
	return;
}

void rpd2_clear(XSGS_REVOKE_PHASE2* rpd) {
	free(rpd->S.sig);
	free(rpd);
	return;
}
