#include <string.h>
#include "xsgs.h"
#include "xsgs_test.h"


void xsgs_print_group_elements(pbc_param_ptr param, char type) {
    element_t G1, G2, GT, Z;
    pairing_t pairing;


    pairing_init_pbc_param(pairing, param);

    element_init_Zr(Z, pairing);
    element_init_G1(G1, pairing);
    element_init_G2(G2, pairing);
    element_init_GT(GT, pairing);

    element_random(Z);
    element_random(G1);
    element_random(G2);
    element_random(GT);

    printf("\nTYPE %c:\n", type-0x20);

    element_printf("Zp(%u / -) = \n%B\n", element_length_in_bytes(Z), Z);
    element_printf("G1(%u / %u) = \n%B\n", element_length_in_bytes(G1), element_length_in_bytes_compressed(G1), G1);
    if(type == 'a')  {
	element_printf("G2(%u / %u) = \n%B\n", element_length_in_bytes(G2), element_length_in_bytes_compressed(G2), G2);
    }
    else {
	element_printf("G2(%u / -) = \n%B\n", element_length_in_bytes(G2), G2);
    }

    element_printf("GT(%u / -) = \n%B\n", element_length_in_bytes(GT), GT);

    element_clear(Z);
    element_clear(G1);
    element_clear(G2);
    element_clear(GT);

    return;
}

int xsgs_curves_test(void) {
	pbc_param_ptr param = NULL;
	BYTE* buf = NULL;


    printf("\n\n+++ eXtremely Short Group Signature - Curve Test +++\n\n");

	param = xsgs_select_curve_param("curves/", "xsgs_curve_", 11);
	if(param == NULL) {
		return 1;
	}

	if(!xsgs_param_export_buf(&buf, param)) {
		pbc_param_clear(param);
		return 2;
	}

	xsgs_print_group_elements(param, buf[5]);

	free(buf);
	pbc_param_clear(param);

    return 0;
}

XSGS_PAILLIER_PUBKEY* xsgs_ppk_gen_test(void) {
    // pailler public key generation
    XSGS_PAILLIER_PUBKEY* ppk = xsgs_paillier_gen(PAILLIER_MODULO_BITS);

    printf("\nPAILLIER PUB KEY:\n");
    gmp_printf("n (%d bit) = \n%Zd\n", PAILLIER_MODULO_BITS, ppk->n);
    gmp_printf("g (%d bit) = \n%Zd\n", PAILLIER_MODULO_BITS, ppk->g);
    gmp_printf("n^2 (%d bit) = \n%Zd\n", PAILLIER_MODULO_BITS*2, ppk->n_squared);

    return ppk;
}

void xsgs_gen_test(pbc_param_ptr param, XSGS_PUBLIC_KEY** gpk, XSGS_ISSUER_KEY** ik, XSGS_OPENER_KEY** ok) {
    *gpk = (XSGS_PUBLIC_KEY*) malloc(sizeof(XSGS_PUBLIC_KEY));
    *ik = (XSGS_ISSUER_KEY*) malloc(sizeof(XSGS_ISSUER_KEY));
    *ok = (XSGS_OPENER_KEY*) malloc(sizeof(XSGS_OPENER_KEY));

    // print system parameter
    printf("\nXSGS SYSTEM PARAMETER:\n");
    pbc_param_out_str(stdout, param);

    // group public key generation
    xsgs_gm_gen(*gpk, *ik, param);

    // test if pairing is symmetric
    printf("\nPAIRING: ");
    if(pairing_is_symmetric((*gpk)->pairing)) {
	printf("group 1 and group 2 are the same (symmetric pairing)\n");
    }
    else {
	printf("group 1 and group 2 are different (no symmetric pairing)\n");
    }

    // group manager key generation
    xsgs_opener_gen(*gpk, *ok);

    printf("\nXSGS GROUP PUBLIC KEY:\n");
    element_printf("G1 = \n%B\n", (*gpk)->G1);
    element_printf("K = \n%B\n", (*gpk)->K);
    element_printf("H = \n%B\n", (*gpk)->H);
    element_printf("G = \n%B\n", (*gpk)->G);
    element_printf("G2 = \n%B\n", (*gpk)->G2);
    element_printf("W = \n%B\n", (*gpk)->W);
    printf("\nXSGS ISSUER KEY:\n");
    element_printf("ik = gamma = \n%B\n", (*ik)->gamma);
    printf("\nXSGS OPENER KEY:\n");
    element_printf("xi1 = \n%B\n", (*ok)->xi1);
    element_printf("xi2 = \n%B\n", (*ok)->xi2);

    return;
}

int xsgs_join_test(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_PAILLIER_PUBKEY* ppk, XSGS_USER_CERT** ucert, XSGS_USER_KEY** uk, XSGS_USER_DB_ENTRY** udbe, char* rsa_cert_name, char* rsa_key_name) {
    int ret = 0;
    char cert_filename[256];
    char key_filename[256];

    memset(cert_filename, 0, 256);
	snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

	memset(key_filename, 0, 256);
	snprintf(key_filename, 255, "key_store/%s.key", rsa_key_name);

    *ucert = (XSGS_USER_CERT*) malloc(sizeof(XSGS_USER_CERT));
    *uk = (XSGS_USER_KEY*) malloc(sizeof(XSGS_USER_KEY));
    *udbe = (XSGS_USER_DB_ENTRY*) malloc(sizeof(XSGS_USER_DB_ENTRY));


    printf("\nXSGS JOIN USER - TEST:\n");

    printf("\nPHASE 1:\n");
    XSGS_JOIN_PHASE1* jpd1 = (XSGS_JOIN_PHASE1*) malloc(sizeof(XSGS_JOIN_PHASE1));
    xsgs_user_join_phase1(gpk, *uk, ppk, jpd1);
    printf("USER DATA:\n");
    element_printf("C = \n%B\n", jpd1->C);
    printf("USER PROOF U:\n");
    gmp_printf("c = \n%Zd\n", jpd1->U.c);
    printf("h = \n");
    for(int i=0; i<=JOIN_HASH_BITS/8; i++) {
	printf("%X", jpd1->U.hash[i]);
    }
    printf("\n");
    gmp_printf("s = \n%Zd\n", jpd1->U.s);

    printf("\nPHASE 2: ");
    XSGS_JOIN_PHASE2* jpd2 = (XSGS_JOIN_PHASE2*) malloc(sizeof(XSGS_JOIN_PHASE2));
    ret = xsgs_user_join_phase2(gpk, *udbe, ik, ppk, jpd1, jpd2);
    if(!ret) {
	printf("user proof U verifies\n");
	printf("USER DATA:\n");
	element_printf("A = \n%B\n", jpd2->A);
	printf("GROUP MANAGER PROOF V:\n");
	element_printf("T1 = \n%B\n", jpd2->V.T1);
	element_printf("T2 = \n%B\n", jpd2->V.T2);
	printf("h = \n");
	for(int i=0; i<=JOIN_HASH_BITS/8; i++) {
	    printf("%X", jpd2->V.hash[i]);
	}
	printf("\n");
	element_printf("s = \n%B\n", jpd2->V.s);

	printf("\nPHASE 3: ");
	XSGS_JOIN_PHASE3* jpd3 = (XSGS_JOIN_PHASE3*) malloc(sizeof(XSGS_JOIN_PHASE3));
	ret = xsgs_user_join_phase3(gpk, *ucert, jpd1, jpd2, jpd3, key_filename);
	if(!ret) {
	    printf("group manager proof V verifies and A is successfully signed (RSA)\n");
	    printf("S = rsa_sign(A) (%d bit) = \n", jpd3->S.len*8);
	    for(DWORD i=0; i<jpd3->S.len; i++) {
		printf("%02X", jpd3->S.sig[i]);
	    }
	    printf("\n");

	    printf("\nPHASE 4: ");
	    XSGS_JOIN_PHASE4* jpd4 = (XSGS_JOIN_PHASE4*) malloc(sizeof(XSGS_JOIN_PHASE4));
	    ret = xsgs_user_join_phase4(gpk, *udbe, jpd3, jpd4, cert_filename);
	    if(!ret) {
		printf("S verifies (RSA)\n");
		printf("XSGS USER REGISTRATION DATABASE ENTRY:\n");
		element_printf("A = \n%B\n", (*udbe)->UCert.A);
		element_printf("x = \n%B\n", (*udbe)->UCert.x);
		element_printf("C = \n%B\n", (*udbe)->C);
		printf("S (%d bit) = \n", (*udbe)->S.len*8);
		for(DWORD i=0; i<(*udbe)->S.len; i++) {
		    printf("%02X", (*udbe)->S.sig[i]);
		}
		printf("\n");

		printf("*TODO* insert user = (UCert, C, S) into registration database *TODO*\n");

		printf("\nPHASE 5: ");
		ret = xsgs_user_join_phase5(gpk, *ucert, *uk, jpd4);
		if(!ret) {
		    printf("A, x, y verifies\n");
		    printf("XSGS USER CERT:\n");
		    element_printf("A = \n%B\n", (*ucert)->A);
		    element_printf("x = \n%B\n", (*ucert)->x);
		    printf("XSGS USER SECRET KEY:\n");
		    element_printf("y = \n%B\n", (*uk)->y);
		}
		else {
		    printf("*BUG* A, x, y does not verify *BUG*\n");
		}

		jpd4_clear(jpd4);
	    }
	    else {
		printf("*BUG* S does not verify (RSA) *BUG*\n");
	    }

	    jpd3_clear(jpd3);
	}
	else {
	    printf("*BUG* group manager proof V does not verify or error on signing S *BUG*\n");
	}

	jpd2_clear(jpd2);
    }
    else {
	printf("*BUG* user proof U does not verify *BUG*\n");
    }

    jpd1_clear(jpd1);

    return ret;
}

int xsgs_signature_test(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_OPENER_KEY* ok, XSGS_USER_DB_ENTRY* udbe, char* rsa_cert_name, BYTE cache_ctl) {
    XSGS_SIGNED_MSG* sig = (XSGS_SIGNED_MSG*) malloc(sizeof(XSGS_SIGNED_MSG));
    XSGS_OPEN_DATA* od;
    char cert_filename[256];
    int ret;
    XSGS_CACHE* cache = NULL;


	if(cache_ctl) {
		printf("\nXSGS SIGNATURE (CACHE) - TEST:\n");
		cache = cache_init(gpk, ucert);
	}
	else {
		printf("\nXSGS SIGNATURE - TEST:\n");
	}

    memset(cert_filename, 0, 256);
    snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

    // sign
    sig->msg_len = 30;
    sig->msg = (BYTE*) malloc(sig->msg_len);
    get_rand_buf(sig->msg, sig->msg_len);
    printf("SIGN: ");
    if(cache_ctl) {
	xsgs_sign_cache(gpk, ucert, uk, cache, sig);
    }
    else {
	xsgs_sign(gpk, ucert, uk, sig);
    }
    for(DWORD i=0; i<sig->msg_len; i++) {
		printf("%02X", sig->msg[i]);
	}
	printf("\n");

	// for testing
	//element_add(sig->sigma.T2, sig->sigma.T2, sig->sigma.T2);

    // verify
	printf("VERIFY: ");
	if(cache_ctl) {
		ret = xsgs_verify_cache(gpk, cache, sig);
	}
	else {
		ret = xsgs_verify(gpk, sig);
	}
    if(ret) {
	printf("signature verifies\n");

	// open
	od = xsgs_open_sig(gpk, ok, sig);
	printf("OPEN: ");
	if(od != NULL) {
	    element_printf("signature successfully opened\n");

	    // find the actual signer, using the read-access to the registration table
	    // set RSA signature of A to open data
	    od->S.len = udbe->S.len;
	    od->S.sig = (BYTE*) malloc(od->S.len);
	    memcpy(od->S.sig, udbe->S.sig, od->S.len);

	    // judge
	    ret = xsgs_judge_sig(gpk, sig, od, cert_filename);
	    printf("JUDGE: ");
	    if(!ret) {
		printf("open data verifies\n");
	    }
	    else {
		printf("*BUG* open data does not verify *BUG*\n");
	    }

	    od_clear(od);
	}
	else {
	    printf("*BUG* signature could not be opened *BUG*\n");
	}
    }
    else {
	printf("*BUG* signature does not verify *BUG*\n");
    }

    sm_clear(sig);

    return ret;
}

int xsgs_batch_signature_test(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_OPENER_KEY* ok, XSGS_USER_DB_ENTRY* udbe, char* rsa_cert_name, BYTE cache_ctl) {
    DWORD i = 0;
    int ret = 0;
    DWORD list_size = 10;
    XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_BATCH_SIGNED_MSG*));
    BYTE* sig_status = (BYTE*) malloc(list_size);
    XSGS_OPEN_DATA* od;
    char cert_filename[256];
    XSGS_CACHE* cache = NULL;


    if(cache_ctl) {
	printf("\nXSGS BATCH SIGNATURE (CACHE) - TEST:\n");
	cache = cache_init(gpk, ucert);
    }
    else {
	printf("\nXSGS BATCH SIGNATURE - TEST:\n");
    }

    memset(cert_filename, 0, 256);
    snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

    // sign
    printf("SIGN:\n");
    for(i=0; i<list_size; i++) {
	sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
	sig_list[i]->msg_len = 30;
	sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
		get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
	printf("[%04u] msg = ", i);
		for(DWORD j=0; j<sig_list[i]->msg_len; j++) {
			printf("%02X", sig_list[i]->msg[j]);
		}
		printf("\n");
    }
    if(cache_ctl) {
	xsgs_batch_sign_cache(gpk, ucert, uk, cache, sig_list, list_size);
    }
    else {
	xsgs_batch_sign(gpk, ucert, uk, sig_list, list_size);
    }

    // for testing
    //element_add(sig_list[0]->sigma.R2, sig_list[0]->sigma.R2, sig_list[0]->sigma.R2);
    //element_add(sig_list[1]->sigma.R2, sig_list[1]->sigma.R2, sig_list[1]->sigma.R2);
    //element_add(sig_list[2]->sigma.R2, sig_list[2]->sigma.R2, sig_list[2]->sigma.R2);
    //element_add(sig_list[3]->sigma.R2, sig_list[3]->sigma.R2, sig_list[3]->sigma.R2);
    //element_add(sig_list[4]->sigma.R2, sig_list[4]->sigma.R2, sig_list[4]->sigma.R2);
    //element_add(sig_list[5]->sigma.R2, sig_list[5]->sigma.R2, sig_list[5]->sigma.R2);
    //element_add(sig_list[6]->sigma.R2, sig_list[6]->sigma.R2, sig_list[6]->sigma.R2);
    //element_add(sig_list[7]->sigma.R2, sig_list[7]->sigma.R2, sig_list[7]->sigma.R2);
    //element_add(sig_list[8]->sigma.R2, sig_list[8]->sigma.R2, sig_list[8]->sigma.R2);
    //element_add(sig_list[9]->sigma.R2, sig_list[9]->sigma.R2, sig_list[9]->sigma.R2);

    // verify
    printf("VERIFY:\n");
    if(cache_ctl) {
	xsgs_batch_verify_cache(gpk, cache, sig_list, list_size, sig_status);
	}
	else {
		xsgs_batch_verify(gpk, sig_list, list_size, sig_status);
	}
    for(i=0; i<list_size; i++) {
	if(sig_status[i]) {
	    printf("[%04d] signature verifies\n", i);
	}
	else {
	    printf("[%04d] *BUG* signature does not verify *BUG*\n", i);
	}
    }


    // open xsgs batch signature
    printf("OPEN: ");
    od = xsgs_open_batch_sig(gpk, ok, sig_list[0]);
    if(od != NULL) {
	element_printf("signature successfully opened\n");

	// find the actual signer, using the read-access to the registration table
	// set RSA signature of A to open data
	od->S.len = udbe->S.len;
	od->S.sig = (BYTE*) malloc(od->S.len);
	memcpy(od->S.sig, udbe->S.sig, od->S.len);

	ret = xsgs_judge_batch_sig(gpk, sig_list[0], od, cert_filename);
	printf("JUDGE: ");
	if(!ret) {
	    printf("open data verifies\n");
	}
	else {
	    printf("*BUG* open data does not verify *BUG*\n");
	}

	od_clear(od);
    }
    else {
	printf("*BUG* signature could not be opened *BUG*\n");
    }

    for(i=0; i<list_size; i++) {
	bsm_clear(sig_list[i]);
    }
    free(sig_list);
    free(sig_status);

    return ret;
}

int xsgs_revocation_test(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_USER_DB_ENTRY* udbe, char* rsa_cert_name, char* rsa_key_name) {
    XSGS_USER_CERT* ucert_tmp;
    XSGS_USER_KEY* uk_tmp;
    XSGS_USER_DB_ENTRY* udbe_tmp;
    BYTE* data;
    int ret = 0;
    char cert_filename[256];
	char key_filename[256];
	XSGS_REVOKE_PHASE1* rpd1;
	XSGS_REVOKE_PHASE2* rpd2;


	memset(cert_filename, 0, 256);
	snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

	memset(key_filename, 0, 256);
	snprintf(key_filename, 255, "key_store/%s.key", rsa_key_name);

    // join 2 test users
    xsgs_user_join_offline(gpk, ik, &ucert_tmp, &uk_tmp, &udbe_tmp, key_filename);

    // copy gpk
    xsgs_gpk_export_buf(&data, gpk);
    XSGS_PUBLIC_KEY* gpk_tmp = xsgs_gpk_import_buf(data);
    free(data);

    printf("\nXSGS REVOCATION - TEST:\n");

    printf("\nPHASE 1:\n");
    xsgs_user_revoke_phase1(gpk_tmp, ik, udbe_tmp, &rpd1);
    printf("REVOCATION DATA:\n");
    element_printf("x = \n%B\n", rpd1->x);
    element_printf("G1 = \n%B\n", rpd1->G1);
    element_printf("K = \n%B\n", rpd1->K);
    element_printf("H = \n%B\n", rpd1->H);
    element_printf("G2 = \n%B\n", rpd1->G2);
    printf("UPDATED GROUP PUBLIC KEY:\n");
    element_printf("G1 = \n%B\n", gpk_tmp->G1);
    element_printf("K = \n%B\n", gpk_tmp->K);
    element_printf("H = \n%B\n", gpk_tmp->H);
    element_printf("G = \n%B\n", gpk_tmp->G);
    element_printf("G2 = \n%B\n", gpk_tmp->G2);
    element_printf("W = \n%B\n", gpk_tmp->W);

    // user updates GPK and identifier A
    printf("\nPHASE 2:\n");
    ret = xsgs_user_revoke_phase2(gpk, uk, ucert, key_filename, rpd1, &rpd2);
    if(!ret) {
		printf("UPDATED GROUP PUBLIC KEY:\n");
		element_printf("G1 = \n%B\n", gpk->G1);
		element_printf("K = \n%B\n", gpk->K);
		element_printf("H = \n%B\n", gpk->H);
		element_printf("G = \n%B\n", gpk->G);
		element_printf("G2 = \n%B\n", gpk->G2);
		element_printf("W = \n%B\n", gpk->W);
		printf("UPDATED USER IDENTIFIER:\n");
		element_printf("A = \n%B\n", ucert->A);
		printf("RSA SIGNATURE OF USER IDENTIFIER:\n");
		printf("S (%d bit) = \n", rpd2->S.len*8);
		for(DWORD i=0; i<rpd2->S.len; i++) {
			printf("%02X", rpd2->S.sig[i]);
		}
		printf("\n");
    }
    else {
	printf("*BUG* Phase 2 failed *BUG*\n");
    }

    // group manager updates udbe
    printf("\nPHASE 3:\n");
    ret = xsgs_user_revoke_phase3(gpk_tmp, ik, udbe, cert_filename, rpd1, rpd2);
    if(!ret) {
	printf("UPDATED USER DATABASE ENTRY:\n");
	element_printf("A = \n%B\n", udbe->UCert.A);
		element_printf("x = \n%B\n", udbe->UCert.x);
		element_printf("C = \n%B\n", udbe->C);
		printf("S (%d bit) = \n", udbe->S.len*8);
		for(DWORD i=0; i<udbe->S.len; i++) {
			printf("%02X", udbe->S.sig[i]);
		}
		printf("\n");
    }
    else {
	printf("*BUG* Phase 3 failed *BUG*\n");
    }

    rpd1_clear(rpd1);
    rpd2_clear(rpd2);
    gpk_clear(gpk_tmp);
    ucert_clear(ucert_tmp);
    uk_clear(uk_tmp);;
    udbe_clear(udbe_tmp);

    return ret;
}

int xsgs_system_test(char gen_export) {
    pbc_param_ptr param = NULL;
    XSGS_PUBLIC_KEY* gpk = NULL;
    XSGS_ISSUER_KEY* ik = NULL;
    XSGS_OPENER_KEY* ok = NULL;
    XSGS_PAILLIER_PUBKEY* ppk = NULL;
    XSGS_USER_CERT* ucert = NULL;
    XSGS_USER_KEY* uk = NULL;
    XSGS_USER_DB_ENTRY* udbe = NULL;


    printf("\n\n+++ eXtremely Short Group Signature - System Test +++\n\n");

    // group keys
    if(gen_export) {
	param = xsgs_select_curve_param("curves/", "xsgs_curve_", 11);
		if(param == NULL) {
			return 1;
		}

	// generate group keys
	xsgs_gen_test(param, &gpk, &ik, &ok);
	xsgs_gpk_export_file("key_store/xsgs_gpk.key", gpk);
	xsgs_ik_export_file("key_store/xsgs_ik.key", ik);
	xsgs_ok_export_file("key_store/xsgs_ok.key", ok);
    }
    else {

	// import group keys
	gpk = xsgs_gpk_import_file("key_store/xsgs_gpk.key");
	if(gpk == NULL) {
	    return 2;
	}
	ik = xsgs_ik_import_file(gpk, "key_store/xsgs_ik.key");
	if(ik == NULL) {
	    gpk_clear(gpk);
	    return 3;
	}
	ok = xsgs_ok_import_file(gpk, "key_store/xsgs_ok.key");
	if(ok == NULL) {
	    gpk_clear(gpk);
	    ik_clear(ik);
	    return 4;
	}
    }

    // paillier public key
    if(gen_export) {
	// generate paillier public key
	ppk = xsgs_ppk_gen_test();
	xsgs_ppk_export_file("key_store/xsgs_ppk.key", ppk);
    }
    else {
	// import paillier public key
	ppk = xsgs_ppk_import_file("key_store/xsgs_ppk.key");
	if(ppk == NULL) {
	    gpk_clear(gpk);
	    ik_clear(ik);
	    ok_clear(ok);
	    return 5;
	}
    }

    // user join test
    if(gen_export) {
	// generate user data
	xsgs_join_test(gpk, ik, ppk, &ucert, &uk, &udbe, "test-2048", "test-2048");
	xsgs_ucert_export_file("cert_store/xsgs_ucert.cert", ucert);
	xsgs_uk_export_file("key_store/xsgs_uk.key", uk);
	xsgs_udbe_export_file("database/xsgs_user.db", udbe);
    }
    else {
	// import user data
	ucert = xsgs_ucert_import_file(gpk, "cert_store/xsgs_ucert.cert");
	if(ucert == NULL) {
	    gpk_clear(gpk);
	    ik_clear(ik);
	    ok_clear(ok);
	    ppk_clear(ppk);
	    return 6;
	}
	uk =  xsgs_uk_import_file(gpk, "key_store/xsgs_uk.key");
	if(uk == NULL) {
	    gpk_clear(gpk);
	    ik_clear(ik);
	    ok_clear(ok);
	    ppk_clear(ppk);
	    ucert_clear(ucert);
	    return 7;
	}
	udbe = xsgs_udbe_import_file(gpk, "database/xsgs_user.db");
	if(udbe == NULL) {
	    gpk_clear(gpk);
	    ik_clear(ik);
	    ok_clear(ok);
	    ppk_clear(ppk);
	    ucert_clear(ucert);
	    uk_clear(uk);
	    return 8;
	}
    }

    // revocation test
	xsgs_revocation_test(gpk, ik, ucert, uk, udbe, "test-2048", "test-2048");

    // signature test
    xsgs_signature_test(gpk, ucert, uk, ok, udbe, "test-2048", 0);
    xsgs_signature_test(gpk, ucert, uk, ok, udbe, "test-2048", 1);
    xsgs_batch_signature_test(gpk, ucert, uk, ok, udbe, "test-2048", 0);
    xsgs_batch_signature_test(gpk, ucert, uk, ok, udbe, "test-2048", 1);

    // clear
    gpk_clear(gpk);
    ik_clear(ik);
    ok_clear(ok);
    ppk_clear(ppk);
    ucert_clear(ucert);
    uk_clear(uk);
    udbe_clear(udbe);

    return 0;
}
