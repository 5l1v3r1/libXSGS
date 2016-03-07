#include <string.h>
#include <time.h>
#include "xsgs.h"
#include "xsgs_bench.h"


#define GET_BENCH_TIME(begin, end, cnt) (((double) (end - begin))/CLOCKS_PER_SEC*1000/cnt)
#define PRINT_BENCH_TIME(begin, end, cnt) printf("%.3f ms\n", GET_BENCH_TIME(begin, end, cnt));fflush(NULL);


void xsgs_group_bench(field_t Zr, field_t G, DWORD list_size) {
	clock_t start_time, end_time;
	DWORD i = 0;
	element_t *lut, *lut2, *lut3;

	element_t* Z1 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* Z2 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* Z3 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* G1 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* G2 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* G3 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* G4 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* G5 = (element_t*) malloc(list_size*sizeof(element_t));

	for(i=0; i<list_size; i++) {
		element_init(Z1[i], Zr);
		element_init(Z2[i], Zr);
		element_init(Z3[i], Zr);
		element_init(G1[i], G);
		element_init(G2[i], G);
		element_init(G3[i], G);
		element_init(G4[i], G);
		element_init(G5[i], G);
	}

	for(i=0; i<list_size; i++) {
		element_random(Z1[i]);
		element_random(Z2[i]);
		element_random(Z3[i]);
		element_random(G2[i]);
		element_random(G3[i]);
		element_random(G4[i]);
	}

	printf("Addition: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_add(G1[i], G2[i], G3[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Multiplication: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_mul(G1[i], G2[i], G3[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Negation: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_neg(G1[i], G2[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Inversion: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_invert(G1[i], G2[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Exponentiation SW: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_pow_zn(G1[i], G2[0], Z1[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Exponentiation SW with NAF: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_pow_naf(G5[i], G2[0], Z1[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	for(i=0; i<list_size; i++){
		if(element_cmp(G1[i], G5[i])) {
			printf("element_pow_naf() error on %u\n", i);
		}
	}

	for(i=0; i<list_size; i++) {
		element_random(G2[i]);
		element_random(G3[i]);
		element_random(G4[i]);
		element_random(G5[i]);
	}

	lut = lut_init(G2[0], mpz_sizeinbase(G->order, 2)+1);
	lut2 = lut_init(G3[0], mpz_sizeinbase(G->order, 2)+1);
	lut3 = lut_init(G4[0], mpz_sizeinbase(G->order, 2)+1);

	printf("Exponentiation FB: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		fixed_base_exp(G1[i], lut, Z1[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Exponentiation FB with NAF: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		fixed_base_exp_naf(G5[i], lut, Z1[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Multiexponentiation2 SAM: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_pow2_zn(G1[i], G2[0], Z1[i], G3[0], Z2[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Multiexponentiation2 SAM with NAF: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_pow_naf2(G5[i], G2[0], Z1[i], G3[0], Z2[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	for(i=0; i<list_size; i++){
		if(element_cmp(G1[i], G5[i])) {
			printf("element_pow_naf2() error on %u\n", i);
		}
	}

	printf("Multiexponentiation2 FB: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		fixed_base_exp2(G5[i], lut, Z1[i], lut2, Z2[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	for(i=0; i<list_size; i++){
		if(element_cmp(G1[i], G5[i])) {
			printf("fixed_base_exp2() error on %u\n", i);
		}
	}

	printf("Multiexponentiation2 FB with NAF: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		fixed_base_exp_naf2(G5[i], lut, Z1[i], lut2, Z2[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	for(i=0; i<list_size; i++){
		if(element_cmp(G1[i], G5[i])) {
			printf("fixed_base_exp_naf2() error on %u\n", i);
		}
	}

	printf("Multiexponentiation3 SAM: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_pow3_zn(G1[i], G2[0], Z1[i], G3[0], Z2[i], G4[0], Z3[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Multiexponentiation3 SAM with NAF: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_pow_naf3(G5[i], G2[0], Z1[i], G3[0], Z2[i], G4[0], Z3[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	for(i=0; i<list_size; i++){
		if(element_cmp(G1[i], G5[i])) {
			printf("element_pow_naf3() error on %u\n", i);
		}
	}

	printf("Multiexponentiation3 FB: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		fixed_base_exp3(G5[i], lut, Z1[i], lut2, Z2[i], lut3, Z3[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	for(i=0; i<list_size; i++){
		if(element_cmp(G1[i], G5[i])) {
			printf("fixed_base_exp3() error on %u\n", i);
		}
	}

	printf("Multiexponentiation3 FB with NAF: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		fixed_base_exp_naf3(G5[i], lut, Z1[i], lut2, Z2[i], lut3, Z3[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	for(i=0; i<list_size; i++){
		if(element_cmp(G1[i], G5[i])) {
			printf("fixed_base_exp_naf3() error on %u\n", i);
		}
	}

	lut_clear(lut, mpz_sizeinbase(G->order, 2)+1);
	lut_clear(lut2, mpz_sizeinbase(G->order, 2)+1);
	lut_clear(lut3, mpz_sizeinbase(G->order, 2)+1);

	for(i=0; i<list_size; i++) {
		element_clear(Z1[i]);
		element_clear(Z2[i]);
		element_clear(Z3[i]);
		element_clear(G1[i]);
		element_clear(G2[i]);
		element_clear(G3[i]);
		element_clear(G4[i]);
		element_clear(G5[i]);
	}

	return;
}

void xsgs_ops_bench(pbc_param_ptr param, DWORD list_size) {
    pairing_t pairing;
    clock_t start_time, end_time;
    DWORD i = 0;


    pairing_init_pbc_param(pairing, param);

    element_t* Z1 = (element_t*) malloc(list_size*sizeof(element_t));
    element_t* Z2 = (element_t*) malloc(list_size*sizeof(element_t));
    element_t* Z3 = (element_t*) malloc(list_size*sizeof(element_t));
    element_t* G1 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* G2 = (element_t*) malloc(list_size*sizeof(element_t));
	element_t* GT = (element_t*) malloc(list_size*sizeof(element_t));

    for(i=0; i<list_size; i++) {
	element_init(Z1[i], pairing->Zr);
	element_init(Z2[i], pairing->Zr);
	element_init(Z3[i], pairing->Zr);
	element_init(G1[i], pairing->G1);
		element_init(G2[i], pairing->G2);
		element_init(GT[i], pairing->GT);
    }

    // Zr
    printf("\nBenchmark of Zr:\n");
    for(i=0; i<list_size; i++) {
		element_random(Z2[i]);
		element_random(Z3[i]);
	}
    printf("Addition: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_add(Z1[i], Z2[i], Z3[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Multiplication: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_mul(Z1[i], Z2[i], Z3[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Negation: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_neg(Z1[i], Z2[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

	printf("Inversion: ");
	start_time = clock();
	for(i=0; i<list_size; i++){
		element_invert(Z1[i], Z2[i]);
	}
	end_time = clock();
	PRINT_BENCH_TIME(start_time, end_time, list_size);

    // group G1
	printf("\nBenchmark of G1:\n");
	xsgs_group_bench(pairing->Zr, pairing->G1, list_size);

    // group G2
	printf("\nBenchmark of G2:\n");
	xsgs_group_bench(pairing->Zr, pairing->G2, list_size);

	// group GT
	printf("\nBenchmark of GT:\n");
	xsgs_group_bench(pairing->Zr, pairing->GT, list_size);

    // pairing
	for(i=0; i<list_size; i++) {
		element_random(G1[i]);
		element_random(G2[i]);
	}
    printf("\nPairing (G1 x G2 -> GT): ");
    start_time = clock();
    for(i=0; i<list_size; i++){
	element_pairing(GT[i], G1[i], G2[i]);
    }
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, list_size);

    for(i=0; i<list_size; i++) {
	element_clear(Z1[i]);
	element_clear(Z2[i]);
	element_clear(Z3[i]);
	element_clear(G1[i]);
		element_clear(G2[i]);
		element_clear(GT[i]);
    }

    return;
}

int xsgs_curves_bench(void) {
    DWORD ret = 0, count = 0;
    pbc_param_ptr param = NULL;


    printf("\n\n+++ eXtremely Short Group Signature - Curve Benchmark +++\n\n");

    param = xsgs_select_curve_param("curves/", "xsgs_curve_", 11);
	if(param == NULL) {
		return 1;
	}

    printf("\nEnter count of measures: ");
    ret = scanf("%u", &count);
    if(ret != 1) {
	return 2;
    }

    xsgs_ops_bench(param, count);
    pbc_param_clear(param);


    return 0;
}

int xsgs_rsa_bench(void){
    int ret = 0;
    DWORD msg_len, sig_len, ct_len, pt_len;
    BYTE *msg, *sig, *ct, *pt;
    clock_t start_time, end_time;
    char key_filename[256];
    char cert_filename[256];
    char* names[3] = {"test-1024", "test-2048", "test-4096"};


    printf("\n\n+++ RSA - BENCHMARK +++\n");

    // parameter input
    printf("Enter message size in bytes: ");
    ret = scanf("%u", &msg_len);
    msg = (BYTE*) malloc(msg_len);
    get_rand_buf(msg, msg_len);

    for(DWORD i=0; i<3; i++) {
	memset(cert_filename, 0, 256);
		snprintf(cert_filename, 255, "cert_store/%s.pem", names[i]);

		memset(key_filename, 0, 256);
		snprintf(key_filename, 255, "key_store/%s.key", names[i]);

		printf("\n[RSA: %u bit, HASH: SHA-256, Pad: OAEP]\n", xsgs_rsa_get_size(key_filename, RSA_PRV_KEY));
		printf("Sign: ");
		start_time = clock();
		ret = xsgs_rsa_sign(key_filename, msg, msg_len, &sig, &sig_len);
		end_time = clock();
		PRINT_BENCH_TIME(start_time, end_time, 1);

		printf("Verify: ");
		start_time = clock();
		ret = xsgs_rsa_verify(cert_filename, msg, msg_len, sig, sig_len);
		end_time = clock();
		PRINT_BENCH_TIME(start_time, end_time, 1);
		free(sig);

		printf("Encrypt: ");
		start_time = clock();
		ret = xsgs_rsa_encrypt(cert_filename, msg, msg_len, &ct, &ct_len);
		end_time = clock();
		printf("%.3f ms [CT: %d bytes]\n", GET_BENCH_TIME(start_time, end_time, 1), ct_len);

		printf("Decrypt: ");
		start_time = clock();
		ret = xsgs_rsa_decrypt(key_filename, ct, ct_len, &pt, &pt_len);
		end_time = clock();
		PRINT_BENCH_TIME(start_time, end_time, 1);
		if(memcmp(msg, pt, msg_len)) {
			printf("[failed]\n");
		}
		free(ct);
		free(pt);
    }

    free(msg);

    return ret;
}

int xsgs_hash_bench(void){
    int ret = 0;
    DWORD msg_len, hash_len[3] = {256, 384, 512}; // NIST length
    BYTE *msg, *hash;
    clock_t start_time, end_time;


    printf("\n\n+++ SHA3 (Keccak) - BENCHMARK +++\n");

    // parameter input
    printf("Enter message size in bytes: ");
    ret = scanf("%u", &msg_len);
    msg = (BYTE*) malloc(msg_len);
    get_rand_buf(msg, msg_len);

    for(DWORD i=0; i<3; i++) {
	hash = (BYTE*)malloc(hash_len[i]/8);

		printf("\n[SHA3: %u bit]\n", hash_len[i]);
		printf("Hash: ");
		start_time = clock();
		ret = xsgs_hash(msg, msg_len*8, hash, hash_len[i]);
		end_time = clock();
		PRINT_BENCH_TIME(start_time, end_time, 1);

		free(hash);
    }

    free(msg);

    return ret;
}

int xsgs_join_bench(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_PAILLIER_PUBKEY* ppk, XSGS_USER_CERT** ucert, XSGS_USER_KEY** uk, XSGS_USER_DB_ENTRY** udbe, char* rsa_cert_name, char* rsa_key_name) {
    XSGS_JOIN_PHASE1* jpd1 = (XSGS_JOIN_PHASE1*) malloc(sizeof(XSGS_JOIN_PHASE1));
    XSGS_JOIN_PHASE2* jpd2 = (XSGS_JOIN_PHASE2*) malloc(sizeof(XSGS_JOIN_PHASE2));
    XSGS_JOIN_PHASE3* jpd3 = (XSGS_JOIN_PHASE3*) malloc(sizeof(XSGS_JOIN_PHASE3));
    XSGS_JOIN_PHASE4* jpd4 = (XSGS_JOIN_PHASE4*) malloc(sizeof(XSGS_JOIN_PHASE4));
    clock_t start_time, end_time;
    int ret;
    *ucert = (XSGS_USER_CERT*) malloc(sizeof(XSGS_USER_CERT));
    *uk = (XSGS_USER_KEY*) malloc(sizeof(XSGS_USER_KEY));
    *udbe = (XSGS_USER_DB_ENTRY*) malloc(sizeof(XSGS_USER_DB_ENTRY));
    char cert_filename[256];
    char key_filename[256];


    memset(cert_filename, 0, 256);
    snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

    memset(key_filename, 0, 256);
    snprintf(key_filename, 255, "key_store/%s.key", rsa_key_name);


    printf("\nXSGS JOIN USER - BENCHMARK:\n");
    printf("[Paillier: 1024 bit, RSA: %d bit, SHA3: %d bit]\n", xsgs_rsa_get_size(key_filename, RSA_PRV_KEY), JOIN_HASH_BITS);

    printf("PHASE 1: ");
    start_time = clock();
    xsgs_user_join_phase1(gpk, *uk, ppk, jpd1);
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, 1);

    printf("PHASE 2: ");
    start_time = clock();
    ret = xsgs_user_join_phase2(gpk, *udbe, ik, ppk, jpd1, jpd2);
    end_time = clock();
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, 1));
    if(!ret) {
	printf("[ok]\n");
    }
    else {
	printf("[failed]\n");
    }

    printf("PHASE 3: ");
    start_time = clock();
    ret = xsgs_user_join_phase3(gpk, *ucert, jpd1, jpd2, jpd3, key_filename);
    end_time = clock();
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, 1));
    if(!ret) {
	printf("[ok]\n");
    }
    else {
	printf("[failed]\n");
    }

    printf("PHASE 4: ");
    start_time = clock();
    ret = xsgs_user_join_phase4(gpk, *udbe, jpd3, jpd4, cert_filename);
    end_time = clock();
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, 1));
    if(!ret) {
	printf("[ok]\n");
    }
    else {
	printf("[failed]\n");
    }

    printf("PHASE 5: ");
    start_time = clock();
    ret = xsgs_user_join_phase5(gpk, *ucert, *uk, jpd4);
    end_time = clock();
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, 1));
    if(!ret) {
	printf("[ok]\n");
    }
    else {
	printf("[failed]\n");
    }

    jpd1_clear(jpd1);
    jpd2_clear(jpd2);
    jpd3_clear(jpd3);
    jpd4_clear(jpd4);

    return 0;
}

int xsgs_signature_bench(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_OPENER_KEY* ok, XSGS_USER_DB_ENTRY* udbe, DWORD msg_len, DWORD list_size, BYTE cache_ctl, char* rsa_cert_name) {
    XSGS_SIGNED_MSG** sig_list = (XSGS_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_SIGNED_MSG*));
    XSGS_OPEN_DATA** od_list = (XSGS_OPEN_DATA**) malloc(list_size*sizeof(XSGS_OPEN_DATA*));
    BYTE* sig_status = (BYTE*) malloc(list_size);
    clock_t start_time, end_time;
    DWORD i = 0;
    char cert_filename[256];
    XSGS_CACHE* cache;


    memset(cert_filename, 0, 256);
    snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

    printf("\nXSGS SIGNATURE - BENCHMARK:\n");
    printf("[msg_len = %d, list_size = %d, SHA3: %d bit, RSA: %d bit]\n", msg_len, list_size, SIGNATURE_HASH_BITS, xsgs_rsa_get_size(cert_filename, RSA_PUB_KEY));

    if(cache_ctl) {
	cache = cache_init(gpk, ucert);
    }

    for(i=0; i < list_size; i++) {
	sig_list[i] = (XSGS_SIGNED_MSG*) malloc(sizeof(XSGS_SIGNED_MSG));
	sig_list[i]->msg_len = msg_len;
	sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
		get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
	}

    // sign
    printf("SIGN: ");
    if(cache_ctl) {
	start_time = clock();
	for(i=0; i<list_size; i++) {
	    xsgs_sign_cache(gpk, ucert, uk, cache, sig_list[i]);
	}
	end_time = clock();
    }
    else {
	start_time = clock();
	for(i=0; i<list_size; i++) {
	    xsgs_sign(gpk, ucert, uk, sig_list[i]);
	}
	end_time = clock();
    }
    PRINT_BENCH_TIME(start_time, end_time, list_size);

    // verify
    printf("VERIFY: ");
    if(cache_ctl) {
	start_time = clock();
	for(i=0; i<list_size; i++) {
	    sig_status[i] = xsgs_verify_cache(gpk, cache, sig_list[i]);
	}
	end_time = clock();
    }
    else {
	start_time = clock();
	for(i=0; i<list_size; i++) {
	    sig_status[i] = xsgs_verify(gpk, sig_list[i]);
	}
	end_time = clock();
    }
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, list_size));
    for(i=0; i<list_size; i++) {
	if(!sig_status[i]) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");

    if(cache_ctl) {
	cache_clear(cache, gpk);
    }

    // open
    printf("OPEN: ");
    start_time = clock();
    for(i=0; i<list_size; i++) {
	od_list[i] = xsgs_open_sig(gpk, ok, sig_list[i]);

	// find the actual signer, using the read-access to the registration table
	od_list[i]->S.len = udbe->S.len;
	od_list[i]->S.sig = (BYTE*) malloc(od_list[i]->S.len);
	memcpy(od_list[i]->S.sig, udbe->S.sig, od_list[i]->S.len);
    }
    end_time = clock();
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, list_size));
    for(i=0; i<list_size; i++) {
	if(od_list[i] == NULL) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");

    // judge
    printf("JUDGE: ");
    start_time = clock();
    for(i=0; i<list_size; i++) {
	sig_status[i] = !xsgs_judge_sig(gpk, sig_list[i], od_list[i], cert_filename);
    }
    end_time = clock();
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, list_size));
    for(i=0; i<list_size; i++) {
	if(!sig_status[i]) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");


    for(i=0; i<list_size; i++) {
	sm_clear(sig_list[i]);
	od_clear(od_list[i]);
    }
    free(sig_list);
    free(sig_status);

    return 0;
}

int xsgs_batch_signature_bench(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_OPENER_KEY* ok, XSGS_USER_DB_ENTRY* udbe, DWORD msg_len, DWORD list_size, BYTE cache_ctl, char* rsa_cert_name) {
    int ret = 0;
    DWORD i = 0;
    XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_BATCH_SIGNED_MSG*));
    XSGS_OPEN_DATA** od_list = (XSGS_OPEN_DATA**) malloc(list_size*sizeof(XSGS_OPEN_DATA*));
    BYTE* sig_status = (BYTE*) malloc(list_size);
    clock_t start_time, end_time;
    char pem_filename[256];
    XSGS_CACHE* cache;


    memset(pem_filename, 0, 256);
    snprintf(pem_filename, 255, "cert_store/%s.pem", rsa_cert_name);


    printf("\nXSGS BATCH SIGNATURE - BENCHMARK:\n");
    printf("[msg_len = %d, list_size = %d, SHA3: %d bit, RSA: %d bit]\n", msg_len, list_size, BATCH_SIGNATURE_HASH_BITS, xsgs_rsa_get_size(pem_filename, RSA_PUB_KEY));

    if(cache_ctl) {
	cache = cache_init(gpk, ucert);
    }

    for(i=0; i < list_size; i++) {
		sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
		sig_list[i]->msg_len = msg_len;
		sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
		get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
	}

    // sign
    printf("SIGN: ");
    if(cache_ctl) {
	start_time = clock();
	xsgs_batch_sign_cache(gpk, ucert, uk, cache, sig_list, list_size);
	end_time = clock();
    }
    else {
	start_time = clock();
	xsgs_batch_sign(gpk, ucert, uk, sig_list, list_size);
	end_time = clock();
    }
    //PRINT_BENCH_TIME(start_time, end_time, list_size);
    PRINT_BENCH_TIME(start_time, end_time, 1);

    //element_add(sig_list[997]->sigma.R2, sig_list[47]->sigma.R2, sig_list[47]->sigma.R2);
	//element_add(sig_list[998]->sigma.R2, sig_list[48]->sigma.R2, sig_list[48]->sigma.R2);
	//element_add(sig_list[999]->sigma.R2, sig_list[49]->sigma.R2, sig_list[49]->sigma.R2);

    // verify
    printf("VERIFY: ");
    start_time = clock();
    if(cache_ctl) {
	xsgs_batch_verify_cache(gpk, cache, sig_list, list_size, sig_status);
    }
    else {
	xsgs_batch_verify(gpk, sig_list, list_size, sig_status);
    }
    end_time = clock();
    //printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, list_size));
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, 1));
    for(i=0; i<list_size; i++) {
	if(!sig_status[i]) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");

    if(cache_ctl) {
	cache_clear(cache, gpk);
    }

    // open
    printf("OPEN: ");
    start_time = clock();
    for(i=0; i<list_size; i++) {
	od_list[i] = xsgs_open_batch_sig(gpk, ok, sig_list[i]);

	// find the actual signer, using the read-access to the registration table
	od_list[i]->S.len = udbe->S.len;
	od_list[i]->S.sig = (BYTE*) malloc(od_list[i]->S.len);
	memcpy(od_list[i]->S.sig, udbe->S.sig, od_list[i]->S.len);
    }
    end_time = clock();
    //printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, list_size));
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, 1));
    for(i=0; i<list_size; i++) {
	if(od_list[i] == NULL) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");

    // judge
    printf("JUDGE: ");
    start_time = clock();
    for(i=0; i<list_size; i++) {
	sig_status[i] = !xsgs_judge_batch_sig(gpk, sig_list[i], od_list[i], pem_filename);
    }
    end_time = clock();
    //printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, list_size));
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, 1));
    for(i=0; i<list_size; i++) {
	if(!sig_status[i]) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");

    for(i=0; i<list_size; i++) {
	bsm_clear(sig_list[i]);
	od_clear(od_list[i]);
    }
    free(sig_list);
    free(sig_status);

    return ret;
}

void xsgs_revocation_bench(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik) {
    XSGS_USER_CERT *ucert_i, *ucert_j;
    XSGS_USER_KEY *uk_i, *uk_j;
    XSGS_USER_DB_ENTRY *udbe_i, *udbe_j;
    XSGS_REVOKE_PHASE1* rpd1;
    XSGS_REVOKE_PHASE2* rpd2;
    clock_t start_time, end_time;
    BYTE* data;


    // join 2 test users
    xsgs_user_join_offline(gpk, ik, &ucert_i, &uk_i, &udbe_i, "key_store/test-2048.key");
    xsgs_user_join_offline(gpk, ik, &ucert_j, &uk_j, &udbe_j, "key_store/test-2048.key");

    // copy gpk
	xsgs_gpk_export_buf(&data, gpk);
	XSGS_PUBLIC_KEY* gpk_tmp1 = xsgs_gpk_import_buf(data);
	XSGS_PUBLIC_KEY* gpk_tmp2 = xsgs_gpk_import_buf(data);
	free(data);

    printf("\nXSGS REVOCATION - BENCHMARK:\n");

    // revoke user and update gpk
    printf("Phase 1: ");
    start_time = clock();
    xsgs_user_revoke_phase1(gpk_tmp1, ik, udbe_j, &rpd1);
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, 1);

    // user generate new user cert and sign it
    printf("Phase 2: ");
    start_time = clock();
    xsgs_user_revoke_phase2(gpk_tmp2, uk_i, ucert_i, "key_store/test-2048.key", rpd1, &rpd2);
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, 1);


    // group manager generate new user cert
    printf("Phase 3: ");
    start_time = clock();
    xsgs_user_revoke_phase3(gpk_tmp1, ik, udbe_i, "cert_store/test-2048.pem", rpd1, rpd2);
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, 1);

    rpd1_clear(rpd1);
    rpd2_clear(rpd2);
    ucert_clear(ucert_i);
    ucert_clear(ucert_j);
    uk_clear(uk_i);
    uk_clear(uk_j);
    udbe_clear(udbe_i);
    udbe_clear(udbe_j);
    gpk_clear(gpk_tmp1);
    gpk_clear(gpk_tmp2);

    return;
}

int xsgs_bench(void) {
    XSGS_PUBLIC_KEY* gpk;
    XSGS_ISSUER_KEY* ik;
    XSGS_OPENER_KEY* ok;
    XSGS_PAILLIER_PUBKEY* ppk;
    XSGS_USER_CERT* ucert;
    XSGS_USER_KEY* uk;
    XSGS_USER_DB_ENTRY* udbe;
    DWORD count = 0, size = 0, cache_ctl = 0, ret;
    pbc_param_ptr param = NULL;

    printf("\n\n+++ eXtremely Short Group Signature - System Benchmark +++\n\n");

    param = xsgs_select_curve_param("curves/", "xsgs_curve_", 11);
	if(param == NULL) {
		return 1;
	}

	// group public key generation
	gpk = (XSGS_PUBLIC_KEY*) malloc(sizeof(XSGS_PUBLIC_KEY));
	ik = (XSGS_ISSUER_KEY*) malloc(sizeof(XSGS_ISSUER_KEY));
	xsgs_gm_gen(gpk, ik, param);

	// group manager key generation
	ok = (XSGS_OPENER_KEY*) malloc(sizeof(XSGS_OPENER_KEY));
	xsgs_opener_gen(gpk, ok);

    // paillier public key generation
	ppk = xsgs_paillier_gen(PAILLIER_MODULO_BITS);

    // benchmark implementation
    xsgs_join_bench(gpk, ik, ppk, &ucert, &uk, &udbe, "test-2048", "test-2048");

    // parameter input
    printf("\nEnter message size in bytes: ");
    ret = scanf("%u", &size);
    printf("Enter count of sign/verify: ");
    ret = scanf("%u", &count);

    printf("Caching [0/1]: ");
    ret = scanf("%u", &cache_ctl);

    xsgs_signature_bench(gpk, ucert, uk, ok, udbe, size, count, cache_ctl, "test-2048");
    xsgs_batch_signature_bench(gpk, ucert, uk, ok, udbe, size, count, cache_ctl, "test-2048");

    xsgs_revocation_bench(gpk, ik);

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
