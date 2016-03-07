#include <string.h>
#include <time.h>
#include <errno.h>
#include "xsgs.h"
#include "xsgs_eval.h"


#define GET_BENCH_TIME(begin, end, cnt) (((double) (end - begin))/CLOCKS_PER_SEC*1000/cnt)
#define PRINT_BENCH_TIME(begin, end, cnt) printf("%.3f ms\n", GET_BENCH_TIME(begin, end, cnt))


int xsgs_signature_eval(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, DWORD msg_len, DWORD list_size, FILE* fp) {
    XSGS_SIGNED_MSG** sig_list = (XSGS_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_SIGNED_MSG*));
    BYTE* sig_status = (BYTE*) malloc(list_size);
    clock_t start_time, end_time;
    DWORD buf_len = 0, i = 0;
    char buf[512];


    printf("\nXSGS SIGNATURE - EVALUATION:\n");
    printf("[msg_len = %d, list_size = %d, SHA3: %d bit]\n", msg_len, list_size, SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
    buf_len = snprintf(buf, 512, "%u, %u, ", msg_len, list_size);

    for(i=0; i < list_size; i++) {
		sig_list[i] = (XSGS_SIGNED_MSG*) malloc(sizeof(XSGS_SIGNED_MSG));
		sig_list[i]->msg_len = msg_len;
		sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
		get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
	}

    // sign
    printf("SIGN: ");
    start_time = clock();
    for(i=0; i<list_size; i++) {
	xsgs_sign_cache(gpk, ucert, uk, cache, sig_list[i]);
    }
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, list_size);
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));

    // verify
    printf("VERIFY: ");
    start_time = clock();
    for(i=0; i<list_size; i++) {
	sig_status[i] = xsgs_verify(gpk, sig_list[i]);
    }
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, list_size);
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(start_time, end_time, list_size));
    for(i=0; i<list_size; i++) {
	if(!sig_status[i]) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");


    for(i=0; i<list_size; i++) {
	sm_clear(sig_list[i]);
    }
    free(sig_list);
    free(sig_status);

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_batch_signature_eval(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, DWORD msg_len, DWORD list_size, FILE* fp) {
    XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_BATCH_SIGNED_MSG*));
    BYTE* sig_status = (BYTE*) malloc(list_size);
    clock_t start_time, end_time;
    DWORD buf_len = 0, i;
    char buf[512];


    printf("\nXSGS BATCH SIGNATURE - EVALUATION:\n");
    printf("[msg_len = %d, list_size = %d, SHA3: %d bit]\n", msg_len, list_size, SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
    buf_len = snprintf(buf, 512, "%u, %u, ", msg_len, list_size);

    for(i=0; i < list_size; i++) {
		sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
		sig_list[i]->msg_len = msg_len;
		sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
		get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
	}

    // sign
    printf("SIGN: ");
    start_time = clock();
    xsgs_batch_sign_cache(gpk, ucert, uk, cache, sig_list, list_size);
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, list_size);
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));

    // verify
    printf("VERIFY: ");
    start_time = clock();
    xsgs_batch_verify(gpk, sig_list, list_size, sig_status);
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, list_size);
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(start_time, end_time, list_size));
    for(i=0; i<list_size; i++) {
	if(!sig_status[i]) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");

    for(i=0; i<list_size; i++) {
	bsm_clear(sig_list[i]);
    }
    free(sig_list);
    free(sig_status);

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_batch_sign_eval(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, DWORD msg_len, DWORD list_size, FILE* fp) {
    XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_BATCH_SIGNED_MSG*));
    clock_t start_time, end_time;
    DWORD buf_len = 0, i;
    char buf[512];


    printf("\nXSGS BATCH SIGN - EVALUATION:\n");
    printf("[msg_len = %d, list_size = %d, SHA3: %d bit]\n", msg_len, list_size, BATCH_SIGNATURE_HASH_BITS);


    memset(buf, 0, 512);
    buf_len = snprintf(buf, 512, "%u, %u, ", msg_len, list_size);

    for(i=0; i < list_size; i++) {
		sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
		sig_list[i]->msg_len = msg_len;
		sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
		get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
	}

    // sign
    printf("SIGN: ");
    start_time = clock();
    xsgs_batch_sign(gpk, ucert, uk, sig_list, list_size);
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, list_size);
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(start_time, end_time, list_size));

    for(i=0; i<list_size; i++) {
	bsm_clear(sig_list[i]);
    }
    free(sig_list);

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_sign_eval1(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, DWORD msg_len, DWORD avg_count, DWORD list_size, FILE* fp) {
	XSGS_SIGNED_MSG** sig_list = (XSGS_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_SIGNED_MSG*));
    clock_t start_time, end_time, all_time;
    DWORD buf_len = 0, i, j;
    char buf[512];


    printf("\nXSGS SIGN - EVALUATION:\n");
    printf("[msg_len = %u, Signatures = %u, F_q: %u bit, SHA3: %u bit]\n", msg_len, list_size, (DWORD)mpz_sizeinbase(gpk->pairing->r, 2), SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
    buf_len = snprintf(buf, 512, "%u, ", msg_len);

    for(j=0, all_time=0; j<avg_count; j++) {
	// init random messages
		for(i=0; i < list_size; i++) {
			sig_list[i] = (XSGS_SIGNED_MSG*) malloc(sizeof(XSGS_SIGNED_MSG));
			sig_list[i]->msg_len = msg_len;
			sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
			get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
		}

		// sign
		printf("Sign: ");
		start_time = clock();
		for(i=0; i<list_size; i++) {
			xsgs_sign_cache(gpk, ucert, uk, cache, sig_list[i]);
		}
		end_time = clock();
		printf("%.3f ms/sign\n", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));
		all_time += end_time - start_time;

		for(i=0; i<list_size; i++) {
			sm_clear(sig_list[i]);
		}
    }
    free(sig_list);

    printf("Average: %.3f ms/sign\n", GET_BENCH_TIME(0, all_time, (avg_count*list_size)));
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(0, all_time, (avg_count*list_size)));

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_sign_eval2(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, DWORD msg_len, DWORD avg_count, DWORD list_size, FILE* fp) {
	XSGS_SIGNED_MSG** sig_list = (XSGS_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_SIGNED_MSG*));
    clock_t start_time, end_time, all_time;
    DWORD buf_len = 0, i, j;
    char buf[512];


    printf("\nXSGS SIGN - EVALUATION:\n");
    printf("[msg_len = %u, Signatures = %u, F_q: %u bit, SHA3: %u bit]\n", msg_len, list_size, (DWORD)mpz_sizeinbase(gpk->pairing->r, 2), SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
    buf_len = snprintf(buf, 512, "%u, ", list_size);

    for(j=0, all_time=0; j<avg_count; j++) {
	// init random messages
		for(i=0; i < list_size; i++) {
			sig_list[i] = (XSGS_SIGNED_MSG*) malloc(sizeof(XSGS_SIGNED_MSG));
			sig_list[i]->msg_len = msg_len;
			sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
			get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
		}

		// sign
		printf("Sign: ");
		start_time = clock();
		for(i=0; i<list_size; i++) {
			xsgs_sign_cache(gpk, ucert, uk, cache, sig_list[i]);
		}
		end_time = clock();
		printf("%.1f ms\n", GET_BENCH_TIME(start_time, end_time, 1));
		buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.1f, ", GET_BENCH_TIME(start_time, end_time, 1));
		all_time += end_time - start_time;

		// free signatures
		for(i=0; i<list_size; i++) {
			sm_clear(sig_list[i]);
		}
    }
    free(sig_list);
    printf("Average: %.3f ms\n", GET_BENCH_TIME(0, all_time, avg_count));
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(0, all_time, avg_count));

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_batch_sign_eval2(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, DWORD msg_len, DWORD avg_count, DWORD list_size, FILE* fp) {
    XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_BATCH_SIGNED_MSG*));
    clock_t start_time, end_time, all_time;
    DWORD buf_len = 0, i, j;
    char buf[512];


    printf("\nXSGS BATCH SIGN - EVALUATION:\n");
    printf("[msg_len = %u, Signatures = %u, F_q: %u bit, SHA3: %u bit]\n", msg_len, list_size, (DWORD)mpz_sizeinbase(gpk->pairing->r, 2), BATCH_SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
    buf_len = snprintf(buf, 512, "%u, ", list_size);

    for(j=0, all_time=0; j<avg_count; j++) {
	// init random messages
		for(i=0; i < list_size; i++) {
			sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
			sig_list[i]->msg_len = msg_len;
			sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
			get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
		}

		// sign
		printf("Batch Sign: ");
		start_time = clock();
		xsgs_batch_sign_cache(gpk, ucert, uk, cache, sig_list, list_size);
		end_time = clock();
		printf("%.1f ms\n", GET_BENCH_TIME(start_time, end_time, 1));
		buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.1f, ", GET_BENCH_TIME(start_time, end_time, 1));
		all_time += end_time - start_time;

		for(i=0; i<list_size; i++) {
			bsm_clear(sig_list[i]);
		}
    }
    free(sig_list);
    printf("Average: %.3f ms\n", GET_BENCH_TIME(0, all_time, avg_count));
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(0, all_time, avg_count));

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_batch_verify_eval(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, FILE* fp) {
    BYTE* sig_status = (BYTE*) malloc(list_size);
    clock_t start_time, end_time;
    DWORD buf_len = 0, i;
    char buf[512];


    printf("\nXSGS BATCH VERIFY - EVALUATION:\n");
    printf("[msg_len = %d, list_size = %d, SHA3: %d bit]\n", sig_list[0]->msg_len, list_size, SIGNATURE_HASH_BITS);

    // verify
    printf("VERIFY: ");
    start_time = clock();
    xsgs_batch_verify(gpk, sig_list, list_size, sig_status);
    end_time = clock();
    PRINT_BENCH_TIME(start_time, end_time, list_size);
    memset(buf, 0, 512);
    buf_len = snprintf(buf, 512, "%u, %u, %.3f\n", sig_list[0]->msg_len, list_size, GET_BENCH_TIME(start_time, end_time, list_size));
    for(i=0; i<list_size; i++) {
	if(!sig_status[i]) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");

    free(sig_status);

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_verify_eval2(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, DWORD msg_len, DWORD avg_count, DWORD list_size, FILE* fp) {
	XSGS_SIGNED_MSG** sig_list = (XSGS_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_SIGNED_MSG*));
	BYTE* sig_status = (BYTE*) malloc(list_size);
    clock_t start_time, end_time, all_time;
    DWORD buf_len = 0, i, j;
    char buf[512];


    printf("\nXSGS VERIFY - EVALUATION:\n");
    printf("[msg_len = %u, Signatures = %u, F_q: %u bit, SHA3: %u bit]\n", msg_len, list_size, (DWORD)mpz_sizeinbase(gpk->pairing->r, 2), SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
	buf_len = snprintf(buf, 512, "%u, ", list_size);

    for(j=0, all_time=0; j<avg_count; j++) {
	// initialize random signatures
		for(i=0; i<list_size; i++) {
			sig_list[i] = (XSGS_SIGNED_MSG*) malloc(sizeof(XSGS_SIGNED_MSG));
			sig_list[i]->msg_len = msg_len;
			sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
			get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
			xsgs_sign_cache(gpk, ucert, uk, cache, sig_list[i]);
		}

		// verify
		printf("Verify: ");
		start_time = clock();
		for(i=0; i<list_size; i++) {
			sig_status[i] = xsgs_verify_cache(gpk, cache, sig_list[i]);
		}
		end_time = clock();
		printf("%.1f ms\n", GET_BENCH_TIME(start_time, end_time, 1));
		buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.1f, ", GET_BENCH_TIME(start_time, end_time, 1));
		all_time += end_time - start_time;
		for(i=0; i<list_size; i++) {
			if(!sig_status[i]) {
				printf("[%04u-failed]\n", i);
			}
		}

		// free signature list
		for(i=0; i<list_size; i++) {
			sm_clear(sig_list[i]);
		}
    }
    free(sig_list);
    free(sig_status);

    printf("Average: %.3f ms\n", GET_BENCH_TIME(0, all_time, avg_count));
	buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(0, all_time, avg_count));

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_batch_verify_eval2(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, DWORD msg_len, DWORD avg_count, DWORD list_size, FILE* fp) {
	XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(list_size*sizeof(XSGS_BATCH_SIGNED_MSG*));
	BYTE* sig_status = (BYTE*) malloc(list_size);
    clock_t start_time, end_time, all_time;
    DWORD buf_len = 0, i, j;
    char buf[512];


    printf("\nXSGS BATCH VERIFY - EVALUATION:\n");
    printf("[msg_len = %u, Signatures = %u, F_q: %u bit, SHA3: %u bit]\n", msg_len, list_size, (DWORD)mpz_sizeinbase(gpk->pairing->r, 2), BATCH_SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
	buf_len = snprintf(buf, 512, "%u, ", list_size);

    for(j=0, all_time=0; j<avg_count; j++) {
	// initialize random signatures
		for(i=0; i<list_size; i++) {
			sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
			sig_list[i]->msg_len = msg_len;
			sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
			get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
		}
		xsgs_batch_sign_cache(gpk, ucert, uk, cache, sig_list, list_size);

		// verify
		printf("Batch Verify: ");
		start_time = clock();
		xsgs_batch_verify_cache(gpk, cache, sig_list, list_size, sig_status);
		end_time = clock();
		printf("%.1f ms\n", GET_BENCH_TIME(start_time, end_time, 1));
		buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.1f, ", GET_BENCH_TIME(start_time, end_time, 1));
		all_time += end_time - start_time;
		for(i=0; i<list_size; i++) {
			if(!sig_status[i]) {
				printf("[%04u-failed]\n", i);
			}
		}

		// free signature list
		for(i=0; i<list_size; i++) {
			bsm_clear(sig_list[i]);
		}
    }
    free(sig_list);
    free(sig_status);

    printf("Average: %.3f ms\n", GET_BENCH_TIME(0, all_time, avg_count));
	buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(0, all_time, avg_count));

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_batch_open_judge_eval(XSGS_PUBLIC_KEY* gpk, XSGS_OPENER_KEY* ok, XSGS_USER_DB_ENTRY* udbe, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, char* rsa_cert_name, FILE* fp) {
    clock_t start_time, end_time;
    DWORD buf_len = 0, i;
    char pem_filename[1024];
    char buf[512];
    BYTE* sig_status = (BYTE*) malloc(list_size);
    XSGS_OPEN_DATA** od_list = (XSGS_OPEN_DATA**) malloc(list_size*sizeof(XSGS_OPEN_DATA*));


    memset(pem_filename, 0, 1024);
    sprintf(pem_filename, "cert_store/%s.pem", rsa_cert_name);

    printf("\nXSGS OPEN, JUDGE - EVALUATION:\n");
    printf("[msg_len = %d, list_size = %d, RSA: %d bit, SHA3: %d bit]\n", sig_list[0]->msg_len, list_size, xsgs_rsa_get_size(pem_filename, RSA_PUB_KEY), BATCH_SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
    buf_len = snprintf(buf, 512, "%u, %u, %u, ", sig_list[0]->msg_len, list_size, xsgs_rsa_get_size(pem_filename, RSA_PUB_KEY));

    // open
    printf("OPEN: ");
    start_time = clock();
    for(i=0; i<list_size; i++) {
	od_list[i] = xsgs_open_batch_sig(gpk, ok, sig_list[i]);

	// find the actual signer, using the read-access to the registration table
	od_list[i]->S.len = udbe->S.len;
	od_list[i]->S.sig = (BYTE*) malloc(od_list[i]->S.len);
	memcpy(od_list[i]->S.sig, udbe->S.sig, od_list[i]->S.len);
	//printf("*TODO* get RSA signature S of xsgs signer A from registration database *TODO*\n");
    }
    end_time = clock();
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, list_size));
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));
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
    printf("%.3f ms ", GET_BENCH_TIME(start_time, end_time, list_size));
    buf_len += snprintf(&buf[buf_len], 512-buf_len, "%.3f\n", GET_BENCH_TIME(start_time, end_time, list_size));
    for(i=0; i<list_size; i++) {
	if(!sig_status[i]) {
	    printf("[%04d-failed] ", i);
	}
    }
    printf("\n");

    for(i=0; i<list_size; i++) {
	od_clear(od_list[i]);
    }
    free(od_list);
    free(sig_status);

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

int xsgs_batch_open_judge_eval2(XSGS_PUBLIC_KEY* gpk, XSGS_OPENER_KEY* ok, XSGS_USER_DB_ENTRY* udbe, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD avg_count, DWORD list_size, char* rsa_cert_name, FILE* fp) {
    clock_t start_time, end_time, all_open_time, all_judge_time;
    DWORD buf_len = 0, i, j;
    char pem_filename[1024];
    char buf[512];
    BYTE* sig_status = (BYTE*) malloc(list_size);
    XSGS_OPEN_DATA** od_list = (XSGS_OPEN_DATA**) malloc(list_size*sizeof(XSGS_OPEN_DATA*));


    memset(pem_filename, 0, 512);
    sprintf(pem_filename, "cert_store/%s.pem", rsa_cert_name);

    printf("\nXSGS OPEN, JUDGE - EVALUATION:\n");
    printf("[msg_len = %u, Signatures = %u, RSA: %u bit, SHA3: %u bit]\n", sig_list[0]->msg_len, list_size, xsgs_rsa_get_size(pem_filename, RSA_PUB_KEY), BATCH_SIGNATURE_HASH_BITS);

    memset(buf, 0, 512);
    buf_len = snprintf(buf, 511, "%u, %u, %u, ", sig_list[0]->msg_len, list_size, xsgs_rsa_get_size(pem_filename, RSA_PUB_KEY));

    for(j=0, all_open_time=0, all_judge_time=0; j<avg_count; j++) {
		// open
		printf("Open: ");
		start_time = clock();
		for(i=0; i<list_size; i++) {
			od_list[i] = xsgs_open_batch_sig(gpk, ok, sig_list[i]);

			// find the actual signer, using the read-access to the registration table
			od_list[i]->S.len = udbe->S.len;
			od_list[i]->S.sig = (BYTE*) malloc(od_list[i]->S.len);
			memcpy(od_list[i]->S.sig, udbe->S.sig, od_list[i]->S.len);
			//printf("*TODO* get RSA signature S of xsgs signer A from registration database *TODO*\n");
		}
		end_time = clock();
		all_open_time += end_time -start_time;
		printf("%.3f ms/open ", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));
		for(i=0; i<list_size; i++) {
			if(od_list[i] == NULL) {
				printf("[%04d-failed] ", i);
			}
		}
		printf("\n");

		// judge
		printf("Judge: ");
		start_time = clock();
		for(i=0; i<list_size; i++) {
			sig_status[i] = !xsgs_judge_batch_sig(gpk, sig_list[i], od_list[i], pem_filename);
		}
		end_time = clock();
		all_judge_time += end_time -start_time;
		printf("%.3f ms/judge ", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f\n", GET_BENCH_TIME(start_time, end_time, list_size));
		for(i=0; i<list_size; i++) {
			if(!sig_status[i]) {
				printf("[%04d-failed] ", i);
			}
		}
		printf("\n");

		for(i=0; i<list_size; i++) {
			od_clear(od_list[i]);
		}
    }
    free(od_list);
    free(sig_status);

    printf("\nAverage Open: %.3f ms/open\n", GET_BENCH_TIME(0, all_open_time, (avg_count*list_size)));
	buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f\n", GET_BENCH_TIME(0, all_open_time, (avg_count*list_size)));

	printf("Average Judge: %.3f ms/judge\n", GET_BENCH_TIME(0, all_judge_time, (avg_count*list_size)));
	buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f\n", GET_BENCH_TIME(0, all_judge_time, (avg_count*list_size)));

    fwrite(buf, 1, buf_len, fp);
    fflush(fp);

    return 0;
}

void xsgs_join_cs_eval(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_PAILLIER_PUBKEY* ppk, char* rsa_cert_name, char* rsa_key_name, DWORD avg_count, DWORD list_size, FILE* fp) {
    clock_t start_time, end_time, all_cs_time, all_time;
    int ret;
    char cert_filename[256];
    char key_filename[256];
    DWORD buf_len = 0, i, j;
    char buf[512];

	XSGS_USER_CERT** ucert_list = (XSGS_USER_CERT**) malloc(list_size*sizeof(XSGS_USER_CERT*));
	XSGS_USER_KEY** uk_list = (XSGS_USER_KEY**) malloc(list_size*sizeof(XSGS_USER_KEY*));
	XSGS_USER_DB_ENTRY** udbe_list = (XSGS_USER_DB_ENTRY**) malloc(list_size*sizeof(XSGS_USER_DB_ENTRY*));
	XSGS_JOIN_PHASE1** jpd1_list = (XSGS_JOIN_PHASE1**) malloc(list_size*sizeof(XSGS_JOIN_PHASE1*));
	XSGS_JOIN_PHASE2** jpd2_list = (XSGS_JOIN_PHASE2**) malloc(list_size*sizeof(XSGS_JOIN_PHASE2*));
	XSGS_JOIN_PHASE3** jpd3_list = (XSGS_JOIN_PHASE3**) malloc(list_size*sizeof(XSGS_JOIN_PHASE3*));
	XSGS_JOIN_PHASE4** jpd4_list = (XSGS_JOIN_PHASE4**) malloc(list_size*sizeof(XSGS_JOIN_PHASE4*));

    memset(cert_filename, 0, 256);
    snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

    memset(key_filename, 0, 256);
    snprintf(key_filename, 255, "key_store/%s.key", rsa_key_name);

    memset(buf, 0, 512);
	buf_len = snprintf(buf, 511, "%u, ", list_size);

    for(j=0, all_time=0; j<avg_count; j++) {
	// init lists
	for(i=0; i<list_size; i++) {
			ucert_list[i] = (XSGS_USER_CERT*) malloc(sizeof(XSGS_USER_CERT));
			uk_list[i] = (XSGS_USER_KEY*) malloc(sizeof(XSGS_USER_KEY));
			udbe_list[i] = (XSGS_USER_DB_ENTRY*) malloc(sizeof(XSGS_USER_DB_ENTRY));
			jpd1_list[i] = (XSGS_JOIN_PHASE1*) malloc(sizeof(XSGS_JOIN_PHASE1));
			jpd2_list[i] = (XSGS_JOIN_PHASE2*) malloc(sizeof(XSGS_JOIN_PHASE2));
			jpd3_list[i] = (XSGS_JOIN_PHASE3*) malloc(sizeof(XSGS_JOIN_PHASE3));
			jpd4_list[i] = (XSGS_JOIN_PHASE4*) malloc(sizeof(XSGS_JOIN_PHASE4));
	}

		printf("\nXSGS JOIN USER - EVALUATION:\n");
		printf("[Users: %u, F_q: %u bit, Paillier: %u bit, RSA: %u bit, SHA3: %u bit]\n", list_size, (DWORD)mpz_sizeinbase(gpk->pairing->r, 2), (DWORD)mpz_sizeinbase(ppk->n, 2), xsgs_rsa_get_size(key_filename, RSA_PRV_KEY), JOIN_HASH_BITS);

		printf("Phase 1 (CS): ");
		start_time = clock();
		for(i=0; i<list_size; i++) {
			xsgs_user_join_phase1(gpk, uk_list[i], ppk, jpd1_list[i]);
		}
		end_time = clock();
		printf("%.3f ms/user\n", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));
		all_cs_time = end_time - start_time;

		// phase 2 (ch)
		for(i=0, ret=0; i<list_size; i++) {
			ret += xsgs_user_join_phase2(gpk, udbe_list[i], ik, ppk, jpd1_list[i], jpd2_list[i]);
		}
		if(ret) {
			printf("Phase 2 (BE): [failed]\n");
		}

		printf("Phase 3 (CS): ");
		start_time = clock();
		for(i=0, ret=0; i<list_size; i++) {
			ret += xsgs_user_join_phase3(gpk, ucert_list[i], jpd1_list[i], jpd2_list[i], jpd3_list[i], key_filename);
		}
		end_time = clock();
		if(ret)  {
			printf("[failed] ");
		}
		printf("%.3f ms/user\n", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));
		all_cs_time += end_time - start_time;

		// phase 4 (ch)
		for(i=0, ret=0; i<list_size; i++) {
			ret += xsgs_user_join_phase4(gpk, udbe_list[i], jpd3_list[i], jpd4_list[i], cert_filename);
		}
		if(ret) {
			printf("PHASE 4 (BE): [failed]\n");
		}

		printf("Phase 5 (CS): ");
		start_time = clock();
		for(i=0, ret=0; i<list_size; i++) {
			ret += xsgs_user_join_phase5(gpk, ucert_list[i], uk_list[i], jpd4_list[i]);
		}
		end_time = clock();
		if(ret)  {
			printf("[failed] ");
		}
		printf("%.3f ms/user\n", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));
		all_cs_time += end_time - start_time;

		printf("Join a User (CS): %.3f ms\n", GET_BENCH_TIME(0, all_cs_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.1f, ", GET_BENCH_TIME(0, all_cs_time, list_size));

		for(i=0, ret=0; i<list_size; i++) {
			jpd1_clear(jpd1_list[i]);
			jpd2_clear(jpd2_list[i]);
			jpd3_clear(jpd3_list[i]);
			jpd4_clear(jpd4_list[i]);
			ucert_clear(ucert_list[i]);
			uk_clear(uk_list[i]);
			udbe_clear(udbe_list[i]);
		}

		all_time += all_cs_time;
    }
    free(jpd1_list);
    free(jpd2_list);
    free(jpd3_list);
    free(jpd4_list);
    free(ucert_list);
    free(uk_list);
    free(udbe_list);

    printf("\nAverage Join a User (CS): %.3f ms\n", GET_BENCH_TIME(0, all_time, (avg_count*list_size)));
    buf_len += snprintf(&buf[buf_len], 1023-buf_len, "%.3f\n", GET_BENCH_TIME(0, all_time, (avg_count*list_size)));

    fwrite(buf, 1, buf_len, fp);
	fflush(fp);

    return;
}

void xsgs_join_ch_eval(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_PAILLIER_PUBKEY* ppk, char* rsa_cert_name, char* rsa_key_name, DWORD avg_count, DWORD list_size, FILE* fp) {
    clock_t start_time, end_time, all_ch_time, all_time;
    int ret;
    char cert_filename[256];
    char key_filename[256];
    DWORD buf_len = 0, i, j;
    char buf[512];

    XSGS_USER_CERT** ucert_list = (XSGS_USER_CERT**) malloc(list_size*sizeof(XSGS_USER_CERT*));
	XSGS_USER_KEY** uk_list = (XSGS_USER_KEY**) malloc(list_size*sizeof(XSGS_USER_KEY*));
	XSGS_USER_DB_ENTRY** udbe_list = (XSGS_USER_DB_ENTRY**) malloc(list_size*sizeof(XSGS_USER_DB_ENTRY*));
	XSGS_JOIN_PHASE1** jpd1_list = (XSGS_JOIN_PHASE1**) malloc(list_size*sizeof(XSGS_JOIN_PHASE1*));
	XSGS_JOIN_PHASE2** jpd2_list = (XSGS_JOIN_PHASE2**) malloc(list_size*sizeof(XSGS_JOIN_PHASE2*));
	XSGS_JOIN_PHASE3** jpd3_list = (XSGS_JOIN_PHASE3**) malloc(list_size*sizeof(XSGS_JOIN_PHASE3*));
	XSGS_JOIN_PHASE4** jpd4_list = (XSGS_JOIN_PHASE4**) malloc(list_size*sizeof(XSGS_JOIN_PHASE4*));

    memset(cert_filename, 0, 256);
    snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

    memset(key_filename, 0, 256);
    snprintf(key_filename, 255, "key_store/%s.key", rsa_key_name);

    memset(buf, 0, 512);
	buf_len = snprintf(buf, 511, "%u, ", list_size);

    for(j=0, all_time=0; j<avg_count; j++) {
	// init lists
		for(i=0; i<list_size; i++) {
			ucert_list[i] = (XSGS_USER_CERT*) malloc(sizeof(XSGS_USER_CERT));
			uk_list[i] = (XSGS_USER_KEY*) malloc(sizeof(XSGS_USER_KEY));
			udbe_list[i] = (XSGS_USER_DB_ENTRY*) malloc(sizeof(XSGS_USER_DB_ENTRY));
			jpd1_list[i] = (XSGS_JOIN_PHASE1*) malloc(sizeof(XSGS_JOIN_PHASE1));
			jpd2_list[i] = (XSGS_JOIN_PHASE2*) malloc(sizeof(XSGS_JOIN_PHASE2));
			jpd3_list[i] = (XSGS_JOIN_PHASE3*) malloc(sizeof(XSGS_JOIN_PHASE3));
			jpd4_list[i] = (XSGS_JOIN_PHASE4*) malloc(sizeof(XSGS_JOIN_PHASE4));
		}

		printf("\nXSGS JOIN USER - EVALUATION:\n");
		printf("[Users: %u, F_q: %u bit, Paillier: %u bit, RSA: %u bit, SHA3: %u bit]\n", list_size, (DWORD)mpz_sizeinbase(gpk->pairing->r, 2), (DWORD)mpz_sizeinbase(ppk->n, 2), xsgs_rsa_get_size(key_filename, RSA_PRV_KEY), JOIN_HASH_BITS);

		for(i=0; i<list_size; i++) {
			xsgs_user_join_phase1(gpk, uk_list[i], ppk, jpd1_list[i]);
		}

		printf("Phase 2 (CH): ");
		start_time = clock();
		for(i=0, ret=0; i<list_size; i++) {
			ret += xsgs_user_join_phase2(gpk, udbe_list[i], ik, ppk, jpd1_list[i], jpd2_list[i]);
		}
		end_time = clock();
		if(ret)  {
			printf("[failed] ");
		}
		printf("%.3f ms/user\n", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));
		all_ch_time = end_time - start_time;

		// phase 3 (cs)
		for(i=0, ret=0; i<list_size; i++) {
			ret += xsgs_user_join_phase3(gpk, ucert_list[i], jpd1_list[i], jpd2_list[i], jpd3_list[i], key_filename);
		}
		if(ret) {
			printf("Phase 3 (CS): [failed]\n");
		}

		printf("Phase 4 (CH): ");
		start_time = clock();
		for(i=0, ret=0; i<list_size; i++) {
			ret += xsgs_user_join_phase4(gpk, udbe_list[i], jpd3_list[i], jpd4_list[i], cert_filename);
		}
		end_time = clock();
		if(ret)  {
			printf("[failed] ");
		}
		printf("%.3f ms/user\n", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));
		all_ch_time += end_time - start_time;

		// phase 5 (cs)
		for(i=0, ret=0; i<list_size; i++) {
			ret += xsgs_user_join_phase5(gpk, ucert_list[i], uk_list[i], jpd4_list[i]);
		}
		if(ret) {
			printf("Phase 5 (CH): [failed]\n");
		}

		printf("Join a User (CH): %.1f ms\n", GET_BENCH_TIME(0, all_ch_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.1f, ", GET_BENCH_TIME(0, all_ch_time, list_size));
		all_time += all_ch_time;

		for(i=0; i<list_size; i++) {
			jpd1_clear(jpd1_list[i]);
			jpd2_clear(jpd2_list[i]);
			jpd3_clear(jpd3_list[i]);
			jpd4_clear(jpd4_list[i]);
			ucert_clear(ucert_list[i]);
			uk_clear(uk_list[i]);
			udbe_clear(udbe_list[i]);
		}
    }
    free(jpd1_list);
	free(jpd2_list);
	free(jpd3_list);
	free(jpd4_list);
	free(ucert_list);
	free(uk_list);
	free(udbe_list);

    printf("\nAverage Join a User (CH): %.3f ms\n", GET_BENCH_TIME(0, all_time, (avg_count*list_size)));
    buf_len += snprintf(&buf[buf_len], 1023-buf_len, "%.3f, ", GET_BENCH_TIME(0, all_time, (avg_count*list_size)));

    fwrite(buf, 1, buf_len, fp);
	fflush(fp);

    return;
}

void xsgs_revoke_cs_eval(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, DWORD avg_count, DWORD list_size, char* rsa_key_name, FILE* fp) {
	clock_t start_time, end_time, all_cs_time;
	char key_filename[256];
	DWORD buf_len = 0, i, j;
	char buf[512];
	BYTE* data;
	XSGS_REVOKE_PHASE1* rpd1;


	XSGS_REVOKE_PHASE2** rpd2_list = (XSGS_REVOKE_PHASE2**) malloc(list_size*sizeof(XSGS_REVOKE_PHASE2*));
	XSGS_PUBLIC_KEY** gpk_list = (XSGS_PUBLIC_KEY**) malloc((list_size+1)*sizeof(XSGS_PUBLIC_KEY*));
	XSGS_USER_CERT** ucert_list = (XSGS_USER_CERT**) malloc((list_size+1)*sizeof(XSGS_USER_CERT*));
	XSGS_USER_KEY** uk_list = (XSGS_USER_KEY**) malloc((list_size+1)*sizeof(XSGS_USER_KEY*));
	XSGS_USER_DB_ENTRY** udbe_list = (XSGS_USER_DB_ENTRY**) malloc((list_size+1)*sizeof(XSGS_USER_DB_ENTRY*));

	memset(key_filename, 0, 256);
	snprintf(key_filename, 255, "key_store/%s.key", rsa_key_name);

	memset(buf, 0, 512);
	buf_len = snprintf(buf, 511, "%u, ", list_size);

	xsgs_gpk_export_buf(&data, gpk);

	for(j=0, all_cs_time=0; j<avg_count; j++) {
		// join test users
		for(i=0; i<(list_size+1); i++) {
			xsgs_user_join_offline(gpk, ik, &ucert_list[i], &uk_list[i], &udbe_list[i], key_filename);
			gpk_list[i] = xsgs_gpk_import_buf(data);
		}

		printf("\nXSGS REVOCATION - EVALUATION:\n");
		printf("[Users in DB = %u]\n", list_size);

		xsgs_user_revoke_phase1(gpk_list[list_size], ik, udbe_list[list_size], &rpd1);

		printf("Phase 2 (CS): ");
		start_time = clock();
		for(i=0; i<list_size; i++) {
			xsgs_user_revoke_phase2(gpk_list[i], uk_list[i], ucert_list[i], key_filename, rpd1, &rpd2_list[i]);
		}
		end_time = clock();
		all_cs_time += end_time - start_time;
		printf("%.3f ms\n", GET_BENCH_TIME(start_time, end_time, list_size));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(start_time, end_time, list_size));


		for(i=0; i<list_size+1; i++) {
			ucert_clear(ucert_list[i]);
			uk_clear(uk_list[i]);
			udbe_clear(udbe_list[i]);
			gpk_clear(gpk_list[i]);
		}
		rpd1_clear(rpd1);
		for(i=0; i<list_size; i++) {
			rpd2_clear(rpd2_list[i]);
		}
	}
	free(ucert_list);
	free(uk_list);
	free(udbe_list);
	free(rpd2_list);
	free(gpk_list);
	free(data);


	printf("\nAverage Revoke a User (CS): %.3f ms\n", GET_BENCH_TIME(0, all_cs_time, (avg_count*list_size)));
	buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(0, all_cs_time, (avg_count*list_size)));

	fwrite(buf, 1, buf_len, fp);
	fflush(fp);

	return;
}

void xsgs_revoke_ch_eval(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, DWORD avg_count, DWORD list_size, char* rsa_key_name, char* rsa_cert_name, FILE* fp) {
    clock_t start_time, end_time, all_ch_time, all_time;
    char key_filename[256], cert_filename[256];
    DWORD buf_len = 0, i, j;
	char buf[512];
	BYTE* data;
	XSGS_REVOKE_PHASE1* rpd1;


	XSGS_REVOKE_PHASE2** rpd2_list = (XSGS_REVOKE_PHASE2**) malloc(list_size*sizeof(XSGS_REVOKE_PHASE2*));
	XSGS_PUBLIC_KEY** gpk_list = (XSGS_PUBLIC_KEY**) malloc((list_size+1)*sizeof(XSGS_PUBLIC_KEY*));
    XSGS_USER_CERT** ucert_list = (XSGS_USER_CERT**) malloc((list_size+1)*sizeof(XSGS_USER_CERT*));
	XSGS_USER_KEY** uk_list = (XSGS_USER_KEY**) malloc((list_size+1)*sizeof(XSGS_USER_KEY*));
	XSGS_USER_DB_ENTRY** udbe_list = (XSGS_USER_DB_ENTRY**) malloc((list_size+1)*sizeof(XSGS_USER_DB_ENTRY*));

	memset(key_filename, 0, 256);
	snprintf(key_filename, 255, "key_store/%s.key", rsa_key_name);
	memset(cert_filename, 0, 256);
	snprintf(cert_filename, 255, "cert_store/%s.pem", rsa_cert_name);

	memset(buf, 0, 512);
	buf_len = snprintf(buf, 511, "%u, ", list_size);

	xsgs_gpk_export_buf(&data, gpk);

	for(j=0, all_time=0; j<avg_count; j++) {
		// join test users
		for(i=0; i<(list_size+1); i++) {
			xsgs_user_join_offline(gpk, ik, &ucert_list[i], &uk_list[i], &udbe_list[i], key_filename);
			gpk_list[i] = xsgs_gpk_import_buf(data);
		}

		printf("\nXSGS REVOCATION - EVALUATION:\n");
		printf("[Users in DB = %u]\n", list_size);

		printf("Phase 1 (CH): ");
		start_time = clock();
		xsgs_user_revoke_phase1(gpk_list[list_size], ik, udbe_list[list_size], &rpd1);
		end_time = clock();
		all_ch_time = end_time - start_time;
		printf("%.1f ms\n", GET_BENCH_TIME(start_time, end_time, 1));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.1f, ", GET_BENCH_TIME(start_time, end_time, 1));

		for(i=0; i<list_size; i++) {
			xsgs_user_revoke_phase2(gpk_list[i], uk_list[i], ucert_list[i], key_filename, rpd1, &rpd2_list[i]);
		}

		printf("Phase 3 (CH): ");
		start_time = clock();
		for(i=0; i<list_size; i++) {
			xsgs_user_revoke_phase3(gpk_list[list_size], ik, udbe_list[i], cert_filename, rpd1, rpd2_list[i]);
		}
		end_time = clock();
		all_ch_time += end_time - start_time;
		printf("%.1f ms\n", GET_BENCH_TIME(start_time, end_time, 1));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.1f, ", GET_BENCH_TIME(start_time, end_time, 1));

		printf("Revoke a User (CH): %.1f ms\n", GET_BENCH_TIME(0, all_ch_time, 1));
		buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.1f, ", GET_BENCH_TIME(0, all_ch_time, 1));
		all_time += all_ch_time;

		for(i=0; i<list_size+1; i++) {
			ucert_clear(ucert_list[i]);
			uk_clear(uk_list[i]);
			udbe_clear(udbe_list[i]);
			gpk_clear(gpk_list[i]);
		}
		rpd1_clear(rpd1);
		for(i=0; i<list_size; i++) {
			rpd2_clear(rpd2_list[i]);
		}
	}
    free(ucert_list);
    free(uk_list);
    free(udbe_list);
    free(rpd2_list);
    free(gpk_list);
    free(data);


    printf("\nAverage Revoke a User (CH): %.3f ms\n", GET_BENCH_TIME(0, all_time, avg_count));
	buf_len += snprintf(&buf[buf_len], 511-buf_len, "%.3f, ", GET_BENCH_TIME(0, all_time, avg_count));

	fwrite(buf, 1, buf_len, fp);
	fflush(fp);

    return;
}

int xsgs_eval(void) {
    XSGS_PUBLIC_KEY* gpk;
    XSGS_USER_CERT* ucert;
    XSGS_USER_KEY* uk;
    XSGS_OPENER_KEY* ok;
    XSGS_ISSUER_KEY* ik;
    XSGS_USER_DB_ENTRY* udbe;
    int ret = 0;
    DWORD static_size = 0, dynamic_start = 0, dynamic_end = 0, step = 0, size = 0, choice = 0;
    FILE* fp = NULL;
    char filename[257];
    XSGS_CACHE* cache;
    pbc_param_ptr param = NULL;


    printf("\n\n+++ eXtremely Short Group Signature - Evaluation +++\n");

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

	// join test user
	xsgs_user_join_offline(gpk, ik, &ucert, &uk, &udbe, "key_store/test-2048.key");

	// init cache
    cache = cache_init(gpk, ucert);

    printf("\n\n+++ Evaluation Menu +++\n");
    printf("1) Sign and Verify - iterate msg size\n");
    printf("2) Sign and Verify - iterate sig count\n");
    printf("3) Batch Sign and Batch Verify - iterate msg size\n");
    printf("4) Batch Sign and Batch Verify - iterate sig count\n");
    printf("5) Batch Sign only - iterate sig count\n");
    printf("6) Batch Verify only - iterate sig count\n");
    printf("7) Open and Judge - iterate sig count\n");
    printf("Select: ");

    ret = scanf("%u", &choice);

	printf("\nEnter static size: ");
	ret = scanf("%u", &static_size);
	printf("Enter dynamic range (#first #last): ");
	ret = scanf("%u %u", &dynamic_start, &dynamic_end);
	printf("Enter dynamic step size: ");
	ret = scanf("%u", &step);
	printf("Enter filename to save results: ");
	memset(filename, 0, 257);
	ret = scanf("%256s", filename);

	fp = fopen(filename, "w+b");

	if(fp == NULL) {
		printf("Error opening results file: %s (%s)\n", strerror(errno), filename);
		gpk_clear(gpk);
		ucert_clear(ucert);
		uk_clear(uk);
		return 4;
	}

    switch(choice) {
	case 1:
	{
	    for(DWORD i=dynamic_start; i<=dynamic_end; i+=step) {
		xsgs_signature_eval(gpk, ucert, uk, cache, i, static_size, fp);
	    }
	    break;
	}
	case 2:
	{
	    for(DWORD i=dynamic_start; i<=dynamic_end; i+=step) {
		xsgs_signature_eval(gpk, ucert, uk, cache, static_size, i, fp);
	    }
	    break;
	}
	case 3:
	{
	    for(DWORD i=dynamic_start; i<=dynamic_end; i+=step) {
		xsgs_batch_signature_eval(gpk, ucert, uk, cache, i, static_size, fp);
	    }
	    break;
	}
	case 4:
	{
	    for(DWORD i=dynamic_start; i<=dynamic_end; i+=step) {
		xsgs_batch_signature_eval(gpk, ucert, uk, cache, static_size, i, fp);
	    }
	    break;
	}
	case 5:
	{
	    for(DWORD i=dynamic_start; i<=dynamic_end; i+=step) {
		xsgs_batch_sign_eval(gpk, ucert, uk, size, i, fp);
	    }
	    break;
	}
	case 6:
	{
	    XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(dynamic_end*sizeof(XSGS_BATCH_SIGNED_MSG*));

	    // initialize signature list
	    printf("Generate signature batch ... ");
	    fflush(stdout);

	    for(DWORD i=0; i < dynamic_end; i++) {
				sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
				sig_list[i]->msg_len = static_size;
				sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
				get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
			}

	    // sign
	    xsgs_batch_sign(gpk, ucert, uk, sig_list, dynamic_end);
	    printf("OK\n");

	    // verify evaluation
	    for(DWORD i=dynamic_start; i<=dynamic_end; i+=step) {
		xsgs_batch_verify_eval(gpk, sig_list, i, fp);
	    }

	    // free signature list
	    for(DWORD i=0; i<dynamic_end; i++) {
		bsm_clear(sig_list[i]);
	    }
	    free(sig_list);
	    break;
	}
	case 7:
	{
	    XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(dynamic_end*sizeof(XSGS_BATCH_SIGNED_MSG*));

	    printf("Generate signature batch ... ");
	    fflush(stdout);

	    for(DWORD i=0; i < dynamic_end; i++) {
				sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
				sig_list[i]->msg_len = static_size;
				sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
				get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
			}

	    // sign
	    xsgs_batch_sign_cache(gpk, ucert, uk, cache, sig_list, dynamic_end);
	    printf("OK\n");

	    // open, judge evaluation
	    for(DWORD i=dynamic_start; i<=dynamic_end; i+=step) {
		xsgs_batch_open_judge_eval(gpk, ok, udbe, sig_list, i, "test-4096", fp);
	    }

	    // free signature list
	    for(DWORD i=0; i<dynamic_end; i++) {
		bsm_clear(sig_list[i]);
	    }
	    free(sig_list);
	    break;
	}
	default:
	{
	    break;
	}
    }

    fclose(fp);

    // clear
    cache_clear(cache, gpk);
    gpk_clear(gpk);
    ik_clear(ik);
	ok_clear(ok);
    ucert_clear(ucert);
    uk_clear(uk);
    udbe_clear(udbe);

    return 0;
}

int xsgs_ccs_paper_eval(void) {
    XSGS_PUBLIC_KEY* gpk;
    XSGS_ISSUER_KEY* ik;
    XSGS_OPENER_KEY* ok;
    XSGS_USER_CERT* ucert;
	XSGS_USER_KEY* uk;
    XSGS_USER_DB_ENTRY* udbe;
    int ret = 0;
    DWORD choice = 0, i;
    FILE* fp = NULL;
    char filename[257];
    XSGS_CACHE* cache;
    pbc_param_ptr param = NULL;


    printf("\n\n+++ eXtremely Short Group Signature - CCS Paper Evaluation +++\n");

    printf("\n\n+++ CCS Paper Evaluation Menu +++\n");
    printf("1) Sign / Batch Sign\n");
    printf("2) Verify / Batch Verify\n");
    printf("3) Open / Judge\n");
    printf("4) User Join CS\n");
    printf("5) User Join CH\n");
    printf("6) User Revoke CS\n");
	printf("7) User Revoke CH\n");
    printf("Select: ");

    ret = scanf("%u", &choice);
    if(ret != 1) {
	return 1;
    }

    param = xsgs_param_import_file("curves/xsgs_curve_d_277699_167_175.param");
	if(param == NULL) {
		printf("Generating missing curve...\n");
		param = xsgs_find_curve_d(277699, 300);
		if(param == NULL) {
			return 2;
		}
		xsgs_param_export_file("curves/xsgs_curve_d_277699_167_175.param", param);
	}

	// group public key generation
	gpk = (XSGS_PUBLIC_KEY*) malloc(sizeof(XSGS_PUBLIC_KEY));
	ik = (XSGS_ISSUER_KEY*) malloc(sizeof(XSGS_ISSUER_KEY));
	xsgs_gm_gen(gpk, ik, param);

	// group manager key generation
	ok = (XSGS_OPENER_KEY*) malloc(sizeof(XSGS_OPENER_KEY));
	xsgs_opener_gen(gpk, ok);

    switch(choice) {
	case 1:
		{
			DWORD data_size[14] = {1, 500, 1000, 10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000, 90000, 100000, 1000000};
			xsgs_user_join_offline(gpk, ik, &ucert, &uk, &udbe, "key_store/test-2048.key");
			cache = cache_init(gpk, ucert);

			// size eval (single)
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-sign-size-d_%u_%u-count_100.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			for(i=0; i<14; i++) {
				xsgs_sign_eval1(gpk, ucert, uk, cache, data_size[i], 10, 100, fp);
			}
			fclose(fp);

			// count eval (single)
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-sign-count-d_%u_%u-msg_size_1000_bytes.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			xsgs_sign_eval2(gpk, ucert, uk, cache, 1000, 10, 1, fp);
			for(i=10; i<=1000; i+=10) {
				xsgs_sign_eval2(gpk, ucert, uk, cache, 1000, 10, i, fp);
			}
			fclose(fp);

			// count eval (batch)
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-batch_sign-count-d_%u_%u-msg_size_1000_bytes.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			xsgs_batch_sign_eval2(gpk, ucert, uk, cache, 1000, 10, 1, fp);
			for(i=10; i<=1000; i+=10) {
				xsgs_batch_sign_eval2(gpk, ucert, uk, cache, 1000, 10, i, fp);
			}

			fclose(fp);
			ucert_clear(ucert);
			uk_clear(uk);
			udbe_clear(udbe);
			cache_clear(cache, gpk);

			break;
		}
	case 2:
		{
			xsgs_user_join_offline(gpk, ik, &ucert, &uk, &udbe, "key_store/test-2048.key");
			cache = cache_init(gpk, ucert);

			// count eval (single)
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-verify-d_%u_%u-msg_size_1000_bytes.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			xsgs_verify_eval2(gpk, ucert, uk, cache, 1000, 10, 1, fp);
			for(i=10; i<=1000; i+=10) {
				xsgs_verify_eval2(gpk, ucert, uk, cache, 1000, 10, i, fp);
			}
			fclose(fp);

			// count eval (batch)
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-batch_verify-d_%u_%u-msg_size_1000_bytes.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			xsgs_batch_verify_eval2(gpk, ucert, uk, cache, 1000, 10, 1, fp);
			for(i=10; i<=1000; i+=10) {
				xsgs_batch_verify_eval2(gpk, ucert, uk, cache, 1000, 10, i, fp);
			}

			fclose(fp);
			ucert_clear(ucert);
			uk_clear(uk);
			udbe_clear(udbe);
			cache_clear(cache, gpk);

			break;
		}
	case 3:
		{
			XSGS_BATCH_SIGNED_MSG** sig_list = (XSGS_BATCH_SIGNED_MSG**) malloc(100*sizeof(XSGS_BATCH_SIGNED_MSG*));
			xsgs_user_join_offline(gpk, ik, &ucert, &uk, &udbe, "key_store/test-2048.key");
			cache = cache_init(gpk, ucert);

			printf("\nGenerate signature batch ... ");
			fflush(stdout);

			for(i=0; i<100; i++) {
				sig_list[i] = (XSGS_BATCH_SIGNED_MSG*) malloc(sizeof(XSGS_BATCH_SIGNED_MSG));
				sig_list[i]->msg_len = 1000;
				sig_list[i]->msg = (BYTE*) malloc(sig_list[i]->msg_len);
				get_rand_buf(sig_list[i]->msg, sig_list[i]->msg_len);
			}
			xsgs_batch_sign_cache(gpk, ucert, uk, cache, sig_list, 100);
			printf("OK\n");

			// open, judge evaluation
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-open_judge-d_%u_%u-msg_size_1000_bytes.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			xsgs_batch_open_judge_eval2(gpk, ok, udbe, sig_list, 10, 100, "test-2048", fp);

			// free signature list
			for(i=0; i<100; i++) {
				bsm_clear(sig_list[i]);
			}
			free(sig_list);

			fclose(fp);
			ucert_clear(ucert);
			uk_clear(uk);
			udbe_clear(udbe);
			cache_clear(cache, gpk);
			break;
		}
	case 4:
		{
			// user join cs eval
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-user_join_cs-d_%u_%u.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			XSGS_PAILLIER_PUBKEY* ppk = xsgs_paillier_gen(PAILLIER_MODULO_BITS);
			xsgs_join_cs_eval(gpk, ik, ppk, "test-2048", "test-2048", 10, 100, fp);
			ppk_clear(ppk);
			fclose(fp);
			break;
		}
	case 5:
		{
			// user join ch eval
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-user_join_ch-d_%u_%u.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			XSGS_PAILLIER_PUBKEY* ppk = xsgs_paillier_gen(PAILLIER_MODULO_BITS);
			xsgs_join_ch_eval(gpk, ik, ppk, "test-2048", "test-2048", 10, 100, fp);
			ppk_clear(ppk);
			fclose(fp);
			break;
		}
	case 6:
		{
			// user revoke cs eval
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-user_revoke_cs-d_%u_%u.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			xsgs_revoke_cs_eval(gpk, ik, 10, 100, "test-2048", fp);
			fclose(fp);
			break;
		}
	case 7:
		{
			// user revoke ch eval
			memset(filename, 0, 257);
			snprintf(filename, 256, "eval_results/eval-user_revoke_ch-d_%u_%u.txt", (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->r, 2), (DWORD)mpz_sizeinbase(((d_param_ptr)param->data)->q, 2));
			fp = fopen(filename, "w+b");
			xsgs_revoke_ch_eval(gpk, ik, 10, 100, "test-2048", "test-2048", fp);
			fclose(fp);
			break;
		}
	default:
	{
	    break;
	}
    }

    // clear
    //pbc_param_clear(param);
    gpk_clear(gpk);
    ik_clear(ik);
    ok_clear(ok);

    return 0;
}
