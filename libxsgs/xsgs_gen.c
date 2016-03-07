#include <string.h>
#include "xsgs.h"

// generate D curves
int gen_dcurve_param(pbc_cm_t cm, void *data) {
	printf("computing Hilbert polynomial and finding roots...\n");
	fflush(stdout);

	pbc_param_init_d_gen((pbc_param_ptr) data, cm);

	printf("bits in q = %u, bits in r = %u\n", (DWORD) mpz_sizeinbase(cm->q, 2),
			(DWORD) mpz_sizeinbase(cm->r, 2));
	fflush(stdout);

	return 1;
}

// generate G curves
int gen_gcurve_param(pbc_cm_t cm, void *data) {
	printf("computing Hilbert polynomial and finding roots...\n");
	fflush(stdout);

	pbc_param_init_g_gen((pbc_param_ptr) data, cm);

	printf("bits in q = %u, bits in r = %u\n", (DWORD) mpz_sizeinbase(cm->q, 2),
			(DWORD) mpz_sizeinbase(cm->r, 2));
	fflush(stdout);

	return 1;
}

// generate curves for xsgs scheme - type D
pbc_param_ptr xsgs_find_curve_d(DWORD d, DWORD b) {
	pbc_param_ptr param = (pbc_param_ptr) malloc(sizeof(pbc_param_t));

	// generate type D curve: discriminant=d, MNT curves of embedding degree 6, group order at most b bits
	if (!pbc_cm_search_d(gen_dcurve_param, param, d, b)) {
		printf("no suitable curves for discriminant %d", d);
		free(param);
		return NULL;
	}

	return param;
}

// generate curves for xsgs scheme - type F
pbc_param_ptr xsgs_find_curve_f(DWORD rbits) {
	pbc_param_ptr param = (pbc_param_ptr) malloc(sizeof(pbc_param_t));

	// generate type F curve: MNT curves of embedding degree 12
	pbc_param_init_f_gen(param, rbits);
	f_param_ptr cm = (f_param_ptr) param->data;
	printf("bits in q = %u, bits in r = %u\n", (DWORD) mpz_sizeinbase(cm->q, 2),
			(DWORD) mpz_sizeinbase(cm->r, 2));

	return param;
}

// generate curves for xsgs scheme - type G
pbc_param_ptr xsgs_find_curve_g(DWORD d, DWORD b) {
	pbc_param_ptr param = (pbc_param_ptr) malloc(sizeof(pbc_param_t));

	// generate type D curve: discriminant=d, CM curves of embedding degree 10, group order at most b bits
	if (!pbc_cm_search_g(gen_gcurve_param, param, d, b)) {
		printf("no suitable curves for discriminant %d", d);
		free(param);
		return NULL;
	}

	return param;
}

// interactive curve generation
int xsgs_generate_curve(BYTE type, char** lpFilename) {
	pbc_param_ptr param = NULL;
	int ret = 0;
	char* filename = NULL;
	DWORD b = 0, d = 0;

	switch (type) {
	case CURVE_TYPE_D:
		printf(
				"\n\n+++ eXtremely Short Group Signature - Generate Type D Curve +++\n\n");

		printf(
				"Enter discriminant (must be 0 or 3 mod 4 and positive, e.g. 277699): ");
		ret = scanf("%u", &d);

		if (d <= 0 || (d % 4 != 0 && d % 4 != 3)) {
			printf("%u %% 4 = %u\n", d, d % 4);
			return 5;
		}

		printf("Enter count of at most bits for group order (e.g. 300): ");
		ret = scanf("%u", &b);

		param = xsgs_find_curve_d(d, b);
		if (param == NULL) {
			return 6;
		}

		filename = (char*) malloc(256);
		memset(filename, 0, 256);
		snprintf(filename, 255, "curves/xsgs_curve_d_%u_%u_%u.param", d,
				(DWORD) mpz_sizeinbase(((d_param_ptr) param->data)->r, 2),
				(DWORD) mpz_sizeinbase(((d_param_ptr) param->data)->q, 2));

		ret = xsgs_param_export_file(filename, param);
		pbc_param_clear(param);

		if (ret) {
			free(filename);
			if (lpFilename != NULL) {
				*lpFilename = NULL;
			}
			return 7;
		}

		printf("Curve saved to: %s\n", filename);
		if (lpFilename != NULL) {
			*lpFilename = filename;
		}
		break;
	case CURVE_TYPE_F:
		printf(
				"\n\n+++ eXtremely Short Group Signature - Generate Type F Curve +++\n\n");

		printf("Enter bit size of r and q (e.g. 160): ");
		ret = scanf("%u", &b);
		if (b == 0) {
			return 8;
		}

		param = xsgs_find_curve_f(b);
		if (param == NULL) {
			return 9;
		}

		filename = (char*) malloc(256);
		memset(filename, 0, 256);
		snprintf(filename, 255, "curves/xsgs_curve_f_%u_%u.param",
				(DWORD) mpz_sizeinbase(((f_param_ptr) param->data)->r, 2),
				(DWORD) mpz_sizeinbase(((f_param_ptr) param->data)->q, 2));

		ret = xsgs_param_export_file(filename, param);
		pbc_param_clear(param);

		if (ret) {
			free(filename);
			if (lpFilename != NULL) {
				*lpFilename = NULL;
			}
			return 10;
		}

		printf("Curve saved to: %s\n", filename);
		if (lpFilename != NULL) {
			*lpFilename = filename;
		}
		break;
	case CURVE_TYPE_G:
		printf(
				"\n\n+++ eXtremely Short Group Signature - Generate Type G Curve +++\n\n");

		printf(
				"Enter discriminant (must be 43 or 67 mod 120 and positive, e.g. 4543003): ");
		ret = scanf("%u", &d);

		if (d <= 0 || (d % 120 != 43 && d % 120 != 67)) {
			printf("%u %% 120 = %u\n", d, d % 120);
			return 5;
		}

		printf("Enter count of at most bits for group order (e.g. 300): ");
		ret = scanf("%u", &b);

		param = xsgs_find_curve_g(d, b);
		if (param == NULL) {
			return 6;
		}

		filename = (char*) malloc(256);
		memset(filename, 0, 256);
		snprintf(filename, 255, "curves/xsgs_curve_g_%u_%u_%u.param", d,
				(DWORD) mpz_sizeinbase(((g_param_ptr) param->data)->r, 2),
				(DWORD) mpz_sizeinbase(((g_param_ptr) param->data)->q, 2));

		ret = xsgs_param_export_file(filename, param);
		pbc_param_clear(param);

		if (ret) {
			free(filename);
			if (lpFilename != NULL) {
				*lpFilename = NULL;
			}
			return 7;
		}

		printf("Curve saved to: %s\n", filename);
		if (lpFilename != NULL) {
			*lpFilename = filename;
		}
		break;
	default:
		return -1;
	}

	return 0;
}

// interactive curve selection or generation
pbc_param_ptr xsgs_select_curve_param(char* curve_dir, char* curve_name_prefix,
		DWORD prefix_length) {
	char* filename = NULL;
	DWORD choice = 0, ret = 0;
	pbc_param_ptr param = NULL;

	// generate curve or select previously generated curve
	printf("CURVE SELECTION:\n");
	printf("[0] Generate new type D curve\n");
	printf("[1] Generate new type F curve\n");
	printf("[2] Generate new type G curve\n");
	print_dir_selection(curve_dir, 3, curve_name_prefix, prefix_length);
	printf("Select: ");
	ret = scanf("%u", &choice);
	if (ret != 1) {
		printf("Input Error.\n");
		return NULL;
	}
	switch (choice) {
	case 0:
		xsgs_generate_curve(CURVE_TYPE_D, &filename);
		break;
	case 1:
		xsgs_generate_curve(CURVE_TYPE_F, &filename);
		break;
	case 2:
		xsgs_generate_curve(CURVE_TYPE_G, &filename);
		break;
	default:
		filename = get_selected_filename(curve_dir, 3, curve_name_prefix,
				prefix_length, choice);
		break;
	}

	if (filename == NULL) {
		printf("Error on curve selection.\n");
		return NULL;
	}

	// import selected curve
	param = xsgs_param_import_file(filename);
	free(filename);
	if (param == NULL) {
		printf("Error on curve parameter import.\n");
		return NULL;
	}

	return param;
}

// GROUP MANAGER INIT - group key generation part1
void xsgs_gm_gen(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, pbc_param_ptr param) {
	// 1. generate prime p, pairing group G1, G2, GT, e and a hash function H: {0,1}* -> Zp
	gpk->param = param;
	gpk->pairing = (pairing_ptr) malloc(sizeof(pairing_t));
	pairing_init_pbc_param(gpk->pairing, gpk->param);

	// 2. select a generator G2 e group 2 at random
	element_init_G2(gpk->G2, gpk->pairing);
	element_random(gpk->G2);
	// and select a generator G1 e group 1 at random (G1 <- psi(G2) not applicable)
	element_init_G1(gpk->G1, gpk->pairing);
	element_random(gpk->G1);

	// 3. choose gamma e Zp* at random and set ik = gamma
	element_init_Zr(ik->gamma, gpk->pairing);
	element_random(ik->gamma);

	// 4. select K e Group1
	element_init_G1(gpk->K, gpk->pairing);
	element_random(gpk->K);
	// and W = G2^gamma (e Group2)
	element_init_G2(gpk->W, gpk->pairing);
	element_pow_naf(gpk->W, gpk->G2, ik->gamma);

	return;
}

// OPENER INIT - group key generation part 2
void xsgs_opener_gen(XSGS_PUBLIC_KEY* gpk, XSGS_OPENER_KEY* ok) {
	pairing_ptr pairing = gpk->pairing;

	// 1. choose xi1, xi2 e Zp at random
	element_init_Zr(ok->xi1, pairing);
	element_random(ok->xi1);
	element_init_Zr(ok->xi2, pairing);
	element_random(ok->xi2);

	// 2. set H = K^xi1 and G = K^xi2
	element_init_G1(gpk->H, pairing);
	element_pow_naf(gpk->H, gpk->K, ok->xi1);
	element_init_G1(gpk->G, pairing);
	element_pow_naf(gpk->G, gpk->K, ok->xi2);

	return;
}

// interactive generation of group keys
int xsgs_generate_group_keys(void) {
	pbc_param_ptr param;
	XSGS_PUBLIC_KEY* gpk;
	XSGS_ISSUER_KEY* ik;
	XSGS_OPENER_KEY* ok;
	DWORD ret = 0;

	printf(
			"\n\n+++ eXtremely Short Group Signature - Generate Group Keys +++\n\n");

	// get interactively curve parameter
	param = xsgs_select_curve_param("curves/", "xsgs_curve_", 11);
	if (param == NULL) {
		return 1;
	}

	// group public key generation
	gpk = (XSGS_PUBLIC_KEY*) malloc(sizeof(XSGS_PUBLIC_KEY));
	ik = (XSGS_ISSUER_KEY*) malloc(sizeof(XSGS_ISSUER_KEY));
	xsgs_gm_gen(gpk, ik, param);

	// group manager key generation
	ok = (XSGS_OPENER_KEY*) malloc(sizeof(XSGS_OPENER_KEY));
	xsgs_opener_gen(gpk, ok);

	// print keys
	printf("\nXSGS GROUP PUBLIC KEY (GPK):\n");
	element_printf("G1 = \n%B\n", gpk->G1);
	element_printf("K = \n%B\n", gpk->K);
	element_printf("H = \n%B\n", gpk->H);
	element_printf("G = \n%B\n", gpk->G);
	element_printf("G2 = \n%B\n", gpk->G2);
	element_printf("W = \n%B\n", gpk->W);
	printf("\nXSGS ISSUER KEY (IK):\n");
	element_printf("gamma = \n%B\n", ik->gamma);
	printf("\nXSGS OPENER KEY (OK):\n");
	element_printf("xi1 = \n%B\n", ok->xi1);
	element_printf("xi2 = \n%B\n", ok->xi2);

	// save keys to key store
	if (xsgs_gpk_export_file("key_store/xsgs_gpk.key", gpk) == 0) {
		printf("\nGPK saved to: key_store/xsgs_gpk.key\n");
	} else {
		printf("Error on saving GPK to: key_store/xsgs_gpk.key\n");
		ret = 2;
	}
	if (xsgs_ik_export_file("key_store/xsgs_ik.key", ik) == 0) {
		printf("IK saved to: key_store/xsgs_ik.key\n");
	} else {
		printf("Error on saving IK to: key_store/xsgs_ik.key\n");
		ret = 3;
	}
	if (xsgs_ok_export_file("key_store/xsgs_ok.key", ok) == 0) {
		printf("OK saved to: key_store/xsgs_ok.key\n");
	} else {
		printf("Error on saving OK to: key_store/xsgs_ok.key\n");
		ret = 4;
	}

	// clear
	//pbc_param_clear(param);
	gpk_clear(gpk);
	ik_clear(ik);
	ok_clear(ok);

	return ret;
}
