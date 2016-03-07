#include "xsgs.h"

element_t* lut_init(element_t base, DWORD size) {
	element_t* lut = (element_t*) malloc(size * sizeof(element_t));
	element_init_same_as(lut[0], base);
	element_set(lut[0], base);

	for (DWORD i = 1; i < size; i++) {
		element_init_same_as(lut[i], base);
		element_square(lut[i], lut[i - 1]);
	}

	return lut;
}

void lut_clear(element_t *lut, DWORD size) {
	for (DWORD i = 0; i < size; i++) {
		element_clear(lut[i]);
	}
	free(lut);
	return;
}

XSGS_CACHE* cache_init(XSGS_PUBLIC_KEY *gpk, XSGS_USER_CERT *ucert) {
	XSGS_CACHE* cache = (XSGS_CACHE*) malloc(sizeof(XSGS_CACHE));
	element_t A_G2;
	element_t G1_G2;
	element_t H_G2;
	element_t H_W;

	element_init_GT(A_G2, gpk->pairing);
	element_init_GT(G1_G2, gpk->pairing);
	element_init_GT(H_G2, gpk->pairing);
	element_init_GT(H_W, gpk->pairing);

	element_pairing(A_G2, ucert->A, gpk->G2);
	element_pairing(G1_G2, gpk->G1, gpk->G2);
	element_pairing(H_G2, gpk->H, gpk->G2);
	element_pairing(H_W, gpk->H, gpk->W);

	cache->LUT_G = lut_init(gpk->G, mpz_sizeinbase(gpk->pairing->G1->order, 2));
	cache->LUT_H = lut_init(gpk->H, mpz_sizeinbase(gpk->pairing->G1->order, 2));
	cache->LUT_K = lut_init(gpk->K, mpz_sizeinbase(gpk->pairing->G1->order, 2));
	cache->LUT_G2 = lut_init(gpk->G2,
	mpz_sizeinbase(gpk->pairing->G2->order, 2));
	cache->LUT_W = lut_init(gpk->W, mpz_sizeinbase(gpk->pairing->G2->order, 2));
	cache->LUT_A_G2 = lut_init(A_G2,
	mpz_sizeinbase(gpk->pairing->GT->order, 2));
	cache->LUT_G1_G2 = lut_init(G1_G2,
	mpz_sizeinbase(gpk->pairing->GT->order, 2));
	cache->LUT_H_G2 = lut_init(H_G2,
	mpz_sizeinbase(gpk->pairing->GT->order, 2));
	cache->LUT_H_W = lut_init(H_W, mpz_sizeinbase(gpk->pairing->GT->order, 2));

	return cache;
}

void cache_clear(XSGS_CACHE *cache, XSGS_PUBLIC_KEY *gpk) {
	lut_clear(cache->LUT_G, mpz_sizeinbase(gpk->pairing->G1->order, 2));
	lut_clear(cache->LUT_H, mpz_sizeinbase(gpk->pairing->G1->order, 2));
	lut_clear(cache->LUT_K, mpz_sizeinbase(gpk->pairing->G1->order, 2));
	lut_clear(cache->LUT_G2, mpz_sizeinbase(gpk->pairing->G2->order, 2));
	lut_clear(cache->LUT_W, mpz_sizeinbase(gpk->pairing->G2->order, 2));
	lut_clear(cache->LUT_A_G2, mpz_sizeinbase(gpk->pairing->GT->order, 2));
	lut_clear(cache->LUT_G1_G2, mpz_sizeinbase(gpk->pairing->GT->order, 2));
	lut_clear(cache->LUT_H_G2, mpz_sizeinbase(gpk->pairing->GT->order, 2));
	lut_clear(cache->LUT_H_W, mpz_sizeinbase(gpk->pairing->GT->order, 2));
	free(cache);
	return;
}

void fixed_base_exp(element_t rop, element_t *lut, element_t exp) {
	mpz_t e;
	mpz_init(e);
	element_to_mpz(e, exp);
	mpz_mod(e, e, lut[0]->field->order);

	if (mpz_is0(e)) {
		element_set1(rop);
	} else {
		element_set(rop, lut[mpz_sizeinbase(e, 2) - 1]);

		for (int l = mpz_sizeinbase(e, 2) - 2; l >= 0; l--) {
			if (mpz_tstbit(e, l)) {
				element_mul(rop, rop, lut[l]);
			}
		}
	}

	mpz_clear(e);
	return;
}

void fixed_base_exp2(element_t rop, element_t *lut1, element_t exp1, element_t *lut2, element_t exp2) {
	mpz_t e1, e2;
	mpz_init(e1);
	mpz_init(e2);
	element_to_mpz(e1, exp1);
	element_to_mpz(e2, exp2);
	mpz_mod(e1, e1, lut1[0]->field->order);
	mpz_mod(e2, e2, lut1[0]->field->order);

	if (mpz_is0(e1) && mpz_is0(e2)) {
		element_set1(rop);
	} else {
		int l1 = mpz_sizeinbase(e1, 2) - 1;
		int l2 = mpz_sizeinbase(e2, 2) - 1;
		int l = (l1 > l2) ? l1 : l2;

		element_set1(rop);

		for (; l >= 0; l--) {
			if (mpz_tstbit(e1, l)) {
				element_mul(rop, rop, lut1[l]);
			}
			if (mpz_tstbit(e2, l)) {
				element_mul(rop, rop, lut2[l]);
			}
		}
	}

	mpz_clear(e1);
	mpz_clear(e2);
	return;
}

void fixed_base_exp3(element_t rop, element_t *lut1, element_t exp1, element_t *lut2, element_t exp2, element_t *lut3, element_t exp3) {
	mpz_t e1, e2, e3;
	mpz_init(e1);
	mpz_init(e2);
	mpz_init(e3);
	element_to_mpz(e1, exp1);
	element_to_mpz(e2, exp2);
	element_to_mpz(e3, exp3);
	mpz_mod(e1, e1, lut1[0]->field->order);
	mpz_mod(e2, e2, lut1[0]->field->order);
	mpz_mod(e3, e3, lut3[0]->field->order);

	if (mpz_is0(e1) && mpz_is0(e2) && mpz_is0(e3)) {
		element_set1(rop);
	} else {
		int l1 = mpz_sizeinbase(e1, 2) - 1;
		int l2 = mpz_sizeinbase(e2, 2) - 1;
		int l3 = mpz_sizeinbase(e3, 2) - 1;
		int l = (l1 > l2) ? ((l1 > l3) ? l1 : l3) : ((l2 > l3) ? l2 : l3);

		element_set1(rop);

		for (; l >= 0; l--) {
			if (mpz_tstbit(e1, l)) {
				element_mul(rop, rop, lut1[l]);
			}
			if (mpz_tstbit(e2, l)) {
				element_mul(rop, rop, lut2[l]);
			}
			if (mpz_tstbit(e3, l)) {
				element_mul(rop, rop, lut3[l]);
			}
		}
	}

	mpz_clear(e1);
	mpz_clear(e2);
	mpz_clear(e3);
	return;
}

XSGS_NAF* naf_init(mpz_t exp, mpz_t mod) {
	mpz_t e;
	XSGS_NAF* naf;

	/*printf("\nEXP:  ");
	 for(int j=mpz_sizeinbase(exp, 2)-1; j>-1; j--) {
	 printf("%X", mpz_tstbit(exp, j));
	 }
	 printf("\n");*/

	naf = (XSGS_NAF*) malloc(sizeof(XSGS_NAF));
	mpz_init_set(e, exp);
	mpz_mod(e, exp, mod);
	naf->len = mpz_sizeinbase(e, 2) + 1;
	naf->exp = (BYTE*) malloc(naf->len);

	for (DWORD i = 0; i < naf->len - 1; i++) {
		naf->exp[i] = mpz_tstbit(e, 0);
		if (mpz_tstbit(e, 1) && naf->exp[i]) {
			naf->exp[i]++;
			mpz_add_ui(e, e, 1);
		}
		mpz_tdiv_q_2exp(e, e, 1);
	}
	if (mpz_tstbit(e, 0)) {
		naf->exp[naf->len - 1] = 1;
	} else {
		naf->len--;
	}

	/*printf("NAF: ");
	 for(int j=naf->len-1; j>=0; j--) {
	 printf("%X", naf->exp[j]);
	 }
	 printf("\n");*/

	mpz_clear(e);
	return naf;
}

void naf_clear(XSGS_NAF *naf) {
	free(naf->exp);
	free(naf);
	return;
}

void fixed_base_exp_naf(element_t rop, element_t *lut, element_t exp) {
	mpz_t e;
	mpz_init(e);
	element_to_mpz(e, exp);
	mpz_mod(e, e, lut[0]->field->order);

	if (mpz_is0(e)) {
		element_set1(rop);
	} else {
		XSGS_NAF* naf = naf_init(e, lut[0]->field->order);
		element_t inv;
		element_init(inv, lut[0]->field);
		element_set1(inv);

		element_set(rop, lut[naf->len - 1]);

		for (int l = naf->len - 2; l >= 0; l--) {
			if (naf->exp[l] == 1) {
				element_mul(rop, rop, lut[l]);
			} else if (naf->exp[l] == 2) {
				element_mul(inv, inv, lut[l]);
			}
		}

		element_invert(inv, inv);
		element_mul(rop, rop, inv);

		naf_clear(naf);
		element_clear(inv);
	}

	mpz_clear(e);
	return;
}

void fixed_base_exp_naf2(element_t rop, element_t *lut1, element_t exp1, element_t *lut2, element_t exp2) {
	mpz_t e1, e2;
	mpz_init(e1);
	mpz_init(e2);
	element_to_mpz(e1, exp1);
	element_to_mpz(e2, exp2);
	mpz_mod(e1, e1, lut1[0]->field->order);
	mpz_mod(e2, e2, lut2[0]->field->order);

	if (mpz_is0(e1) && mpz_is0(e2)) {
		element_set1(rop);
	} else {
		XSGS_NAF* naf1 = naf_init(e1, lut1[0]->field->order);
		XSGS_NAF* naf2 = naf_init(e2, lut2[0]->field->order);
		element_t inv;
		element_init(inv, lut1[0]->field);

		int l1 = naf1->len - 1;
		int l2 = naf2->len - 1;
		int l = (l1 > l2) ? l1 : l2;

		element_set1(rop);
		element_set1(inv);

		for (; l >= 0; l--) {
			if (l <= l1) {
				if (naf1->exp[l] == 1) {
					element_mul(rop, rop, lut1[l]);
				} else if (naf1->exp[l] == 2) {
					element_mul(inv, inv, lut1[l]);
				}
			}

			if (l <= l2) {
				if (naf2->exp[l] == 1) {
					element_mul(rop, rop, lut2[l]);
				} else if (naf2->exp[l] == 2) {
					element_mul(inv, inv, lut2[l]);
				}
			}
		}

		element_invert(inv, inv);
		element_mul(rop, rop, inv);

		naf_clear(naf1);
		naf_clear(naf2);
		element_clear(inv);
	}

	mpz_clear(e1);
	mpz_clear(e2);
	return;
}

void fixed_base_exp_naf3(element_t rop, element_t *lut1, element_t exp1, element_t *lut2, element_t exp2, element_t *lut3, element_t exp3) {
	mpz_t e1, e2, e3;
	mpz_init(e1);
	mpz_init(e2);
	mpz_init(e3);
	element_to_mpz(e1, exp1);
	element_to_mpz(e2, exp2);
	element_to_mpz(e3, exp3);
	mpz_mod(e1, e1, lut1[0]->field->order);
	mpz_mod(e2, e2, lut2[0]->field->order);
	mpz_mod(e3, e3, lut3[0]->field->order);

	if (mpz_is0(e1) && mpz_is0(e2) && mpz_is0(e3)) {
		element_set1(rop);
	} else {
		XSGS_NAF* naf1 = naf_init(e1, lut1[0]->field->order);
		XSGS_NAF* naf2 = naf_init(e2, lut2[0]->field->order);
		XSGS_NAF* naf3 = naf_init(e3, lut3[0]->field->order);
		element_t inv;
		element_init(inv, lut1[0]->field);

		int l1 = naf1->len - 1;
		int l2 = naf2->len - 1;
		int l3 = naf3->len - 1;
		int l = (l1 > l2) ? ((l1 > l3) ? l1 : l3) : ((l2 > l3) ? l2 : l3);

		element_set1(rop);
		element_set1(inv);

		for (; l >= 0; l--) {
			if (l <= l1) {
				if (naf1->exp[l] == 1) {
					element_mul(rop, rop, lut1[l]);
				} else if (naf1->exp[l] == 2) {
					element_mul(inv, inv, lut1[l]);
				}
			}

			if (l <= l2) {
				if (naf2->exp[l] == 1) {
					element_mul(rop, rop, lut2[l]);
				} else if (naf2->exp[l] == 2) {
					element_mul(inv, inv, lut2[l]);
				}
			}

			if (l <= l3) {
				if (naf3->exp[l] == 1) {
					element_mul(rop, rop, lut3[l]);
				} else if (naf3->exp[l] == 2) {
					element_mul(inv, inv, lut3[l]);
				}
			}
		}

		element_invert(inv, inv);
		element_mul(rop, rop, inv);

		naf_clear(naf1);
		naf_clear(naf2);
		naf_clear(naf3);
		element_clear(inv);
	}

	mpz_clear(e1);
	mpz_clear(e2);
	mpz_clear(e3);
	return;
}

#define POW_LUT_SIZE	8
void element_pow_naf_mpz(element_t rop, element_t base, mpz_t exp) {
	int l = 0, i;
	BYTE b;
	mpz_t e;
	mpz_init_set(e, exp);
	mpz_mod(e, e, base->field->order);

	if (mpz_is0(e)) {
		element_set1(rop);
	} else {
		XSGS_NAF* naf = naf_init(e, base->field->order);
		element_t inv, rop_t;
		element_init(inv, base->field);
		element_init(rop_t, base->field);
		element_invert(inv, base);

		// lookup table for windows size = 4
		element_t lut[POW_LUT_SIZE];
		for (i = 0; i < POW_LUT_SIZE; i++) {
			element_init(lut[i], base->field);
		}

		if (naf->len > 4) {
			element_square(rop_t, base);
			for (i = 0; i < POW_LUT_SIZE; i += 4) {
				// 100/1000
				element_square(rop_t, rop_t);
				// 101/1001
				element_mul(lut[i], rop_t, base);
				// 102/1002
				element_mul(lut[i + 1], rop_t, inv);
				// 201/2001
				element_invert(lut[i + 2], lut[i + 1]);
				// 202/2002
				element_invert(lut[i + 3], lut[i]);
			}
			for (l = naf->len - 3, i = 0; i < POW_LUT_SIZE; l--, i += 4) {
				b = naf->exp[l];
				if (b) {
					if (b == 1) {
						// 101/1002
						element_set(rop_t, lut[i]);
					} else {
						// 102/1002
						element_set(rop_t, lut[i + 1]);
					}
					l--;
					break;
				}
			}
		} else {
			element_set(rop_t, base);
			l = naf->len - 2;
		}

		for (; l >= 0;) {
			element_square(rop_t, rop_t);
			b = naf->exp[l];
			if (b) {
				if (b == 1) {
					if (naf->exp[l - 2] && l >= 2) {
						element_square(rop_t, rop_t);
						element_square(rop_t, rop_t);
						if (naf->exp[l - 2] == 1) {
							element_mul(rop_t, rop_t, lut[0]);
						} else {
							element_mul(rop_t, rop_t, lut[1]);
						}
						l -= 3;
					} else if (naf->exp[l - 3] && l >= 3) {
						element_square(rop_t, rop_t);
						element_square(rop_t, rop_t);
						element_square(rop_t, rop_t);
						if (naf->exp[l - 3] == 1) {
							element_mul(rop_t, rop_t, lut[4]);
						} else {
							element_mul(rop_t, rop_t, lut[5]);
						}
						l -= 4;
					} else {
						element_mul(rop_t, rop_t, base);
						l--;
					}
				} else {
					if (naf->exp[l - 2] && l >= 2) {
						element_square(rop_t, rop_t);
						element_square(rop_t, rop_t);
						if (naf->exp[l - 2] == 1) {
							element_mul(rop_t, rop_t, lut[2]);
						} else {
							element_mul(rop_t, rop_t, lut[3]);
						}
						l -= 3;
					} else if (naf->exp[l - 3] && l >= 3) {
						element_square(rop_t, rop_t);
						element_square(rop_t, rop_t);
						element_square(rop_t, rop_t);
						if (naf->exp[l - 3] == 1) {
							element_mul(rop_t, rop_t, lut[6]);
						} else {
							element_mul(rop_t, rop_t, lut[7]);
						}
						l -= 4;
					} else {
						element_mul(rop_t, rop_t, inv);
						l--;
					}
				}
			} else {
				l--;
			}
		}

		element_set(rop, rop_t);

		naf_clear(naf);
		element_clear(inv);
		element_clear(rop_t);
		for (i = 0; i < POW_LUT_SIZE; i++) {
			element_clear(lut[i]);
		}
	}

	mpz_clear(e);

	return;
}

void element_pow_naf(element_t rop, element_t base, element_t exp) {
	mpz_t e;
	mpz_init(e);
	element_to_mpz(e, exp);
	element_pow_naf_mpz(rop, base, e);
	mpz_clear(e);
	return;
}

void element_pow_naf2_mpz(element_t rop, element_t base1, mpz_t exp1, element_t base2, mpz_t exp2) {
	mpz_t e1, e2;
	mpz_init_set(e1, exp1);
	mpz_init_set(e2, exp2);
	mpz_mod(e1, e1, base1->field->order);
	mpz_mod(e2, e2, base2->field->order);

	if (mpz_is0(e1) && mpz_is0(e2)) {
		element_set1(rop);
	} else {
		XSGS_NAF* naf1 = naf_init(e1, base1->field->order);
		XSGS_NAF* naf2 = naf_init(e2, base2->field->order);

		int l1 = naf1->len - 1;
		int l2 = naf2->len - 1;
		int l = (l1 > l2) ? l1 - 1 : l2 - 1;

		// lookup table
		element_t lut[3][3];
		//element_init(lut[0][0], base1->field);
		element_init(lut[0][1], base1->field);
		element_init(lut[0][2], base1->field);
		element_init(lut[1][0], base1->field);
		element_init(lut[2][0], base1->field);
		element_init(lut[1][1], base1->field);
		element_init(lut[1][2], base1->field);
		element_init(lut[2][1], base1->field);
		element_init(lut[2][2], base1->field);

		//element_set1(lut[0][0]);

		element_set(lut[1][0], base1);
		element_set(lut[0][1], base2);

		element_invert(lut[2][0], lut[1][0]);
		element_invert(lut[0][2], lut[0][1]);

		element_mul(lut[1][1], lut[1][0], lut[0][1]);
		element_mul(lut[1][2], lut[1][0], lut[0][2]);
		//element_mul(lut[2][1], lut[2][0], lut[0][1]);
		//element_mul(lut[2][2], lut[2][0], lut[0][2]);
		element_invert(lut[2][1], lut[1][2]);
		element_invert(lut[2][2], lut[1][1]);

		if (l1 == l2) {
			element_set(rop, lut[1][1]);
		} else if (l1 > l2) {
			element_set(rop, lut[1][0]);
		} else {
			element_set(rop, lut[0][1]);
		}

		for (; l >= 0; l--) {
			element_square(rop, rop);
			BYTE b1 = naf1->exp[l];
			BYTE b2 = naf2->exp[l];

			if (l <= l1 && l <= l2) {
				if (b1 != 0 || b2 != 0) {
					element_mul(rop, rop, lut[b1][b2]);
				}
			} else if (l <= l1) {
				if (b1 != 0) {
					element_mul(rop, rop, lut[b1][0]);
				}
			} else if (b2 != 0) {
				element_mul(rop, rop, lut[0][b2]);
			}
		}

		naf_clear(naf1);
		naf_clear(naf2);
		//element_clear(lut[0][0]);
		element_clear(lut[0][1]);
		element_clear(lut[0][2]);
		element_clear(lut[1][0]);
		element_clear(lut[1][1]);
		element_clear(lut[1][2]);
		element_clear(lut[2][0]);
		element_clear(lut[2][1]);
		element_clear(lut[2][2]);
	}

	mpz_clear(e1);
	mpz_clear(e2);

	return;
}

void element_pow_naf2(element_t rop, element_t base1, element_t exp1, element_t base2, element_t exp2) {
	mpz_t e1, e2;
	mpz_init(e1);
	mpz_init(e2);
	element_to_mpz(e1, exp1);
	element_to_mpz(e2, exp2);
	element_pow_naf2_mpz(rop, base1, e1, base2, e2);
	mpz_clear(e1);
	mpz_clear(e2);
	return;
}

void element_pow_naf3(element_t rop, element_t base1, element_t exp1, element_t base2, element_t exp2, element_t base3, element_t exp3) {
	mpz_t e1, e2, e3;
	mpz_init(e1);
	mpz_init(e2);
	mpz_init(e3);
	element_to_mpz(e1, exp1);
	element_to_mpz(e2, exp2);
	element_to_mpz(e3, exp3);
	mpz_mod(e1, e1, base1->field->order);
	mpz_mod(e2, e2, base2->field->order);
	mpz_mod(e3, e3, base3->field->order);

	if (mpz_is0(e1) && mpz_is0(e2) && mpz_is0(e3)) {
		element_set1(rop);
	} else {
		XSGS_NAF* naf1 = naf_init(e1, base1->field->order);
		XSGS_NAF* naf2 = naf_init(e2, base2->field->order);
		XSGS_NAF* naf3 = naf_init(e3, base3->field->order);

		int l1 = naf1->len - 1;
		int l2 = naf2->len - 1;
		int l3 = naf3->len - 1;
		int l = (l1 > l2) ? ((l1 > l3) ? l1 : l3) : ((l2 > l3) ? l2 : l3);

		// lookup table
		element_t lut[3][3][3];

		//element_init(lut[0][0][0], base1->field);
		element_init(lut[0][0][1], base1->field);
		element_init(lut[0][0][2], base1->field);
		element_init(lut[0][1][0], base1->field);
		element_init(lut[0][2][0], base1->field);
		element_init(lut[1][0][0], base1->field);
		element_init(lut[2][0][0], base1->field);
		element_init(lut[0][1][1], base1->field);
		element_init(lut[0][1][2], base1->field);
		element_init(lut[0][2][1], base1->field);
		element_init(lut[0][2][2], base1->field);
		element_init(lut[1][1][0], base1->field);
		element_init(lut[1][2][0], base1->field);
		element_init(lut[2][1][0], base1->field);
		element_init(lut[2][2][0], base1->field);
		element_init(lut[1][0][1], base1->field);
		element_init(lut[1][0][2], base1->field);
		element_init(lut[2][0][1], base1->field);
		element_init(lut[2][0][2], base1->field);
		element_init(lut[1][1][1], base1->field);
		element_init(lut[1][1][2], base1->field);
		element_init(lut[1][2][1], base1->field);
		element_init(lut[1][2][2], base1->field);
		element_init(lut[2][1][1], base1->field);
		element_init(lut[2][1][2], base1->field);
		element_init(lut[2][2][1], base1->field);
		element_init(lut[2][2][2], base1->field);

		//element_set1(lut[0][0][0]);

		element_set(lut[1][0][0], base1);
		element_set(lut[0][1][0], base2);
		element_set(lut[0][0][1], base3);
		element_invert(lut[2][0][0], lut[1][0][0]);
		element_invert(lut[0][2][0], lut[0][1][0]);
		element_invert(lut[0][0][2], lut[0][0][1]);
		element_mul(lut[1][1][0], lut[1][0][0], lut[0][1][0]);
		element_mul(lut[1][2][0], lut[1][0][0], lut[0][2][0]);
		element_invert(lut[2][1][0], lut[1][2][0]);
		element_invert(lut[2][2][0], lut[1][1][0]);
		element_mul(lut[1][0][1], lut[1][0][0], lut[0][0][1]);
		element_mul(lut[1][0][2], lut[1][0][0], lut[0][0][2]);
		element_invert(lut[2][0][1], lut[1][0][2]);
		element_invert(lut[2][0][2], lut[1][0][1]);
		element_mul(lut[0][1][1], lut[0][1][0], lut[0][0][1]);
		element_mul(lut[0][1][2], lut[0][1][0], lut[0][0][2]);
		element_invert(lut[0][2][1], lut[0][1][2]);
		element_invert(lut[0][2][2], lut[0][1][1]);
		element_mul(lut[1][1][1], lut[1][1][0], lut[0][0][1]);
		element_mul(lut[1][1][2], lut[1][1][0], lut[0][0][2]);
		element_mul(lut[1][2][1], lut[1][2][0], lut[0][0][1]);
		element_mul(lut[1][2][2], lut[1][2][0], lut[0][0][2]);
		element_invert(lut[2][1][1], lut[1][2][2]);
		element_invert(lut[2][1][2], lut[1][2][1]);
		element_invert(lut[2][2][1], lut[1][1][2]);
		element_invert(lut[2][2][2], lut[1][1][1]);

		if (l == l1) {
			if (l == l2) {
				if (l == l3) {
					element_set(rop, lut[1][1][1]);
				} else {
					element_set(rop, lut[1][1][0]);
				}
			} else if (l == l3) {
				element_set(rop, lut[1][0][1]);
			} else {
				element_set(rop, lut[1][0][0]);
			}
		} else if (l == l2) {
			if (l == l3) {
				element_set(rop, lut[0][1][1]);
			} else {
				element_set(rop, lut[0][1][0]);
			}
		} else {
			element_set(rop, lut[0][0][1]);
		}

		for (l--; l >= 0; l--) {
			element_square(rop, rop);
			BYTE b1 = naf1->exp[l];
			BYTE b2 = naf2->exp[l];
			BYTE b3 = naf3->exp[l];

			if (l <= l1 && l <= l2 && l <= l3) {
				if (b1 != 0 || b2 != 0 || b3 != 0) {
					element_mul(rop, rop, lut[b1][b2][b3]);
				}
			} else if (l <= l1 && l <= l2) {
				if (b1 != 0 || b2 != 0) {
					element_mul(rop, rop, lut[b1][b2][0]);
				}
			} else if (l <= l1 && l <= l3) {
				if (b1 != 0 || b3 != 0) {
					element_mul(rop, rop, lut[b1][0][b3]);
				}
			} else if (l <= l2 && l <= l3) {
				if (b2 != 0 || b3 != 0) {
					element_mul(rop, rop, lut[0][b2][b3]);
				}
			} else if (l <= l1) {
				if (b1 != 0) {
					element_mul(rop, rop, lut[b1][0][0]);
				}
			} else if (l <= l2) {
				if (b2 != 0) {
					element_mul(rop, rop, lut[0][b2][0]);
				}
			} else if (b3 != 0) {
				element_mul(rop, rop, lut[0][0][b3]);
			}
		}

		naf_clear(naf1);
		naf_clear(naf2);
		naf_clear(naf3);
		//element_clear(lut[0][0][0]);
		element_clear(lut[0][0][1]);
		element_clear(lut[0][0][2]);
		element_clear(lut[0][1][0]);
		element_clear(lut[0][2][0]);
		element_clear(lut[1][0][0]);
		element_clear(lut[2][0][0]);
		element_clear(lut[0][1][1]);
		element_clear(lut[0][1][2]);
		element_clear(lut[0][2][1]);
		element_clear(lut[0][2][2]);
		element_clear(lut[1][1][0]);
		element_clear(lut[1][2][0]);
		element_clear(lut[2][1][0]);
		element_clear(lut[2][2][0]);
		element_clear(lut[1][0][1]);
		element_clear(lut[1][0][2]);
		element_clear(lut[2][0][1]);
		element_clear(lut[2][0][2]);
		element_clear(lut[1][1][1]);
		element_clear(lut[1][1][2]);
		element_clear(lut[1][2][1]);
		element_clear(lut[1][2][2]);
		element_clear(lut[2][1][1]);
		element_clear(lut[2][1][2]);
		element_clear(lut[2][2][1]);
		element_clear(lut[2][2][2]);
	}

	mpz_clear(e1);
	mpz_clear(e2);
	mpz_clear(e3);

	return;
}

void mpz_powm2(mpz_t rop, mpz_t base1, mpz_t exp1, mpz_t base2, mpz_t exp2, mpz_t mod) {
	if (mpz_is0(exp1) && mpz_is0(exp2)) {
		mpz_set_ui(rop, 1);
	} else {

		mpz_t lut;
		mpz_init(lut);
		mpz_mul(lut, base1, base2);
		mpz_mod(lut, lut, mod);

		int l1 = mpz_sizeinbase(exp1, 2) - 1;
		int l2 = mpz_sizeinbase(exp2, 2) - 1;
		int l = (l1 > l2) ? l1 - 1 : l2 - 1;

		if (l1 == l2) {
			mpz_set(rop, lut);
		} else if (l1 > l2) {
			mpz_set(rop, base1);
		} else {
			mpz_set(rop, base2);
		}

		for (; l >= 0; l--) {
			mpz_mul(rop, rop, rop);
			mpz_mod(rop, rop, mod);

			BYTE b1 = mpz_tstbit(exp1, l);
			BYTE b2 = mpz_tstbit(exp2, l);

			if (b1 && b2) {
				mpz_mul(rop, rop, lut);
				mpz_mod(rop, rop, mod);
			} else if (b1) {
				mpz_mul(rop, rop, base1);
				mpz_mod(rop, rop, mod);
			} else if (b2) {
				mpz_mul(rop, rop, base2);
				mpz_mod(rop, rop, mod);
			}
		}

		mpz_clear(lut);
	}

	return;
}

void rec_for(DWORD* sum, DWORD* prod_idx, DWORD* values, DWORD cur_depth, DWORD prod_cnt, DWORD value_cnt) {
	if (cur_depth == 0) {
		prod_idx[cur_depth] = 0;
	} else {
		prod_idx[cur_depth] = prod_idx[cur_depth - 1] + 1;
	}
	if (cur_depth < prod_cnt - 1) {
		while (prod_idx[cur_depth] < value_cnt) {
			rec_for(sum, prod_idx, values, cur_depth + 1, prod_cnt, value_cnt);
			prod_idx[cur_depth]++;
		}
	} else {
		while (prod_idx[cur_depth] < value_cnt) {
			DWORD prod = 1;
			for (DWORD i = 0; i < prod_cnt; i++) {
				prod *= values[prod_idx[i]];
			}
			*sum += prod;
			prod_idx[cur_depth]++;
		}
	}

	return;
}

void rec_for_mpz(mpz_t sum, DWORD* prod_idx, DWORD* values, DWORD cur_depth, DWORD prod_cnt, DWORD value_cnt) {
	if (cur_depth == 0) {
		prod_idx[cur_depth] = 0;
	} else {
		prod_idx[cur_depth] = prod_idx[cur_depth - 1] + 1;
	}
	if (cur_depth < prod_cnt - 1) {
		while (prod_idx[cur_depth] < value_cnt) {
			rec_for_mpz(sum, prod_idx, values, cur_depth + 1, prod_cnt,
					value_cnt);
			prod_idx[cur_depth]++;
		}
	} else {
		mpz_t prod;
		mpz_init(prod);
		while (prod_idx[cur_depth] < value_cnt) {
			mpz_init_set_ui(prod, 1);
			for (DWORD i = 0; i < prod_cnt; i++) {
				mpz_mul_ui(prod, prod, values[prod_idx[i]]);
			}
			mpz_add(sum, sum, prod);
			prod_idx[cur_depth]++;
		}
		mpz_clear(prod);
	}

	return;
}

DWORD get_elem_sym_poly(DWORD prod_cnt, DWORD* values, DWORD value_cnt) {
	DWORD i, ret;

	if (prod_cnt > value_cnt) {
		return 0;
	}

	if (prod_cnt == value_cnt) {
		ret = values[0];
		for (i = 1; i < value_cnt; i++) {
			ret *= values[i];
		}
		return ret;
	}

	switch (prod_cnt) {
	case 0:
		ret = 1;
		break;
	case 1:
		ret = values[0];
		for (i = 1; i < value_cnt; i++) {
			ret += values[i];
		}
		break;
	default:
		ret = 0;
		DWORD* prod_idx = (DWORD*) malloc(prod_cnt * sizeof(DWORD));
		rec_for(&ret, prod_idx, values, 0, prod_cnt, value_cnt);
		break;
	}

	return ret;
}

void get_elem_sym_poly_mpz(mpz_t rop, DWORD prod_cnt, DWORD* values, DWORD value_cnt) {
	DWORD i;

	if (prod_cnt > value_cnt) {
		mpz_set_ui(rop, 0);
		return;
	}

	if (prod_cnt == value_cnt) {
		mpz_init_set_ui(rop, values[0]);
		for (i = 1; i < value_cnt; i++) {
			mpz_mul_ui(rop, rop, values[i]);
		}
		return;
	}

	switch (prod_cnt) {
	case 0:
		mpz_set_ui(rop, 1);
		break;
	case 1:
		mpz_init_set_ui(rop, values[0]);
		for (i = 1; i < value_cnt; i++) {
			mpz_add_ui(rop, rop, values[i]);
		}
		break;
	default:
		mpz_set_ui(rop, 0);
		DWORD* prod_idx = (DWORD*) malloc(prod_cnt * sizeof(DWORD));
		rec_for_mpz(rop, prod_idx, values, 0, prod_cnt, value_cnt);
		break;
	}

	return;
}

int count_up(DWORD* values, DWORD array_size, DWORD max_value) {
	int ret = 0, idx, update_cnt, i;
	for (idx = array_size - 1; idx >= 0; idx--) {
		update_cnt = array_size - idx;
		if (values[idx] <= (max_value - update_cnt)) {
			values[idx]++;

			for (i = 1; (i < update_cnt) && (update_cnt > 1); i++) {
				values[idx + i] = values[idx + i - 1] + 1;
			}

			ret = 1;
			break;
		}
	}

	return ret;
}
