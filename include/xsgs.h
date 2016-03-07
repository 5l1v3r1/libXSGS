#ifndef XSGS_H
#define XSGS_H


#include <gmp.h>
#include <pbc.h>
#include <openssl/ossl_typ.h>


typedef uint8_t 	BYTE;
typedef uint16_t	WORD;
typedef uint32_t	DWORD;
typedef uint64_t	QWORD;

#define CURVE_TYPE_D	1
#define CURVE_TYPE_F	2
#define CURVE_TYPE_G	3

#define RSA_PUB_KEY 0
#define RSA_PRV_KEY 1


// TYPE D CURVE PARAMETER
struct d_param_s {
  mpz_t q;	 // curve defined over F_q
  mpz_t n;	 // has order n (= q - t + 1) in F_q
  mpz_t h;	 // h * r = n, r is prime
  mpz_t r;	 // order of G1, G2, GT and Zr
  mpz_t a, b;	 // curve equation is y^2 = x^3 + ax + b
  int k;	 // embedding degree
  mpz_t nk;	 // order of curve over F_q^k
  mpz_t hk;	 // hk * r^2 = nk
  mpz_t *coeff;  // coefficients of polynomial used to extend F_q by k/2
  mpz_t nqr;	 // a quadratic nonresidue in F_q^d that lies in F_q
};
typedef struct d_param_s d_param_t[1];
typedef struct d_param_s *d_param_ptr;

// TYPE F CURVE PARAMETER
struct f_param_s {
    mpz_t q; // Curve defined over F_q.
    mpz_t r; // The order of the curve.
    mpz_t b; // E: y^2 = x^3 + b
    mpz_t beta; //beta is a quadratic nonresidue in Fq
	//we use F_q^2 = F_q[sqrt(beta)]
    mpz_t alpha0, alpha1;
	//the polynomial x^6 + alpha0 + alpha1 sqrt(beta)
	//is irreducible over F_q^2[x], so
	//we can extend F_q^2 to F_q^12 using the
	//sixth root of -(alpha0 + alpha1 sqrt(beta))
};
typedef struct f_param_s f_param_t[1];
typedef struct f_param_s *f_param_ptr;

// TYPE G CURVE PARAMETER
struct g_param_s {
  mpz_t q;    // Curve defined over F_q.
  mpz_t n;    // n = #E(F_q) (= q - t + 1)
  mpz_t h;    // h * r = n, r is prime
  mpz_t r;
  mpz_t a, b; // E: y^2 = x^3 + ax + b

  // k = 10 for these curves.
  mpz_t nk;	 // #E(F_q^k)
  mpz_t hk;	 // hk * r^2 = nk
  mpz_t *coeff;  //Coefficients of polynomial used to extend F_q by k/2
  mpz_t nqr;	 // Quadratic nonresidue in F_q^d that lies in F_q.
};
typedef struct g_param_s g_param_t[1];
typedef struct g_param_s *g_param_ptr;

// GROUP PUBLIC KEY
typedef struct {
    pbc_param_ptr param;    // type d curve parameter
    pairing_ptr pairing;    // description of bilinear map e, used groups Group1, Group2, GroupT, prime p, ...
    element_t G1;	    // G1 = psi(G2), generator in Group1
    element_t K;	    // additional and independent generator in Group1
    element_t H;	    // additional and independent generator in Group1
    element_t G;	    // additional and independent generator in Group1
    element_t G2;	    // random generator in Group2
    element_t W;	    // W = (ik=gamma) * G2
} XSGS_PUBLIC_KEY;

// CACHE WITH PRECALCULATED ELEMENTS
typedef struct {
	element_t* LUT_G;		// used in sign
    element_t* LUT_H;		// used in sign / batch verify
    element_t* LUT_K;		// used in sign / verify / batch verify
    element_t* LUT_G2;		// used in verify
    element_t* LUT_W;		// used in verify
    element_t* LUT_A_G2;	// used in sign
    element_t* LUT_G1_G2;	// used in verify
    element_t* LUT_H_G2;	// used in sign / verify
    element_t* LUT_H_W; 	// used in sign / verify
} XSGS_CACHE;

// NAF
typedef struct {
	DWORD len;
	BYTE* exp;
}XSGS_NAF;

// GROUP MANAGER'S SECRET KEY
typedef struct {
    element_t gamma;	// random element from Zp*
} XSGS_ISSUER_KEY;

// OPENER'S SECRET KEY
typedef struct {
    element_t xi1;  // random element from Zp
    element_t xi2;  // random element from Zp
} XSGS_OPENER_KEY;

// JOIN PHASE DATA 1 - 4
#define PAILLIER_MODULO_BITS 1024
#define JOIN_HASH_BITS 256
typedef struct {
    DWORD len;
    BYTE* sig;
} RSA_SIGNATURE;
typedef struct {
	mpz_t n;	    //public modulus n = p q
	mpz_t g;	    // g = n + 1 (cached to avoid recomputing)
	mpz_t n_squared;    // cached to avoid recomputing
} XSGS_PAILLIER_PUBKEY;
typedef struct {
    element_t C;
    struct {
	mpz_t c;
	BYTE* hash;
	mpz_t s;
    } U;
} XSGS_JOIN_PHASE1;
typedef struct {
    element_t A;
    struct {
	element_t T1;
	element_t T2;
	BYTE* hash;
	element_t s;
    } V;
} XSGS_JOIN_PHASE2;
typedef struct {
    RSA_SIGNATURE S;
} XSGS_JOIN_PHASE3;
typedef struct {
    element_t x;
} XSGS_JOIN_PHASE4;

// REVOCATION PHASE DATA 1 - 2
typedef struct	{
	element_t x;
	element_t G1;
	element_t K;
	element_t H;
	element_t G;
	element_t G2;
	element_t W;
} XSGS_REVOKE_PHASE1;
typedef struct	{
	RSA_SIGNATURE S;
} XSGS_REVOKE_PHASE2;

// USER'S CERTIFICATE
typedef struct {
    element_t A;
    element_t x;
} XSGS_USER_CERT;

// USER'S SECRET KEY
typedef struct {
    element_t y;
} XSGS_USER_KEY;

// USER'S DATABASE ENTRY
typedef struct {
    XSGS_USER_CERT UCert;
    element_t C;
    RSA_SIGNATURE S;
} XSGS_USER_DB_ENTRY;

// GROUP SIGNATURE
#define SIGNATURE_HASH_BITS 256
typedef struct {
    element_t T1;
    element_t T2;
    element_t T3;
    element_t T4;
    BYTE* c;
    element_t s_alpha;
    element_t s_beta;
    element_t s_x;
    element_t s_z;
} XSGS_SIGNATURE;
typedef struct {
    DWORD msg_len;
    BYTE* msg;
    XSGS_SIGNATURE sigma;
} XSGS_SIGNED_MSG;

// GROUP SIGNATURE (BATCH)
#define BATCH_SIGNATURE_HASH_BITS 256
typedef struct {
    element_t T1;
    element_t T2;
    element_t T3;
    element_t T4;
    element_t R1;
    element_t R2;
    element_t R3;
    element_t R4;
    element_t s_alpha;
    element_t s_beta;
    element_t s_x;
    element_t s_z;
} XSGS_BATCH_SIGNATURE;
typedef struct	{
    DWORD msg_len;
    BYTE* msg;
    XSGS_BATCH_SIGNATURE sigma;
} XSGS_BATCH_SIGNED_MSG;

// OPEN SIGNATURE DATA
#define OPEN_HASH_BITS 256
typedef struct {
    element_t A;
    struct {
	BYTE* hash;
	element_t s_alpha;
	element_t s_beta;
	element_t s_gamma;
	element_t s_delta;
    } tau;
    RSA_SIGNATURE S;
} XSGS_OPEN_DATA;

// Per-element data. Elements of this group are points on the elliptic curve.
typedef struct {
  int inf_flag;    // inf_flag == 1 means O, the point at infinity.
  element_t x, y;  // Otherwise we have the finite point (x, y).
} *point_ptr;


// xsgs utility functions
void get_rand_buf(BYTE* buf, DWORD len);
void init_rand(gmp_randstate_t rand_state, DWORD bytes);
DWORD mpz_to_bytes(unsigned char *data, mpz_t z);
DWORD mpz_length_in_bytes(mpz_t z);
void mpz_from_bytes(mpz_t z, unsigned char *data, DWORD len);
void mpz_from_hash(mpz_t z, void *data, DWORD len);
int print_dir_selection(char* dir, DWORD idx, char* filter, DWORD flen);
char* get_selected_filename(char* dir, DWORD idx, char* filter, DWORD flen, DWORD choice);

// xsgs commitment functions - Paillier
XSGS_PAILLIER_PUBKEY* xsgs_paillier_gen(int mbits);
XSGS_PAILLIER_PUBKEY* xsgs_ppk_import_buf(BYTE* data);
DWORD xsgs_ppk_export_buf(BYTE** data, XSGS_PAILLIER_PUBKEY* ppk);
XSGS_PAILLIER_PUBKEY* xsgs_ppk_import_file(char* filename);
int xsgs_ppk_export_file(char* filename, XSGS_PAILLIER_PUBKEY* ppk);
void ppk_clear(XSGS_PAILLIER_PUBKEY* ppk);

// xsgs hash function - Keccak (SHA3)
int xsgs_hash(BYTE* data, DWORD dlen, BYTE* hash, DWORD hlen);

// xsgs RSA functions
EVP_PKEY* xsgs_rsa_get_pkey_from_file(char* pem_file, BYTE type);
int xsgs_rsa_get_size(char* pem_file, BYTE type);
int xsgs_rsa_sign(char* pem_file, BYTE* msg, DWORD msg_len, BYTE** sig, DWORD* sig_len);
int xsgs_rsa_verify(char* pem_file, BYTE* msg, DWORD msg_len, BYTE* sig, DWORD sig_len);
int xsgs_rsa_encrypt(char* pem_file, BYTE* pt, DWORD pt_len, BYTE** ct, DWORD* ct_len);
int xsgs_rsa_decrypt(char* pem_file, BYTE* ct, DWORD ct_len, BYTE** pt, DWORD* pt_len);

// cache and performance optimized arithmetic functions
element_t* lut_init(element_t base, DWORD size);
void lut_clear(element_t* lut, DWORD size);
XSGS_CACHE* cache_init(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert);
void cache_clear(XSGS_CACHE* cache, XSGS_PUBLIC_KEY* gpk);
void fixed_base_exp(element_t rop, element_t* lut, element_t exp);
void fixed_base_exp2(element_t rop, element_t* lut1, element_t exp1, element_t* lut2, element_t exp2);
void fixed_base_exp3(element_t rop, element_t* lut1, element_t exp1, element_t* lut2, element_t exp2, element_t* lut3, element_t exp3);
XSGS_NAF* naf_init(mpz_t exp, mpz_t mod);
void naf_clear(XSGS_NAF* naf);
void fixed_base_exp_naf(element_t rop, element_t* lut, element_t exp);
void fixed_base_exp_naf2(element_t rop, element_t* lut1, element_t exp1, element_t* lut2, element_t exp2);
void fixed_base_exp_naf3(element_t rop, element_t* lut1, element_t exp1, element_t* lut2, element_t exp2, element_t* lut3, element_t exp3);
void element_pow_naf_mpz(element_t rop, element_t base, mpz_t e);
void element_pow_naf(element_t rop, element_t base, element_t exp);
void element_pow_naf2_mpz(element_t rop, element_t base1, mpz_t exp1, element_t base2, mpz_t exp2);
void element_pow_naf2(element_t rop, element_t base1, element_t exp1, element_t base2, element_t exp2);
void element_pow_naf3(element_t rop, element_t base1, element_t exp1, element_t base2, element_t exp2, element_t base3, element_t exp3);
void mpz_powm2(mpz_t rop, mpz_t base1, mpz_t exp1, mpz_t base2, mpz_t exp2, mpz_t mod);
DWORD get_elem_sym_poly(DWORD prod_cnt, DWORD* values, DWORD value_cnt);
void get_elem_sym_poly_mpz(mpz_t rop, DWORD t, DWORD* j, DWORD w);
int count_up(DWORD* values, DWORD array_size, DWORD max_value);

// xsgs generation algorithms
int gen_dcurve_params(pbc_cm_t cm, void *data);
int gen_gcurve_param(pbc_cm_t cm, void *data);
pbc_param_ptr xsgs_find_curve_d(DWORD d, DWORD b);
pbc_param_ptr xsgs_find_curve_f(DWORD rbits);
pbc_param_ptr xsgs_find_curve_g(DWORD d, DWORD b);
int xsgs_generate_curve(BYTE type, char** lpFilename);
pbc_param_ptr xsgs_select_curve_param(char* curve_dir, char* curve_name_prefix, DWORD prefix_length);
void xsgs_gm_gen(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, pbc_param_ptr param);
void xsgs_opener_gen(XSGS_PUBLIC_KEY* gpk, XSGS_OPENER_KEY* ok);
int xsgs_generate_group_keys(void);

// xsgs user join
void xsgs_user_join_phase1(XSGS_PUBLIC_KEY* gpk, XSGS_USER_KEY* uk, XSGS_PAILLIER_PUBKEY* ppk, XSGS_JOIN_PHASE1* jpd1);
int xsgs_user_join_phase2(XSGS_PUBLIC_KEY* gpk, XSGS_USER_DB_ENTRY* udbe, XSGS_ISSUER_KEY* ik, XSGS_PAILLIER_PUBKEY* ppk, XSGS_JOIN_PHASE1* jpd1, XSGS_JOIN_PHASE2* jpd2);
int xsgs_user_join_phase3(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_JOIN_PHASE1* jpd1, XSGS_JOIN_PHASE2* jpd2, XSGS_JOIN_PHASE3* jpd3, char* usk_pem_filename);
int xsgs_user_join_phase4(XSGS_PUBLIC_KEY* gpk, XSGS_USER_DB_ENTRY* udbe, XSGS_JOIN_PHASE3* jpd3, XSGS_JOIN_PHASE4* jpd4, char* upk_pem_filename);
int xsgs_user_join_phase5(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_JOIN_PHASE4* jpd4);
int xsgs_user_join_offline(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_USER_CERT** ucert, XSGS_USER_KEY** uk, XSGS_USER_DB_ENTRY** udbe, char* usk_pem_filename);

// xsgs revocation algorithms
void xsgs_update_gpk(XSGS_PUBLIC_KEY* gpk, XSGS_REVOKE_PHASE1* rpd1);
void xsgs_user_revoke_phase1(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_USER_DB_ENTRY* udbe, XSGS_REVOKE_PHASE1** rpd1);
int xsgs_user_revoke_phase2(XSGS_PUBLIC_KEY* gpk, XSGS_USER_KEY* uk, XSGS_USER_CERT* ucert, char* usk_pem_filename, XSGS_REVOKE_PHASE1* rpd1, XSGS_REVOKE_PHASE2** rpd2);
int xsgs_user_revoke_phase3(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_USER_DB_ENTRY* udbe, char* upk_pem_filename, XSGS_REVOKE_PHASE1* rpd1, XSGS_REVOKE_PHASE2* rpd2);

// xsgs sign algorithms
void xsgs_sign(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_SIGNED_MSG* sig_msg);
void xsgs_sign_cache(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, XSGS_SIGNED_MSG* sig_msg);
void xsgs_batch_sign(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_BATCH_SIGNED_MSG** sig_msg_list, DWORD list_size);
void xsgs_batch_sign_cache(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG** sig_msg_list, DWORD list_size);

// xsgs verify algorithms
int xsgs_verify(XSGS_PUBLIC_KEY* gpk, XSGS_SIGNED_MSG* sig_msg);
int xsgs_verify_cache(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_SIGNED_MSG* sig_msg);
void xsgs_batch_verify(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status);
void xsgs_batch_verify2(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status);
void xsgs_batch_verify_cache(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status);
void xsgs_batch_verify_cache2(XSGS_PUBLIC_KEY* gpk, XSGS_CACHE* cache, XSGS_BATCH_SIGNED_MSG** sig_list, DWORD list_size, BYTE* sig_status);

// xsgs open signature algorithms
XSGS_OPEN_DATA* xsgs_open_sig(XSGS_PUBLIC_KEY* gpk, XSGS_OPENER_KEY* ok, XSGS_SIGNED_MSG* sig);
XSGS_OPEN_DATA* xsgs_open_batch_sig(XSGS_PUBLIC_KEY* gpk, XSGS_OPENER_KEY* ok, XSGS_BATCH_SIGNED_MSG* sig);

// xsgs judge opened signature
int xsgs_judge_sig(XSGS_PUBLIC_KEY* gpk, XSGS_SIGNED_MSG* sig, XSGS_OPEN_DATA* od, char* upk_pem_filename);
int xsgs_judge_batch_sig(XSGS_PUBLIC_KEY* gpk, XSGS_BATCH_SIGNED_MSG* sig, XSGS_OPEN_DATA* od, char* upk_pem_filename);

// xsgs cleanup functions
void gpk_clear(XSGS_PUBLIC_KEY* gpk);
void ik_clear(XSGS_ISSUER_KEY* ik);
void ok_clear(XSGS_OPENER_KEY* ok);
void ucert_clear(XSGS_USER_CERT* ucert);
void uk_clear(XSGS_USER_KEY* uk);
void udbe_clear(XSGS_USER_DB_ENTRY* udbe);
void sm_clear(XSGS_SIGNED_MSG* sig);
void bsm_clear(XSGS_BATCH_SIGNED_MSG* sig);
void jpd1_clear(XSGS_JOIN_PHASE1* jp);
void jpd2_clear(XSGS_JOIN_PHASE2* jp);
void jpd3_clear(XSGS_JOIN_PHASE3* jp);
void jpd4_clear(XSGS_JOIN_PHASE4* jp);
void od_clear(XSGS_OPEN_DATA* od);
void rpd1_clear(XSGS_REVOKE_PHASE1* rpd);
void rpd2_clear(XSGS_REVOKE_PHASE2* rpd);

// system parameter import/export functions
pbc_param_ptr xsgs_param_import_buf(BYTE* buf);
DWORD xsgs_param_export_buf(BYTE** buf, pbc_param_ptr p);
pbc_param_ptr xsgs_param_import_file(char* filename);
int xsgs_param_export_file(char* filename, pbc_param_ptr p);

// generation data import/export functions
XSGS_PUBLIC_KEY* xsgs_gd1_import_buf(BYTE* data);
DWORD xsgs_gd1_export_buf(BYTE** data, XSGS_PUBLIC_KEY* gpk);
void xsgs_gd2_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_gd2_export_buf(BYTE** data, XSGS_PUBLIC_KEY* gpk);

// group public key import/export functions
XSGS_PUBLIC_KEY* xsgs_gpk_import_buf(BYTE* data);
DWORD xsgs_gpk_export_buf(BYTE** data, XSGS_PUBLIC_KEY* gpk);
XSGS_PUBLIC_KEY* xsgs_gpk_import_file(char* filename);
int xsgs_gpk_export_file(char* filename, XSGS_PUBLIC_KEY* gpk);

// group manager key import/export functions
XSGS_ISSUER_KEY* xsgs_ik_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_ik_export_buf(BYTE** data, XSGS_ISSUER_KEY* ik);
XSGS_ISSUER_KEY* xsgs_ik_import_file(XSGS_PUBLIC_KEY* gpk, char* filename);
int xsgs_ik_export_file(char* filename, XSGS_ISSUER_KEY* ik);

// opener key import/export functions
XSGS_OPENER_KEY* xsgs_ok_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_ok_export_buf(BYTE** data, XSGS_OPENER_KEY* ok);
XSGS_OPENER_KEY* xsgs_ok_import_file(XSGS_PUBLIC_KEY* gpk, char* filename);
int xsgs_ok_export_file(char* filename, XSGS_OPENER_KEY* ok);

// user cert import/export functions
XSGS_USER_CERT* xsgs_ucert_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_ucert_export_buf(BYTE** data, XSGS_USER_CERT* ucert);
XSGS_USER_CERT* xsgs_ucert_import_file(XSGS_PUBLIC_KEY* gpk, char* filename);
int xsgs_ucert_export_file(char* filename, XSGS_USER_CERT* ucert);

// user key import/export functions
XSGS_USER_KEY* xsgs_uk_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_uk_export_buf(BYTE** data, XSGS_USER_KEY* uk);
XSGS_USER_KEY* xsgs_uk_import_file(XSGS_PUBLIC_KEY* gpk, char* filename);
int xsgs_uk_export_file(char* filename, XSGS_USER_KEY* uk);

// user database entry import/export functions
XSGS_USER_DB_ENTRY* xsgs_udbe_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_udbe_export_buf(BYTE** data, XSGS_USER_DB_ENTRY* udbe);
XSGS_USER_DB_ENTRY* xsgs_udbe_import_file(XSGS_PUBLIC_KEY* gpk, char* filename);
int xsgs_udbe_export_file(char* filename, XSGS_USER_DB_ENTRY* udbe);

// join phase data 1-4 import/export functions
XSGS_JOIN_PHASE1* xsgs_jpd1_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_jpd1_export_buf(BYTE** data, XSGS_JOIN_PHASE1* jpd1);
XSGS_JOIN_PHASE2* xsgs_jpd2_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_jpd2_export_buf(BYTE** data, XSGS_JOIN_PHASE2* jpd2);
XSGS_JOIN_PHASE3* xsgs_jpd3_import_buf(BYTE* data);
DWORD xsgs_jpd3_export_buf(BYTE** data, XSGS_JOIN_PHASE3* jpd3);
XSGS_JOIN_PHASE4* xsgs_jpd4_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_jpd4_export_buf(BYTE** data, XSGS_JOIN_PHASE4* jpd4);

// revocation phase data 1-2 import/export functions
XSGS_REVOKE_PHASE1* xsgs_rpd1_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_rpd1_export_buf(BYTE** data, XSGS_REVOKE_PHASE1* rpd1);
XSGS_REVOKE_PHASE2* xsgs_rpd2_import_buf(BYTE* data);
DWORD xsgs_rpd2_export_buf(BYTE** data, XSGS_REVOKE_PHASE2* rpd2);

// signed message import/export functions
XSGS_SIGNED_MSG* xsgs_sm_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_sm_export_buf(BYTE** data, XSGS_SIGNED_MSG* sm);
XSGS_BATCH_SIGNED_MSG* xsgs_bsm_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_bsm_export_buf(BYTE** data, XSGS_BATCH_SIGNED_MSG* bsm);

// open data import/export functions
XSGS_OPEN_DATA* xsgs_od_import_buf(XSGS_PUBLIC_KEY* gpk, BYTE* data);
DWORD xsgs_od_export_buf(BYTE** data, XSGS_OPEN_DATA* od);


#endif // XSGS_H
