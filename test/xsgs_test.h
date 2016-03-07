#ifndef XSGS_TEST_H
#define XSGS_TEST_H


#include "xsgs.h"


// test functions
void xsgs_print_group_elements(pbc_param_ptr param, char type);
int xsgs_curves_test(void);
XSGS_PAILLIER_PUBKEY* xsgs_ppk_gen_test(void);
void xsgs_gen_test(pbc_param_ptr param, XSGS_PUBLIC_KEY** gpk, XSGS_ISSUER_KEY** ik, XSGS_OPENER_KEY** ok);
int xsgs_join_test(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_PAILLIER_PUBKEY* ppk, XSGS_USER_CERT** ucert, XSGS_USER_KEY** uk, XSGS_USER_DB_ENTRY** udbe, char* rsa_cert_name, char* rsa_key_name);
int xsgs_signature_test(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_OPENER_KEY* ok, XSGS_USER_DB_ENTRY* udbe, char* rsa_cert_name, BYTE cache_ctl);
int xsgs_batch_signature_test(XSGS_PUBLIC_KEY* gpk, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_OPENER_KEY* ok, XSGS_USER_DB_ENTRY* udbe, char* rsa_cert_name, BYTE cache_ctl);
int xsgs_revocation_test(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_USER_CERT* ucert, XSGS_USER_KEY* uk, XSGS_USER_DB_ENTRY* udbe, char* rsa_cert_name, char* rsa_key_name);
void xsgs_io_test(XSGS_PUBLIC_KEY* gpk, XSGS_ISSUER_KEY* ik, XSGS_OPENER_KEY* ok, XSGS_USER_CERT* ucert, XSGS_USER_DB_ENTRY* udbe);
int xsgs_system_test(char gen_export);


#endif // XSGS_TEST_H
