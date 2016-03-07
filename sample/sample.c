#include <stdio.h>
#include <stdlib.h>
#include "xsgs.h"


int main(int argc, char **argv) {
    int ret = 0;
    DWORD choice = 0;


    printf("*************************************************\n");
    printf("*						    *\n");
    printf("* Sample application			    *\n");
    printf("* of eXtremely Short Group Signature Library    *\n");
    printf("*						    *\n");
    printf("* Author: Martin Goll			    *\n");
    printf("* Contact: Martin.Goll@rub.de		    *\n");
    printf("*						    *\n");
    printf("*************************************************\n");

    printf("\n\n+++ Main Menu +++\n");
    printf("[1] XSGS Curve Gen - Generate type D curve parameter. Save curve parameter to file.\n");
    printf("[2] XSGS Curve Gen - Generate type F curve parameter. Save curve parameter to file.\n");
    printf("[3] XSGS Curve Gen - Generate type G curve parameter. Save curve parameter to file.\n");
    printf("[4] XSGS Group Gen - Generate GPK, IK and OK. Save keys to key store.\n");
    printf("[5] XSGS User Join - Join a user to existing group. Export user UDBE, UCert and UK to file.\n");
    printf("[6] XSGS User  Rev - Revoke a user and update UCerts from other users.\n");
    printf("[7] XSGS Signature - GSign(msg), GVrfy(sig), Open(sig) and Judge(od).\n");

    printf("Select: ");

    ret = scanf("%u", &choice);

    switch(choice) {
	case 1:
		ret = xsgs_generate_curve(CURVE_TYPE_D, NULL);
		break;
	case 2:
		ret = xsgs_generate_curve(CURVE_TYPE_F, NULL);
		break;
	case 3:
		ret = xsgs_generate_curve(CURVE_TYPE_G, NULL);
		break;
	case 4:
		ret = xsgs_generate_group_keys();
		break;
	case 5:
		printf("\n\n+++ eXtremely Short Group Signature - Join a user to group (complete offline) +++\n\n");
		//ret = xsgs_user_join_offline(gpk, ik, &ucert, &uk, &udbe, "key_store/test-2048.key");
		ret = 0;
		break;
	case 6:
		printf("\n\n*TODO* XSGS Revocation *TODO*\n\n");
		ret = 0;
		break;
	case 7:
		printf("\n\n*TODO* XSGS Signature *TODO*\n\n");
		ret = 0;
		break;
	default:
		break;
    }

    return ret;
}
