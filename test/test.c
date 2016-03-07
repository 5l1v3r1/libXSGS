#include <stdio.h>
#include <stdlib.h>
#include "xsgs.h"
#include "xsgs_test.h"


int main(int argc, char **argv) {
    int ret = 0;
    DWORD choice = 0;


    printf("*************************************************\n");
    printf("*						    *\n");
    printf("* Function Tests				    *\n");
    printf("* of eXtremely Short Group Signature Library    *\n");
    printf("*						    *\n");
    printf("* Author: Martin Goll			    *\n");
    printf("* Contact: Martin.Goll@rub.de		    *\n");
    printf("*						    *\n");
    printf("*************************************************\n");

    printf("\n\n+++ Main Menu +++\n");
    printf("[1] Curve Type A/D/F Test.\n");
    printf("[2] XSGS Complete Test - Generate new keys and save them to file.\n");
    printf("[3] XSGS Complete Test - Import keys from file.\n");

    printf("Select: ");

    ret = scanf("%u", &choice);

    switch(choice) {
    case 1:
		ret = xsgs_curves_test();
		break;
	case 2:
		ret = xsgs_system_test(1);
		break;
	case 3:
		ret = xsgs_system_test(0);
		break;
	default:
		break;
    }

    return ret;
}
