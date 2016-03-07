#include <stdio.h>
#include <stdlib.h>
#include "xsgs.h"
#include "xsgs_bench.h"
#include "xsgs_eval.h"


int main(int argc, char **argv) {
    int ret = 0;
    DWORD choice = 0;


    printf("*************************************************\n");
    printf("*						    *\n");
    printf("* Benchmarks / Evaluations			    *\n");
    printf("* of eXtremely Short Group Signature Library    *\n");
    printf("*						    *\n");
    printf("* Author: Martin Goll			    *\n");
    printf("* Contact: Martin.Goll@rub.de		    *\n");
    printf("*						    *\n");
    printf("*************************************************\n");

    printf("\n\n+++ Main Menu +++\n");
    printf("[1] XSGS Curve Type D/F/G Benchmark.\n");
    printf("[2] XSGS RSA Benchmark - Use keys from file.\n");
    printf("[3] XSGS SHA3 Benchmark.\n");
    printf("[4] XSGS Benchmark - Use certs and keys from file.\n");
    printf("[5] XSGS Evaluation - Use certs and keys from file.\n");
	printf("[6] XSGS CCS Paper Evaluation - Use certs and keys from file.\n");
	printf("[7] XSGS Seminar Paper Evaluation - Use certs and keys from file.\n");

    printf("Select: ");

    ret = scanf("%u", &choice);

    switch(choice) {
	case 1:
		ret = xsgs_curves_bench();
		break;
	case 2:
		ret = xsgs_rsa_bench();
		break;
	case 3:
		ret = xsgs_hash_bench();
		break;
	case 4:
		ret = xsgs_bench();
		break;
	case 5:
		ret = xsgs_eval();
		break;
	case 6:
		ret = xsgs_ccs_paper_eval();
		break;
	case 7:
		printf("*TODO* Not yet implemented. *TODO*\n");
		break;
	default:
		break;
    }

    return ret;
}
