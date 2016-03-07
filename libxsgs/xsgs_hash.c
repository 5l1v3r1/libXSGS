#include "KeccakNISTInterface.h"
#include "xsgs.h"

int xsgs_hash(BYTE* data, DWORD dlen, BYTE* hash, DWORD hlen) {
	return Hash(hlen, data, dlen, hash);
}
