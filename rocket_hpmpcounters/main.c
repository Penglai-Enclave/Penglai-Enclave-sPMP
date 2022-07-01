#include <stdio.h>
#include <stdlib.h>



int main(){
	unsigned long inst, itlb, dtlb;
	__asm__ __volatile__("csrr %0, instret" : "=r"(inst));
	//read counter-3 MHPMCounter3
	__asm__ __volatile__("csrr %0, hpmcounter3" : "=r"(itlb));
	//read counter-4 MHPMCounter4
	__asm__ __volatile__("csrr %0, hpmcounter4" : "=r"(dtlb));
	fprintf(stderr, "inst: %ld, itlb miss: %ld, dtlb miss: %ld\n", inst, itlb, dtlb);
	return 0;
}
