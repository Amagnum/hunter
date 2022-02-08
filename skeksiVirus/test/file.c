#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <link.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <sys/time.h>
void Exit(long);

#define __ASM__ asm __volatile__

#define PIC_RESOLVE_ADDR(target) (get_rip() - ((char *)&get_rip_label - (char *)target))

extern long get_rip_label;


unsigned long get_rip(void)
{
	long ret;
	__asm__ __volatile__ 
	(
	"call get_rip_label	\n"
       	".globl get_rip_label	\n"
       	"get_rip_label:		\n"
        "pop %%rax		\n"
	"mov %%rax, %0" : "=r"(ret)
	);

	return ret;
}

void end_code() 
{
	Exit(0);

}

void dummy_marker()
{
	__ASM__("nop");
}

int main(){
    void (*f1)(void) = (void (*)())PIC_RESOLVE_ADDR(&end_code);
	void (*f2)(void) = (void (*)())PIC_RESOLVE_ADDR(&dummy_marker);
    int my_size= (int)((char *)f2 - (char *)f1);
    printf("%s : %d : %s\n",(char *)f2, my_size, (char *)f1);
    return 0;
}

void Exit(long status)
{
        __asm__ volatile("mov %0, %%rdi\n"
                         "mov $60, %%rax\n"
                         "syscall" : : "r"(status));
}