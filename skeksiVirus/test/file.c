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

int _getuid(void)
{
        unsigned long ret;
        __asm__ volatile("mov $102, %rax\n"
                         "syscall");
         asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

void Exit(long status)
{
        __asm__ volatile("mov %0, %%rdi\n"
                         "mov $60, %%rax\n"
                         "syscall" : : "r"(status));
}

long _open(const char *path, unsigned long flags, long mode)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
                        "mov $2, %%rax\n"
                        "syscall" : : "g"(path), "g"(flags), "g"(mode));
        asm ("mov %%rax, %0" : "=r"(ret));              
        
        return ret;
}

int _close(unsigned int fd)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov $3, %%rax\n"
                        "syscall" : : "g"(fd));
        return (int)ret;
}

int _read(long fd, char *buf, unsigned long len)
{
         long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $0, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

long _write(long fd, char *buf, unsigned long len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $1, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;
}

int _fstat(long fd, void *buf)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $5, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _unlink(const char *path)
{
	   long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
			"mov $87, %%rax\n"		
			"syscall" ::"g"(path));
	asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _rename(const char *old, const char *new)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $82, %%rax\n"
                        "syscall" ::"g"(old),"g"(new));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

long _lseek(long fd, long offset, unsigned int whence)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $8, %%rax\n"
                        "syscall" : : "g"(fd), "g"(offset), "g"(whence));
        asm("mov %%rax, %0" : "=r"(ret));
        return ret;

}

int _fsync(int fd)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov $74, %%rax\n"
                        "syscall" : : "g"(fd));

        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

void *_mmap(void *addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
        long mmap_fd = fd;
        unsigned long mmap_off = off;
        unsigned long mmap_flags = flags;
        unsigned long ret;

        __asm__ volatile(
                         "mov %0, %%rdi\n"
                         "mov %1, %%rsi\n"
                         "mov %2, %%rdx\n"
                         "mov %3, %%r10\n"
                         "mov %4, %%r8\n"
                         "mov %5, %%r9\n"
                         "mov $9, %%rax\n"
                         "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
        asm ("mov %%rax, %0" : "=r"(ret));              
        return (void *)ret;
}

int _munmap(void *addr, size_t len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $11, %%rax\n"
                        "syscall" :: "g"(addr), "g"(len));
        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _mprotect(void * addr, unsigned long len, int prot)
{
        unsigned long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $10, %%rax\n"
                        "syscall" : : "g"(addr), "g"(len), "g"(prot));
        asm("mov %%rax, %0" : "=r"(ret));
        
        return (int)ret;
}

long _ptrace(long request, long pid, void *addr, void *data)
{
        long ret;

        __asm__ volatile(
                        "mov %0, %%rdi\n"
						"mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov %3, %%r10\n"
                        "mov $101, %%rax\n"
                        "syscall" : : "g"(request), "g"(pid), "g"(addr), "g"(data)
		);
        asm("mov %%rax, %0" : "=r"(ret));
        
        return ret;
}

int _prctl(long option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
        long ret;
        
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov %3, %%r10\n"
                        "mov $157, %%rax\n"
                        "syscall\n" :: "g"(option), "g"(arg2), "g"(arg3), "g"(arg4), "g"(arg5));
        asm("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _getdents64(unsigned int fd, struct linux_dirent64 *dirp,
                    unsigned int count)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $217, %%rax\n"
                        "syscall" :: "g"(fd), "g"(dirp), "g"(count));
        asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}

int _gettimeofday(struct timeval *tv, struct timezone *tz)
{
	long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $96, %%rax\n"
			"syscall" :: "g"(tv), "g"(tz));
	asm ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;

}

void _memcpy(void *dst, void *src, unsigned int len)
{
        int i;
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;

        for (i = 0; i < len; i++) {
                *d = *s;
                s++, d++;
        }

}


void Memset(void *mem, unsigned char byte, unsigned int len)
{
        unsigned char *p = (unsigned char *)mem; 
        int i = len;
        while (i--) {
                *p = byte;
                p++;
        }
}

int _printf(char *fmt, ...)
{
        int in_p;
        unsigned long dword;
        unsigned int word;
        char numbuf[26] = {0};
        __builtin_va_list alist;

        in_p;
        __builtin_va_start((alist), (fmt));

        in_p = 0;
        while(*fmt) {
                if (*fmt!='%' && !in_p) {
                        _write(1, fmt, 1);
                        in_p = 0;
                }
                else if (*fmt!='%') {
                        switch(*fmt) {
                                case 's':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts((char *)dword);
                                        break;
                                case 'u':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
                                        _puts(itoa(word, numbuf));
                                        break;
                                case 'd':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
                                        _puts(itoa(word, numbuf));
                                        break;
                                case 'x':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts(itox(dword, numbuf));
                                        break;
                                default:
                                        _write(1, fmt, 1);
                                        break;
                        }
                        in_p = 0;
                }
                else {
                        in_p = 1;
                }
                fmt++;
        }
        return 1;
}
char * itoa(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 10) + '0';
                x /= 10;
                i++;
        } while (x!=0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}
char * itox(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 16);

                /* char conversion */
                if (t[i] > 9)
                        t[i] = (t[i] - 10) + 'a';
                else
                        t[i] += '0';

                x /= 16;
                i++;
        } while (x != 0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}

int _puts(char *str)
{
        _write(1, str, _strlen(str));
        _fsync(1);

        return 1;
}

int _puts_nl(char *str)
{	
        _write(1, str, _strlen(str));
	_write(1, "\n", 1);
	_fsync(1);

        return 1;
}

size_t _strlen(char *s)
{
        size_t sz;

        for (sz=0;s[sz];sz++);
        return sz;
}

	

char _toupper(char c)
{
	if( c >='a' && c <= 'z')
		return (c = c +'A' - 'a');
	return c;
	
}

      
int _strncmp(const char *s1, const char *s2, size_t n)
{
	for ( ; n > 0; s1++, s2++, --n)
		if (*s1 != *s2)
			return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
		else if (*s1 == '\0')
			return 0;
	return 0;
}
                                               
int _strcmp(const char *s1, const char *s2)
{
	for ( ; *s1 == *s2; s1++, s2++)
		if (*s1 == '\0')
	    		return 0;
	return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
}

int _memcmp(const void *s1, const void *s2, unsigned int n)
{
        unsigned char u1, u2;

        for ( ; n-- ; s1++, s2++) {
                u1 = * (unsigned char *) s1;
                u2 = * (unsigned char *) s2;
        if ( u1 != u2) {
                return (u1-u2);
        }
    }
}





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


/*
 * end_code() gets over-written with a trampoline
 * that jumps to the original entry point.
 */
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
    _printf("%s : %d : %s\n",(char *)f2, my_size, (char *)f1);
    return 0;
}