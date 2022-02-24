#include <stdio.h>

int main(){
	FILE *fd=fopen("./test.txt","r");
	char str[500];
	while(fscanf(fd,"%s", str)!=EOF){
         printf("%s ", str);
    }
	fclose(fd);
	return 0;
}
