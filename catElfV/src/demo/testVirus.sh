#!/bin/bash
gcc -o virus virus_infWhile.c
echo "#include<stdio.h>
int main(){
    printf(\"Sweet World!\n\");
    return 0;
}" > sweet.c
gcc -o sweet sweet.c
echo "V: running virus"  
./virus #running virus
echo -ne "\nVirus size: "
wc ./virus -c
echo -e "\nS: infecting first sweet file"
./sweet #infected sweet
# echo -e "\nS: Creating another healthy file\n"
gcc -o sweet_diff sweet.c
echo "S: Infecting another file"
./sweet > /dev/null
echo "S2: second file infected!!"
./sweet_diff
echo -e "\nRemoving executables"
#rm sweet* virus
