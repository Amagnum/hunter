#!/bin/bash
gcc -o virus ref_virus2.c
gcc -o sweet sweet.c
echo "V: running virus"  
./virus #running virus
echo "
Virus size"
wc ./virus -c
echo "S: infecting first sweet file"
./sweet #infected sweet
echo "
S: Creating another healthy file
"
gcc -o sweet2 sweet.c
echo "S: Running infected file"
./sweet
echo "S2: second file infected!!"
./sweet2
echo "
Removing executables"
rm sweet sweet2 virus
