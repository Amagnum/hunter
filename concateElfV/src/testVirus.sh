#!/bin/bash
gcc -o virus virus.c
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
gcc -o sweet_diff sweet.c
echo "S: Running infected file"
./sweet
echo "S2: second file infected!!"
./sweet_diff
echo "
Removing executables"
rm sweet sweet_diff virus
