#!/bin/bash
gcc -w file1.c -o exe1
gcc -w file2.c -o exe2
gcc -w file3.c -o exe3
gcc -w file4.c -o exe4

strace -o strace_exe1 ./exe1
strace -o strace_exe2 ./exe2 2 3 4
strace -o strace_exe3 ./exe3
strace -o strace_exe4 ./exe4

cat strace_exe1 | awk -F\( '{print $1}' > str_exe1
cat strace_exe2 | awk -F\( '{print $1}' > str_exe2
cat strace_exe3 | awk -F\( '{print $1}' > str_exe3
cat strace_exe4 | awk -F\( '{print $1}' > str_exe4

# rm strace_exe*
