#!/bin/bash
name=$(basename $1 .c)
mkdir -p $name
gcc -w "$1" -o $name/$name.elf
strace -o $name/$name.strace ./$name/$name.elf
awk -F'(' '{print $1}' $name/$name.strace > $name/$name.sc
sort $name/$name.sc | uniq> $name/$name.uniq_sc
