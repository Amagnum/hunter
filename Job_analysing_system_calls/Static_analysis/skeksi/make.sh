#!/bin/bash
name=$(basename $1 .c)
mkdir -p $name
gcc -w -g -static -N -O0 -D INFECT_PLTGOT -fno-stack-protector -nostdlib -fpic "$1" -o $name/$name.elf
gcc -Wall -g -no-pie -z noseparate-code ./sweet.c -o ./$name/target.elf
./$name/target.elf
# strace -o $name/$name.strace ./$name/$name.elf
# awk -F'(' '{print $1}' $name/$name.strace > $name/$name.sc
# sort $name/$name.sc | uniq > $name/$name.uniq_sc
# ./$name/target.elf
