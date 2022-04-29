#!/bin/bash
gcc -w main.c -o main
strip main
objdump -d -M intel --no-show-raw-insn --start-address 0x0000000000001260 --stop-address 0x00000000000019a4 main | sed 1,7d | awk "{print $2}" | sed 's/^ *//g' | sed 's/  */ /g' | tr '\t' ' ' | tr -s '\n' | awk '{print $2}' > main_disassembly_intel_extracted.txt
