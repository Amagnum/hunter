#!/bin/bash
objdump -d -M intel --no-show-raw-insn --start-address 0x00000000000014e0 --stop-address 0x00000000000027c4 virus.elf | sed 1,7d | awk "{print $2}" | sed 's/^ *//g' | sed 's/  */ /g' | tr '\t' ' ' | tr -s '\n' | awk '{print $2}' > main_disassembly_intel_extracted.txt
