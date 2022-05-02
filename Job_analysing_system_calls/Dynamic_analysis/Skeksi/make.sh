#!/bin/bash
strip virus
objdump -d -M intel --no-show-raw-insn --start-address 0x0000000000000800 --stop-address 0x0000000000000db4 virus | sed 1,7d | awk "{print $2}" | sed 's/^ *//g' | sed 's/  */ /g' | tr '\t' ' ' | tr -s '\n' | awk '{print $2}' > main_disassembly_intel_extracted.txt
