#!/usr/bin/env bash
gcc -Wall sweet.c -o sweet
#readelf -a sweet > readelf.txt
#objdump -d sweet > disassembly_AT_and_T.txt
#objdump -M intel -d sweet > disassembly_intel.txt
#strace -v -o stracedFile.txt ./sweet > output.txt
#hexdump -v -C sweet > hexdump.txt
#objdump --full-contents --section=.comment sweet
# To read the content of a section in human readable form `readelf -p .dynstr ./sweet`
