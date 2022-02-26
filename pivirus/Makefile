CC= gcc
CFLAGS= -g -nostdlib -nostartfiles -fPIC -fomit-frame-pointer
ASM= nasm
ASMFLAGS= -f elf64

all: hostile pivirus

hostile: hostile.asm 
	$(ASM) $(ASMFLAGS) -o hostile.o hostile.asm

pivirus: pivirus.c
	$(CC) pivirus.c hostile.o $(CFLAGS) -o pivirus

clean:
	rm *.o
