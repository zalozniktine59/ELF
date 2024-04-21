CC = gcc -m64
CFLAGS = -Wall -Wextra -Wpedantic -Werror

all: build run

build: build_elf_changer build_hello

run:
	./elf_changer -h hello

clean:
	rm -f elf_changer hello

build_elf_changer:
	$(CC) $(CFLAGS) -o elf_changer main.c

build_hello:
	$(CC) $(CFLAGS) -o hello hello.c