CFLAGS=-O0 -g3 -pthread

all:
	gcc $(CFLAGS) -c syscall.S
	gcc $(CFLAGS) -c main.c
	gcc $(CFLAGS) syscall.o main.o -o fsb
#	rsync * olga:fsb

