#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv)
{
	// printf will execute a write syscall (no. 1)	
	printf("hello test 1\n"); // syscall 1
	printf("hello test 2\n"); // syscall 1
	FILE *fp;
	char buff[255];
	// fopen will execute an openat syscall (no. 257 - or 2 if it was open)
	fp = fopen("/home/lennertfranssens/Documents/thesis/bpf_demo/hello", "r");
	// fscanf will execute a read syscall (no. 0)
	fscanf(fp, "%s", buff);
	// fclose will execute a close syscall (no. 3)
	fclose(fp);
	printf("%s\n", buff);
	return 0;

}
