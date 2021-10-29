#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv) {

	printf("hello test 1\n"); // syscall 1
	printf("hello test 2\n"); // syscall 1
	FILE *fp;
	char buff[255];
	fp = fopen("/home/lennertfranssens/Documents/bpf/hello", "r"); // syscall 2 or 257
	fscanf(fp, "%s", buff);
	fclose(fp); // syscall 3
	printf("%s\n", buff); // syscall 1
	return 0;

}
