#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

int main(int argc, char **argv)
{
	pid_t pid;
	int status;

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <prog> <arg1> ... <argN>\n", argv[0]);
		return 1;
	}

	if ((pid = fork()) == 0)
	{
		/* CHILD */
		
		////////////////////////////////////////////////////////
		//						      //
		//		TODO: reverse the filter	      //
		//		only allow some syscalls	      //
		//		and trace all other sys-	      //
		//		calls.				      //
		//                                                    //
		////////////////////////////////////////////////////////

		// trace write, read and openat syscall (openat is used on ubuntu rather than open)
		// NOTE: execve (no. 59) is always traced!
		// TODO: you can uncomment the lines of __NR_close to demonstrate that this is allowed and not traced if not in the filter (purpose of the whole demonstration)
		struct sock_filter filter[] = {
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 1),
			BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 1),
                        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 1),
                        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
			//BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_close, 0, 1), // syscall number 3, takes 1 argument: int fd (most of the time it is 3, the first free file descriptor)
                        //BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
			BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
		};
		
		// set filter
		struct sock_fprog prog = {
			.filter = filter,
			.len = (unsigned short) (sizeof(filter)/sizeof(filter[0])),
		};
		
		// ptrace (this) forked child
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		
		// avoid the need for CAP_SYS_ADMIN
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		{
			perror("prctl(PR_SET_NO_NEW_PRIVS)");
			return 1;
		}
		
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
		{
			perror("when setting seccomp filter");
			return 1;
		}
		
		// send SIGSTOP signal to this forked process
		kill(getpid(), SIGSTOP);
		
		// some commands if not executing in execve
		// we see that this will not introduce execve (59) syscalls and has less open (2) syscalls
		/*// printf will execute a write syscall (no. 1)
		printf("hello test 1\n");
		printf("hello test 2\n");
		FILE *fp;
		char buff[255];
		// fopen will execute an openat syscall (no. 257 - or 2 if it was open)
		fp = fopen("/home/lennertfranssens/Documents/bpf/hello", "r");
		// fscanf will execute a read syscall (no. 0)
		fscanf(fp, "%s", buff);
		// fclose will execute a close syscall (no. 3)
		fclose(fp);
		printf("%s\n", buff);
		return 0;*/
		
		// count arguments length (number of characters + space or \0)
		int argv_len = 0;
		for (int i = 1; i < argc; ++i)
	       	{
			if (argv[i])
			{
				argv_len += strlen(argv[i]) + 1;
			}
		}
		// make new array of characters to store the arguments (program to execute in execve and its parameters)
		char new_argv[argv_len + 1];
		new_argv[0] = '\0';
		for (int i = 1; i < argc; ++i)
		{
			if (i > 1)
			{
				strcat(new_argv, " ");
			}
			strcat(new_argv, argv[i]);
		}
		// construct argument for execve
		char* execve_args[] = {(char*)"sh", (char*)"-c", new_argv, NULL};
		return execv("/bin/bash", execve_args);
	} else {
		/* PARENT */

		waitpid(pid, &status, 0);
		ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
		
		while (1)
		{
			//ptrace(PTRACE_SYSCALL, pid, 0, 0); // tracks all system calls and not only the filtered (not the purpose of this program!!!)
			ptrace(PTRACE_CONT, pid, 0, 0);
			waitpid(pid, &status, 0);
			printf("--------------------------------\n");
			printf("[waitpid status: 0x%08x]\n", status);
			
			if (WSTOPSIG(status) == (SIGTRAP|0x80))
			{
				printf("SIGTRAP|0x80\n");
			} else if (WSTOPSIG(status) == SIGTRAP) {
				long syscall_no = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);
				printf("syscall number: %ld\n", syscall_no);
				printf("SIGTRAP\n");
				// get some arguments of the syscall
				struct user_regs_struct regs;
				// first argument is 1 if syscall is write (1) and 3 (first free file descriptor) if syscall is read (0)
				ptrace(PTRACE_GETREGS, pid, 0, &regs);
				printf("first argument: %llu\n", regs.rdi);
			} else if (WIFEXITED(status) == SIGSTOP) {
				printf("SIGSTOP\n");
			} else if (WIFEXITED(status)) {
				printf("CHILD is exiting\n");
				return 1;
			}
		}
		return 0;
	}
}
