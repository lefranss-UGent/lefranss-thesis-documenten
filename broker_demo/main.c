#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <time.h>
#include <signal.h>

#include <ucontext.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>

static void handle_sigsys(int sig, siginfo_t *info, void *ucontext)
{
	struct ucontext_t *ctx = ucontext;
        mcontext_t *mctx = &ctx->uc_mcontext;
        long long r;
        char buf[1024];
        int len;

        len = snprintf(buf, 1024, "--------------------------------------------------\nSYSCALL NO %lld\n\tARG1 %lld\n\tARG2 %lld\n\tARG3 %lld\n\tARG4 %lld\n\tARG5 %lld\n\tARG6 %lld\n\n",
                       mctx->gregs[REG_RAX], mctx->gregs[REG_RDI],
                       mctx->gregs[REG_RSI], mctx->gregs[REG_RDX],
                       mctx->gregs[REG_R10], mctx->gregs[REG_R8],
                       mctx->gregs[REG_R9]);
        write(2, buf, len);

	r = syscall(mctx->gregs[REG_RAX], mctx->gregs[REG_RDI],
                    mctx->gregs[REG_RSI], mctx->gregs[REG_RDX],
                    mctx->gregs[REG_R10], mctx->gregs[REG_R8],
                    mctx->gregs[REG_R9]);

	len = snprintf(buf, 1024, "\nReturn value of syscall: %lld\n", r);
        write(2, buf, len);

	mctx->gregs[REG_RAX] = r;
	
	// sigreturn code
	__asm__ volatile("movq $0xf, %rax");
        __asm__ volatile("leaveq");
        __asm__ volatile("add $0x8, %rsp");
        __asm__ volatile("syscall");
        __asm__ volatile("nop");
}

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
		
		// set signal handler
		struct sigaction act;
		int ret;
		sigset_t mask; /* set of signals that the thread is currently blocking */
		memset(&act, 0, sizeof(act));
		sigemptyset(&mask);
		act.sa_sigaction = handle_sigsys;
		act.sa_flags = SA_SIGINFO;
		act.sa_mask = mask;
		if (sigaction(SIGSYS, &act, NULL)) {
			perror("Error sigaction:");
			exit(-1);
		}
		if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
			perror("sigprocmask");
			return -1;
		}

		struct sock_filter filter[] = {
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_getpid, 0, 1), // redirect to signal handler
			BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 1),
			BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_read, 0, 1),
                       BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_openat, 0, 1),
                       BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_close, 0, 1), // redirect to signal handler
                       BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP),
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
		
		// set seccomp filter mode
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
		{
			perror("when setting seccomp filter");
			return 1;
		}
		
		// send SIGSTOP signal to this forked process
		kill(getpid(), SIGSTOP);
		
		// some functions that invoke syscalls
		printf("hello test 1\n");
		printf("hello test 2\n");
		getpid();
		FILE *fp;
		char buff[255];
		fp = fopen("/home/lennertfranssens/Documents/thesis/broker_demo/hello", "r");
		fscanf(fp, "%s", buff);
		fclose(fp);
		printf("%s\n", buff);
		
		return 0;
	} else {
		/* PARENT */

		waitpid(pid, &status, 0);
		ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
		
		while (1)
		{
			sleep(1);
			//ptrace(PTRACE_SYSCALL, pid, 0, 0); // tracks all system calls and not only the filtered (not the purpose of this program!!!)
			ptrace(PTRACE_CONT, pid, 0, SIGSYS);
			waitpid(pid, &status, 0);
			printf("--------------------------------\n");
			printf("[waitpid status: 0x%08x]\n", status);
			
			if (WSTOPSIG(status) == (SIGTRAP|0x80))
			{
				printf("SIGTRAP|0x80\n");
			} else if (WSTOPSIG(status) == SIGTRAP) {
				printf("received a SIGTRAP\n");
				long syscall_no = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);
				printf("syscall number: %ld\n", syscall_no);
				// get some arguments of the syscall
				struct user_regs_struct regs;
				// first argument is 1 if syscall is write (1) and 3 (first free file descriptor) if syscall is read (0)
				ptrace(PTRACE_GETREGS, pid, 0, &regs);
				printf("first argument: %llu\n", regs.rdi);
			} else if (WSTOPSIG(status) == SIGSYS) {
				// Why I am not in the signal_handler?
				printf("received a SIGSYS, but why am I not in the signal_handler?\n");
				long syscall_no = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);
				printf("syscall number: %ld\n", syscall_no);
			} else if (WIFEXITED(status) == SIGSTOP) {
				printf("received a SIGSTOP\n");
			} else if (WIFEXITED(status)) {
				printf("CHILD is exiting\n");
				return 1;
			} else {
				printf("CHILD is exiting\n");
				return 1;
			}
		}
		return 0;
	}
}
