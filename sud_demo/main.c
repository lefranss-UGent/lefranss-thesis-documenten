#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <ucontext.h>

#ifndef PR_SET_SYSCALL_USER_DISPATCH
# define PR_SET_SYSCALL_USER_DISPATCH	59
# define PR_SYS_DISPATCH_OFF	0
# define PR_SYS_DISPATCH_ON	1
# define SYSCALL_DISPATCH_FILTER_ALLOW	0
# define SYSCALL_DISPATCH_FILTER_BLOCK	1
#endif

#ifdef __NR_syscalls
# define MAGIC_SYSCALL_1 (__NR_syscalls + 1) /* Bad Linux syscall number */
#else
# define MAGIC_SYSCALL_1 (0xff00)  /* Bad Linux syscall number */
#endif

/*
 * To test returning from a sigsys with selector blocked, the test
 * requires some per-architecture support (i.e. knowledge about the
 * signal trampoline address).  On i386, we know it is on the vdso, and
 * a small trampoline is open-coded for x86_64.  Other architectures
 * that have a trampoline in the vdso will support TEST_BLOCKED_RETURN
 * out of the box, but don't enable them until they support syscall user
 * dispatch.
 */
#if defined(__x86_64__) || defined(__i386__)
#define TEST_BLOCKED_RETURN
#endif

#ifdef __x86_64__
void* (syscall_dispatcher_start)(void);
void* (syscall_dispatcher_end)(void);
#else
unsigned long syscall_dispatcher_start = 0;
unsigned long syscall_dispatcher_end = 0;
#endif

unsigned long trapped_call_count = 0;
unsigned long native_call_count = 0;

char selector;
#define SYSCALL_BLOCK   (selector = SYSCALL_DISPATCH_FILTER_BLOCK)
#define SYSCALL_UNBLOCK (selector = SYSCALL_DISPATCH_FILTER_ALLOW)

extern void* (syscall_dispatcher)(void);
extern void* (syscall_instruction_entry)(void);
extern unsigned int raw_syscall(long number,
                                unsigned long arg1, unsigned long arg2,
                                unsigned long arg3, unsigned long arg4,
                                unsigned long arg5, unsigned long arg6);
#define T(x) x?"PARENT":"CHILD"

int __thread id = 0;
int pid;

// How can I return the return value of the system call back to where the system call was blocked?
static void handle_sigsys(int sig, siginfo_t *info, void *ucontext)
{
	struct ucontext_t *ctx = ucontext;
        mcontext_t *mctx = &ctx->uc_mcontext;
        long long r;
        char buf[1024];
        int len;

        SYSCALL_UNBLOCK;

        len = snprintf(buf, 1024, "--------------------------------------------------\n[%d] SYSCALL NO %lld\n\tARG1 %lld\n\tARG2 %lld\n\tARG3 %lld\n\tARG4 %lld\n\tARG5 %lld\n\tARG6 %lld\n\n", id,
                       mctx->gregs[REG_RAX], mctx->gregs[REG_RDI],
                       mctx->gregs[REG_RSI], mctx->gregs[REG_RDX],
                       mctx->gregs[REG_R10], mctx->gregs[REG_R8],
                       mctx->gregs[REG_R9]);
        write(2, buf, len);

        if (info->si_syscall > 0xf000) {
                trapped_call_count ++;
                mctx->gregs[REG_RAX] = 0xdeadbeef;
                goto out;
        }

        native_call_count++;
	r = syscall(mctx->gregs[REG_RAX], mctx->gregs[REG_RDI],
                    mctx->gregs[REG_RSI], mctx->gregs[REG_RDX],
                    mctx->gregs[REG_R10], mctx->gregs[REG_R8],
                    mctx->gregs[REG_R9]);

	len = snprintf(buf, 1024, "\nReturn value of syscall: %lld\n", r);
        write(2, buf, len);


	mctx->gregs[REG_RAX] = r;
out:
        SYSCALL_BLOCK;

	__asm__ volatile("movq $0xf, %rax");
        __asm__ volatile("leaveq");
        __asm__ volatile("add $0x8, %rsp");
        __asm__ volatile("syscall_dispatcher_start:");
        __asm__ volatile("syscall");
        __asm__ volatile("nop"); /* Landing pad within dispatcher area */
        __asm__ volatile("syscall_dispatcher_end:");
}

int main(void)
{
	struct sigaction act;
	int ret;
	sigset_t mask; /* set of signals that the thread is currently blocking */

	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);

	act.sa_sigaction = handle_sigsys;
	act.sa_flags = SA_SIGINFO;
	act.sa_mask = mask;

	ret = sigaction(SIGSYS, &act, NULL);
	if (ret) {
		perror("Error sigaction:");
		exit(-1);
	}

	fprintf(stderr, "Enabling syscall trapping.\n");

	if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
		  syscall_dispatcher_start,
		  (syscall_dispatcher_end - syscall_dispatcher_start + 1),
		  &selector)) {
		perror("prctl failed\n");
		exit(-1);
	}

	size_t length = snprintf(NULL, 0, "Hello, World!\n") + 1;
	char buffer[length];
	snprintf(buffer, length, "Hello, World!\n");

	SYSCALL_BLOCK;
	
	/* perform some syscalls */
	// printf that causes syscall 1
	printf("Hello, World! From printf\n");
	printf("Hello, World! Again from printf\n");	
	// syscall of bad syscall number
	syscall(MAGIC_SYSCALL_1);
	// syscall 186
        syscall(SYS_gettid);
	// syscall 1
	write(STDOUT_FILENO, buffer, length);

	/* open file, read from it, write the contents and close file syscalls */
	int fd, n;
	unsigned char buff[BUFSIZ];
	if ( (fd = open("hello", O_RDONLY)) < 0) {
		perror("No hello file found...");
		exit(-1);
	}
	while ( (n = read(fd, buff, BUFSIZ)) > 0) {
		if (write(1, buff, n) < 0) {
			perror("Error while writing out buffer...");
			exit(1);
		}
	}
	if (n < 0) {
		perror("Error while reading hello file...");
		exit(1);
	}
	if (close(fd) < 0) {
		perror("Error while closing hello file...");
		exit(1);
	}

#ifdef TEST_BLOCKED_RETURN
	if (selector == SYSCALL_DISPATCH_FILTER_ALLOW) {
		fprintf(stderr, "Failed to return with selector blocked.\n");
		exit(-1);
	}
#endif

	SYSCALL_UNBLOCK;

	printf("##################################################\ntrapped_call_count:\t%lu\nnative_call_count:\t%lu\n",
		trapped_call_count, native_call_count);
	return 0;
}
