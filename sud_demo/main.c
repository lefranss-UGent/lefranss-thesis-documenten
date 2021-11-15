#define _GNU_SOURCE
#include<stdio.h>
#include<sys/prctl.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>

#include <stdio.h>
#include <sys/prctl.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>


#include <ucontext.h>

//#define USE_DISPATCHER
#define TEST_COUNT 4000000

#define SYSCALL_DISABLE_ALLOW 0
#define SYSCALL_DISABLE_BLOCK 1

extern void* (syscall_dispatcher)(void);
extern void* (syscall_instruction_entry)(void);
extern unsigned int raw_syscall(long number,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6);
#define T(x) x?"PARENT":"CHILD"

int __thread id = 0;
unsigned long trapped_call_count = 0;
unsigned long native_call_count = 0;
int pid;

#ifdef USE_DISPATCHER
#define SYSINFO(x) raw_syscall(SYS_sysinfo, (unsigned long)x, 0,0,0,0,0)
#else
#define SYSINFO(x) sysinfo(x)
#endif

int *sel_ptr;

#define FASTVAR

#ifdef FASTVAR
#define SYSCALL_BLOCK (*sel_ptr) = 1;
#define SYSCALL_UNBLOCK (*sel_ptr) = 0;
#else
#define SYSCALL_BLOCK raw_syscall(SYS_prctl, 59, SYSCALL_DISABLE_BLOCK,\
				  (unsigned long) &syscall_dispatcher, (unsigned long)sel_ptr, 0, 0);
#define SYSCALL_UNBLOCK	raw_syscall(SYS_prctl, 59, SYSCALL_DISABLE_ALLOW, 0, 0, 0, 0);
#endif


static double perf_syscall()
{
	struct sysinfo info;
	struct timespec ts;
	unsigned int i;
	double t1, t2;
	int addr;

	addr = 0;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	t1 = ts.tv_sec + 1.0e-9 * ts.tv_nsec;
	for (i = 0; i < TEST_COUNT; ++i) {
		if (SYSINFO(&info)) {
			perror("sysinfo");
			exit(-1);
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &ts);
	t2 = ts.tv_sec + 1.0e-9 * ts.tv_nsec;
	return (t2 - t1) / TEST_COUNT;
}

static void handle_sigsys(int sig, siginfo_t *info, void *ucontext)
{
	struct ucontext_t *ctx = ucontext;
	mcontext_t *mctx = &ctx->uc_mcontext;
	int r;
	char buf[1024];
	int len;

	SYSCALL_UNBLOCK;

	len = snprintf(buf, 1024, "[%d], sys_%d(%d,%d,%d,%d,%d,%d)\n", id,
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
	mctx->gregs[REG_RAX] = mctx->gregs[REG_RDX];
out:
	SYSCALL_BLOCK;

	__asm__ volatile("movq $0xf, %rax");
	__asm__ volatile("leaveq");
	__asm__ volatile("add $0x8, %rsp");
	__asm__ volatile("jmp syscall_instruction_entry");
}

void *do_t(int lock)
{
	int ret;

	printf("[%d] hello World\n", id);

	if (prctl(59, sel_ptr, 0, 0, 0)) {
		printf("prctl failed %s\n", strerror(errno));
		exit (1);
	}
	*sel_ptr = lock;
	printf("[%d] hello World 2\n", id);
	*sel_ptr = !lock;
	printf("[%d] hello World 3 sel=%d\n", id);
}

void *do_t1(void *arg)
{
	id = 1;
	do_t(1);
}

void *do_t2(void *arg)
{
	id = 2;
	do_t(0);
}

int main ()
{
	int ret;
	pthread_t t1, t2;
	const struct sigaction act = {
		.sa_sigaction = handle_sigsys,
		.sa_flags = SA_SIGINFO,
		.sa_mask = 0
	};
	double time1, time2;
	int selector = 0;

	sel_ptr = &selector;


	trapped_call_count = native_call_count = 0;
	time1 = perf_syscall();
	printf("Avg sycall time %.0lfns.\n", time1 * 1.0e9);

	ret = sigaction(SIGSYS, &act, NULL);
	if (ret) {
		printf("Error sigaction: %s.\n", strerror(errno));
		return -1;
	}

	if (prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE,0, 0)) {
		printf("Error enabling speculation: %s.\n", strerror(errno));
		return -1;
	}
	ret = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);
	if (ret < 0) {
		printf("Error getting speculation: %s.\n", strerror(errno));
		return -1;
	}

	if (prctl(59, SYSCALL_DISABLE_BLOCK, &syscall_dispatcher, &selector,  0)) {
		printf("prctl failed %s\n", strerror(errno));
		exit (1);
	}

	selector = 1;

	__asm__ volatile("movq $0xf001,%rax");
	__asm__ volatile("syscall");
	__asm__ volatile("movl %%eax, %0" : "=m"(ret));

	if (selector)
		printf("ret %#x.%d\n", ret, selector);
	else
		printf("Failed to undo selector ret %#x.%d\n", ret, selector);

	if (!trapped_call_count)
	{
		printf("syscall trapping does not work.\n");
		exit(-1);
	}

	SYSCALL_UNBLOCK
	time2 = perf_syscall();
	SYSCALL_BLOCK

	printf("trapped_call_count %u, native_call_count %u.\n", trapped_call_count, native_call_count);
	printf("Avg sycall time %.0lfns.\n", time2 * 1.0e9);
	printf("Interception overhead: %.1lf%% (+%.0lfns).\n",
	       100.0 * (time2 / time1 - 1.0) , 1.0e9 * (time2 - time1));

}

