// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020 Collabora Ltd.
 *
 * Benchmark and test syscall user dispatch
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

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

static void handle_sigsys(int sig, siginfo_t *info, void *ucontext)
{
	char buf[1024];
	int len;

	SYSCALL_UNBLOCK;

	/* printf and friends are not signal-safe. */
	len = snprintf(buf, 1024, "Caught sys_%x\n", info->si_syscall);
	write(1, buf, len);

	if (info->si_syscall == MAGIC_SYSCALL_1)
		trapped_call_count++;
	else
		native_call_count++;

#ifdef TEST_BLOCKED_RETURN
	SYSCALL_BLOCK;
#endif
#ifdef __x86_64__
	__asm__ volatile("movq $0xf, %rax");
	__asm__ volatile("leaveq");
	__asm__ volatile("add $0x8, %rsp");
	__asm__ volatile("syscall_dispatcher_start:");
	__asm__ volatile("syscall");
	__asm__ volatile("nop"); /* Landing pad within dispatcher area */
	__asm__ volatile("syscall_dispatcher_end:");
#endif

}

int main(void)
{
	struct sigaction act;
	int ret;
	sigset_t mask;

	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);

	// Take a look at: sigaction sa_handler
	// here we set sa_flags to SA_SIGIFO and sa_sigaction is then used instead of sa_handler
	// uncomment the following line and comment sa_sigaction and sa_flags
	// act.sa_sighandler = SIG_DFL; // or SIG_IGN to ignore the signal or a pointer to a signal handeling function
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

	SYSCALL_BLOCK;
	
	// perform some syscalls
	syscall(MAGIC_SYSCALL_1);
	syscall(SYS_gettid);
	//printf("Hello, world!\n");

#ifdef TEST_BLOCKED_RETURN
	if (selector == SYSCALL_DISPATCH_FILTER_ALLOW) {
		fprintf(stderr, "Failed to return with selector blocked.\n");
		exit(-1);
	}
#endif

	SYSCALL_UNBLOCK;

	printf("trapped_call_count %lu, native_call_count %lu.\n",
	       trapped_call_count, native_call_count);
	return 0;

}
