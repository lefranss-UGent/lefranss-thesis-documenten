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
	
		// example on: https://man7.org/linux/man-pages/man2/seccomp.2.html
		struct sock_filter filter[] = {
			// TODO: check magic value in r12 (p. 111 Adv. Tech. MVEE) -> SECCOMP_RET_KILL_PROCESS? if not correct, else resume filtering
			//BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[12])),
			//BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MAGIC_VALUE_FROM_MEMORY, 1, 0),
                        //BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
			// load system call number into accumulator
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_uname, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpriority, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_nanosleep, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrusage, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sysinfo, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_times, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_capget, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getitimer, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_futex, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_gettimeofday, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_time, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clock_gettime, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getegid, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_geteuid, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getgid, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpgrp, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_gettid, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sched_yield, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getcwd, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_access, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_stat, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fstat, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lstat, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getdents, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlink, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlinkat, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getxattr, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lgetxattr, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fgetxattr, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lseek, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_alarm, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setitimer, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_timerfd_gettime, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_madvise, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fadvise64, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pread64, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readv, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_preadv, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_poll, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_select, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_timerfd_settime, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sync, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fdatasync, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_syncfs, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pwrite64, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_writev, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pwritev, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvfrom, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmsg, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_recvmmsg, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockname, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpeername, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockopt, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmmsg, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendfile, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_epoll_wait, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_epoll_ctl, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_shutdown, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setsockopt, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			// IF NOT ALLOW EXECVE (and related from exec family) THEN THE FILTER IS NOT WORKING (because we need execve and it is not working in our syscall replacement)
			// BUT even though we ALLOW them here, they are traced too
			// TODO: do some research to find what causes the 'always tracing' of exec-family syscalls
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
                        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
		};

		/*
		  special attention for:
			  	case __NR_futex: return ipmon_handle_futex_maybe_checked(args);
				case __NR_read: return ipmon_handle_read_maybe_checked(args);
				case __NR_pread64: return ipmon_handle_pread64_maybe_checked(args);
				case __NR_readv: return ipmon_handle_readv_maybe_checked(args);
				case __NR_preadv: return ipmon_handle_preadv_maybe_checked(args);
				case __NR_poll: return ipmon_handle_poll_maybe_checked(args);
				case __NR_select: return ipmon_handle_select_maybe_checked(args);
				case __NR_write: return ipmon_handle_write_maybe_checked(args);
				case __NR_pwrite64: return ipmon_handle_pwrite64_maybe_checked(args);
				case __NR_writev: return ipmon_handle_writev_maybe_checked(args);
				case __NR_pwritev: return ipmon_handle_pwritev_maybe_checked(args);
		  and:
				futex: ARG2 (args.arg2)
				ioctl: ARG2 (args.arg2)
			        fcntl (not found in MVEE_ipmon.cpp)	
		*/
		
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

		printf("__NR_execve: %d\n", __NR_execve);
		
		while (1)
		{
			//sleep(1);
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
