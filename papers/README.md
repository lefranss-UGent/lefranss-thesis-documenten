## eBPF & seccomp
Filter and Modify System Calls with seccomp and ptrace:
* https://www.alfonsobeato.net/c/filter-and-modify-system-calls-with-seccomp-and-ptrace/, https://github.com/alfonsosanchezbeato/ptrace-redirect
* Syscall User Dispatch https://www.kernel.org/doc/html/latest/admin-guide/syscall-user-dispatch.html 
* Seccomp user-space notification and signals https://lwn.net/Articles/851813/
* https://dangokyo.me/2018/05/01/seccomp-and-ptrace/

Performance monitoring with eBPF:
* http://www.brendangregg.com/perf.html

BPF filters:

* https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.7-RELEASE

## seccomp
* http://manpages.ubuntu.com/manpages/xenial/man2/seccomp.2.html
* https://man7.org/linux/man-pages/man2/seccomp.2.html
* Article with detailed example: https://www.alfonsobeato.net/c/filter-and-modify-system-calls-with-seccomp-and-ptrace/
* https://tbrindus.ca/on-online-judging-part-5/
* Example: https://dangokyo.me/2018/05/01/seccomp-and-ptrace/
* https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
* http://terenceli.github.io/%E6%8A%80%E6%9C%AF/2019/02/04/seccomp
* Example: https://gist.github.com/fntlnz/08ae20befb91befd9a53cd91cdc6d507

## unotify
* https://f5.pm/go-73639.html
* https://lwn.net/Articles/756233/
* https://lwn.net/Articles/851813/
* https://brauner.github.io/2020/07/23/seccomp-notify.html
* https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt
* Example: https://man7.org/tlpi/code/online/dist/seccomp/seccomp_user_notification.c.html

## ptrace
* https://man7.org/linux/man-pages/man2/ptrace.2.html
* Example: https://www.linuxjournal.com/article/6100
* https://nullprogram.com/blog/2018/06/23/
* Example: Linux Magazine "Perl script uses Ptrace for process tracing"
* Ptrace a syscall: https://pchaigno.github.io/strace/2019/10/02/introducing-strace-seccomp-bpf.html

## syscall user dispatch
* https://www.kernel.org/doc/html/latest/admin-guide/syscall-user-dispatch.html
* Example: https://gitlab.collabora.com/krisman/syscall-disable-personality/-/tree/master/
* Example: https://elixir.bootlin.com/linux/v5.11/source/tools/testing/selftests/syscall_user_dispatch
* Context: https://www.gnu.org/software/libc/manual/html_node/System-V-contexts.html
* Signal handler: https://man7.org/linux/man-pages/man7/signal.7.html
* Signal action: https://man7.org/linux/man-pages/man2/sigaction.2.html, https://pubs.opengroup.org/onlinepubs/007904875/functions/sigaction.html
