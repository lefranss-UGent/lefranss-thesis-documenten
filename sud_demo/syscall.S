	.text

	.globl syscall_thunk
//scall_thunk:
//	pushq %rcx
//	/* Log system call */
//	pushq %r9
//	movq %r8, %r9
//	movq %r10, %r8
//	movq %rdx, %rcx
//	movq %rsi, %rdx
//	movq %rdi, %rsi
//	movq %rax, %rdi
//	call do_thunk
//	popq %r9
//	ret
//
	.globl raw_syscall
	.globl syscall_dispatcher
	.globl syscall_instruction_entry
raw_syscall:
	movq %rdi, %rax		/* Syscall number -> rax.  */
	movq %rsi, %rdi		/* shift arg1 - arg5.  */
	movq %rdx, %rsi
	movq %rcx, %rdx
	movq %r8, %r10
	movq %r9, %r8
	movq 8(%rsp),%r9	/* arg6 is on the stack.  */
syscall_instruction_entry:
	syscall			/* Do the system call.  */
syscall_dispatcher:
	ret			/* Return to caller.  */

