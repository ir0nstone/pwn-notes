# Sigreturn-Oriented Programming \(SROP\)

### Overview

A **sigreturn** is a special type of [syscall](../../syscalls/). The purpose of sigreturn is to return from the **signal handler** and to clean up the stack frame after a signal has been unblocked.

What this involves is storing _all_ the register values on the stack. Once the signal is unblocked, all the values are popped back in \(RSP points to the bottom of the **sigreturn frame**, this collection of register values\).

### Exploitation

By leveraging a `sigreturn`, we can control _all register values at once_ - amazing! Yet this is also a drawback - we can't pick-and-choose registers, so if we don't have a stack leak it'll be hard to set registers like RSP to a workable value. Nevertheless, this is a super powerful technique - especially with limited gadgets.

