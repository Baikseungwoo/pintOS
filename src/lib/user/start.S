/* lib/user/start.S - Entry point for user programs */

.global _start
.type _start, @function

_start:
    /* Setup stack pointer */
    movl %esp, %ebp

    /* Call main(int argc, char *argv[]) */
    call main

    /* If main returns, call exit with return value */
    pushl %eax
    call exit

    /* Should never reach here */
    hlt