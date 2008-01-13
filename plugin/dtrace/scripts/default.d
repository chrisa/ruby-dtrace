syscall:::entry
/pid == $1/
{
        @syscalls[probefunc] = count();
}

END
{
        printf("System Calls");
        printa(@syscalls);
}
