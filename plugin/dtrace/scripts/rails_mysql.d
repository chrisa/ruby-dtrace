pid$1::mysql_real_query:entry
{
        @queries[copyinstr(arg1)] = count();
}

ruby$1:::function-entry
{
        @rbclasses[this->class = copyinstr(arg0)] = count();
        this->sep = strjoin(this->class, "#");
        @rbmethods[strjoin(this->sep, copyinstr(arg1))] = count();
}

syscall:::entry
/pid == $1/
{
        @syscalls[probefunc] = count();
}

END
{
        printf("MySQL Queries");
        printa(@queries);
        printf("System Calls");
        printa(@syscalls);
        printf("Ruby Classes");
        printa(@rbclasses);
        printf("Ruby Methods");
        printa(@rbmethods);
}
