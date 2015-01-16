#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
 
int main(int argc, char *argv[])
{
    char *newargv[] = { NULL };
    char *newenviron[] = { NULL };

    setreuid(1337, 31337);

    execve("/bin/sh", newargv, newenviron);

    return 0;
}
