#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    pid_t pid;

    printf("parent: pid=%d\n", getpid());

    pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return 1;
    } else if (pid == 0) {
        printf("child: pid%d, ppid=%d\n", getpid(), getppid());
        return 0;
    } else {
        printf("parent: pid%d, ppid=%d\n", getpid(), getppid());
        return 0;
    }
}
