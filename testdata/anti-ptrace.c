#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int check_tracerpid(void) {
    printf("[check_tracerpid] /proc/self/status ... ");

    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        perror("fopen");
        exit(1);
    }

    char line[512];
    int tracerpid = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracerpid = atoi(line + 10);
            break;
        }
    }

    fclose(f);

    if (tracerpid == -1) {
        printf("TracerPid not found\n");
        exit(1);
    } else if (tracerpid != 0) {
        printf("TRACED (TracerPid: %d)\n", tracerpid);
        return 1;
    } else {
        printf("OK\n");
        return 0;
    }
}

static int check_ptrace_traceme(void) {
    printf("[check_ptrace_traceme] ptrace(PTRACE_TRACEME) ... ");

    errno = 0;
    long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (ret == -1) {
        if (errno != EPERM) {
            perror("ptrace");
            exit(1);
        }

        printf("TRACED\n");
        return 1;
    }

    printf("OK\n");
    return 0;
}

int main(void) {
    printf("pid = %d\n", getpid());

    check_tracerpid();
    check_ptrace_traceme();

    return 0;
}