/*
 * chkgetdents.c - check getdents64 syscall buffer integrity
 *
 * Compares raw getdents64() syscall output with libc readdir()
 * and brute-force chdir enumeration to detect rootkits that
 * hook directory listing functions to hide processes.
 *
 * Usage: chkgetdents [-v] [directory]
 *   -v    verbose mode (show hidden PIDs)
 *   Default directory: /proc
 *
 * Returns: number of discrepancies found
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAX_PID     4194304
#define BUF_SIZE    65536

struct linux_dirent64 {
    ino64_t        d_ino;
    off64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

static int verbose = 0;
static int d_reclen_anomaly = 0;

/* Bitmap arrays for PID tracking */
static unsigned char pid_getdents[MAX_PID / 8 + 1];
static unsigned char pid_chdir[MAX_PID / 8 + 1];
static unsigned char pid_readdir[MAX_PID / 8 + 1];

#define SET_BIT(arr, pid) do {                                      \
    if ((pid) >= 1 && (pid) < MAX_PID)                              \
        (arr)[(pid) / 8] |= (unsigned char)(1 << ((pid) % 8));      \
} while (0)

#define GET_BIT(arr, pid)                                           \
    (((pid) >= 1 && (pid) < MAX_PID) ?                              \
     (((arr)[(pid) / 8] >> ((pid) % 8)) & 1) : 0)

/*
 * Collect PID list from raw getdents64() syscall.
 * Also validates the d_reclen chain integrity.
 */
static int collect_getdents64(const char *path)
{
    int fd, nread, pos;
    char buf[BUF_SIZE];

    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        if (verbose)
            fprintf(stderr, "chkgetdents: open(%s): %s\n",
                    path, strerror(errno));
        return -1;
    }

    nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
    if (nread < 0) {
        if (verbose)
            fprintf(stderr, "chkgetdents: getdents64(%s): %s\n",
                    path, strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    if (nread == 0) {
        if (verbose)
            fprintf(stderr, "chkgetdents: getdents64 returned 0 bytes\n");
        return 0;
    }

    pos = 0;
    while (pos < nread) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);

        /* Sanity check d_reclen */
        if (d->d_reclen <= 0) {
            if (verbose)
                fprintf(stderr,
                    "chkgetdents: d_reclen=%hu at offset %d (invalid)\n",
                    d->d_reclen, pos);
            d_reclen_anomaly = 1;
            break;
        }
        if (pos + d->d_reclen > nread) {
            if (verbose)
                fprintf(stderr,
                    "chkgetdents: d_reclen=%hu at offset %d "
                    "exceeds buffer (pos+reclen=%d, nread=%d)\n",
                    d->d_reclen, pos, pos + d->d_reclen, nread);
            d_reclen_anomaly = 1;
            break;
        }

        /* Record numeric PIDs (skip . and .. entries) */
        if (d->d_ino > 0) {
            int pid = atoi(d->d_name);
            if (pid >= 1 && pid < MAX_PID && d->d_name[0] != '.')
                SET_BIT(pid_getdents, pid);
        }

        pos += d->d_reclen;
    }

    /* Verify the chain consumed exactly the bytes returned */
    if (pos != nread) {
        if (verbose)
            fprintf(stderr,
                "chkgetdents: d_reclen chain mismatch "
                "(pos=%d, nread=%d)\n", pos, nread);
        d_reclen_anomaly = 1;
    }

    return 0;
}

/*
 * Collect PID list from libc opendir()/readdir().
 */
static int collect_readdir(const char *path)
{
    DIR *dp;
    struct dirent *de;

    dp = opendir(path);
    if (!dp) {
        if (verbose)
            fprintf(stderr, "chkgetdents: opendir(%s): %s\n",
                    path, strerror(errno));
        return -1;
    }

    while ((de = readdir(dp)) != NULL) {
        if (de->d_ino > 0 && isdigit(de->d_name[0])) {
            int pid = atoi(de->d_name);
            if (pid >= 1 && pid < MAX_PID)
                SET_BIT(pid_readdir, pid);
        }
    }

    closedir(dp);
    return 0;
}

/*
 * Brute-force chdir() into /proc/PID for every possible PID.
 * This catches processes hidden from both getdents64 and readdir
 * but whose /proc/PID directory is still accessible.
 */
static int collect_chdir(const char *path)
{
    char dirbuf[512];
    long pid;
    int found = 0;

    for (pid = 1; pid < MAX_PID; pid++) {
        snprintf(dirbuf, sizeof(dirbuf), "%s/%ld", path, pid);
        if (chdir(dirbuf) == 0) {
            SET_BIT(pid_chdir, pid);
            found++;
        }
    }

    if (verbose)
        fprintf(stderr, "chkgetdents: chdir brute-force found %d PIDs\n",
                found);

    return 0;
}

int main(int argc, char **argv)
{
    const char *path = "/proc";
    int i, pid;
    int hidden_rd = 0;   /* visible via chdir but not readdir */
    int hidden_gd = 0;   /* visible via chdir but not getdents64 */
    int diff_rd_gd = 0;  /* visible via readdir but not getdents64 */
    int ret = 0;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v"))
            verbose++;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "-?")) {
            printf("Usage: %s [-v] [directory]\n", argv[0]);
            printf("  -v           verbose mode (show individual hidden PIDs)\n");
            printf("  directory    path to scan (default: /proc)\n");
            printf("\n");
            printf("Compares getdents64(), readdir(), and chdir() enumeration\n");
            printf("to detect process-hiding rootkits.\n");
            return 0;
        } else {
            path = argv[i];
        }
    }

    /* Collect PIDs from three independent sources */
    if (collect_getdents64(path) < 0) {
        fprintf(stderr, "chkgetdents: failed to read %s via getdents64\n", path);
        return 2;
    }

    if (collect_readdir(path) < 0) {
        fprintf(stderr, "chkgetdents: failed to read %s via readdir\n", path);
        return 2;
    }

    if (verbose)
        fprintf(stderr, "chkgetdents: brute-forcing chdir into %s/* ...\n", path);
    collect_chdir(path);

    /* Cross-reference the three views */
    for (pid = 1; pid < MAX_PID; pid++) {
        int g = GET_BIT(pid_getdents, pid);   /* getdents64    */
        int c = GET_BIT(pid_chdir, pid);        /* chdir brute   */
        int r = GET_BIT(pid_readdir, pid);      /* libc readdir  */

        /* PID accessible via chdir but hidden from readdir */
        if (c && !r) {
            hidden_rd++;
            if (verbose)
                printf("PID %6d: hidden from readdir\n", pid);
        }

        /* PID accessible via chdir but hidden from getdents64 */
        if (c && !g) {
            hidden_gd++;
            if (verbose)
                printf("PID %6d: hidden from getdents64\n", pid);
        }

        /* PID visible via readdir but not via getdents64 */
        if (r && !g) {
            diff_rd_gd++;
            if (verbose)
                printf("PID %6d: in readdir but not in getdents64\n", pid);
        }
    }

    /* Report findings */
    if (d_reclen_anomaly) {
        printf("WARNING: getdents64 d_reclen chain anomaly detected "
               "(possible syscall hook)\n");
        ret++;
    }

    if (hidden_rd) {
        printf("WARNING: %d process(es) hidden from readdir\n", hidden_rd);
        ret++;
    }

    if (hidden_gd) {
        printf("WARNING: %d process(es) hidden from getdents64\n", hidden_gd);
        ret++;
    }

    if (diff_rd_gd) {
        printf("WARNING: %d process(es) visible in readdir but not getdents64\n",
               diff_rd_gd);
        ret++;
    }

    return ret;
}
