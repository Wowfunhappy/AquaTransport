#ifndef AQUATRANSPORT_ANISETTE_STATE_H
#define AQUATRANSPORT_ANISETTE_STATE_H
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>

#define AQ_ANISETTE_STATE_DIRECTORY "/usr/share/aquatransport/state"
#define AQ_ANISETTE_STATE_FD 3

/* The root broker owns the directory and opens/locks this file before dropping
 * privileges. Only the already-open descriptor enters the worker. Callers must
 * supply a directory under a trusted parent (the root-owned installation folder).
 * The explicit owner argument permits unprivileged scratch-directory tests. */
static int aq_adi_state_valid(int fd, uid_t owner) {
    struct stat st;
    return !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == owner &&
        st.st_nlink == 1 && !(st.st_mode & 077) && st.st_size <= 4096;
}
static int aq_adi_open_state(const char *directory, uid_t owner) {
    struct stat st;
    if (mkdir(directory, 0700) && errno != EEXIST) return -1;
    if (lstat(directory, &st) || !S_ISDIR(st.st_mode) || st.st_uid != owner || (st.st_mode & 077)) {
        errno = EPERM; return -1;
    }
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/anisette.plist", directory) >= sizeof path) { errno = ENAMETOOLONG; return -1; }
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (!aq_adi_state_valid(fd, owner)) { close(fd); errno = EPERM; return -1; }
    if (flock(fd, LOCK_EX | LOCK_NB)) { int saved = errno; close(fd); errno = saved; return -1; }
    return fd;
}
static int aq_adi_worker_fds(int client, int listener, int state) {
    close(listener);
    if (dup2(client, STDIN_FILENO) < 0 || dup2(state, AQ_ANISETTE_STATE_FD) < 0 ||
        fcntl(AQ_ANISETTE_STATE_FD, F_SETFD, 0)) return -1;
    if (client != STDIN_FILENO && client != AQ_ANISETTE_STATE_FD) close(client);
    if (state != AQ_ANISETTE_STATE_FD) close(state);
    return 0;
}
#endif
