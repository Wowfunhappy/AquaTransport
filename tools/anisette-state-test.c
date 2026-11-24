#include "../src/mac/aquatransport_anisette_state.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--inherited")) {
        assert(aq_adi_state_valid(AQ_ANISETTE_STATE_FD, getuid()));
        assert(!(fcntl(AQ_ANISETTE_STATE_FD, F_GETFD) & FD_CLOEXEC));
        assert(pwrite(AQ_ANISETTE_STATE_FD, "state", 5, 0) == 5);
        assert(write(STDIN_FILENO, "ok", 2) == 2);
        return 0;
    }
    char directory[] = "/tmp/aq-state-lock.XXXXXX";
    assert(mkdtemp(directory));
    char path[PATH_MAX], linkPath[PATH_MAX];
    snprintf(path, sizeof path, "%s/anisette.plist", directory);
    snprintf(linkPath, sizeof linkPath, "%s/alias", directory);
    int fd = aq_adi_open_state(directory, getuid()); assert(fd >= 0);
    assert(aq_adi_open_state(directory, getuid()) < 0);
    assert(!aq_adi_state_valid(fd, getuid()+1));
    assert(fcntl(fd, F_GETFD) & FD_CLOEXEC);
    close(fd);
    assert(chmod(path, 0666) == 0 && aq_adi_open_state(directory, getuid()) < 0);
    assert(chmod(path, 0600) == 0);
    assert(link(path, linkPath) == 0 && aq_adi_open_state(directory, getuid()) < 0);
    unlink(linkPath);
    assert(truncate(path, 4097) == 0 && aq_adi_open_state(directory, getuid()) < 0);
    assert(truncate(path, 0) == 0);
    assert(chmod(directory, 0777) == 0 && aq_adi_open_state(directory, getuid()) < 0);
    assert(chmod(directory, 0700) == 0);
    assert(unlink(path) == 0 && symlink("/dev/null", path) == 0 && aq_adi_open_state(directory, getuid()) < 0);
    unlink(path);

    /* Exercise the production descriptor setup with both possible collisions:
     * fd 3 initially belongs to the listener or to the client socket. */
    for (int collision = 0; collision < 2; collision++) {
        int listener = -1, peers[2];
        if (!collision) listener = open("/dev/null", O_RDONLY);
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, peers) == 0);
        if (collision) listener = open("/dev/null", O_RDONLY);
        fd = aq_adi_open_state(directory, getuid()); assert(fd >= 0 && listener >= 0);
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            close(peers[1]);
            assert(aq_adi_worker_fds(peers[0], listener, fd) == 0);
            execl(argv[0], argv[0], "--inherited", NULL);
            _exit(127);
        }
        close(peers[0]); close(listener);
        char reply[2]; assert(read(peers[1], reply, 2) == 2 && !memcmp(reply, "ok", 2));
        close(peers[1]); int status;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
        char contents[5]; assert(pread(fd, contents, 5, 0) == 5 && !memcmp(contents, "state", 5));
        close(fd);
    }
    unlink(path); rmdir(directory);
    puts("PASS: machine-state ownership, permissions, links, bounds, locking and descriptor inheritance");
    return 0;
}
