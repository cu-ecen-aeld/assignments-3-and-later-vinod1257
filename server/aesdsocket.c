#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define PORT_STR "9000"
#define BACKLOG 10
#define DATAFILE "/var/tmp/aesdsocketdata"
#define RECV_CHUNK 1024

static volatile sig_atomic_t exit_requested = 0;
static int listen_fd = -1;

static void handle_signal(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) {
        exit_requested = 1;
        if (listen_fd != -1) {
            close(listen_fd); // unblock accept()
            listen_fd = -1;
        }
    }
}

static int install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    if (sigaction(SIGINT, &sa, NULL) < 0) return -1;
    if (sigaction(SIGTERM, &sa, NULL) < 0) return -1;
    return 0;
}

/* Create, bind and listen socket on PORT_STR. */
static int setup_listen_socket(void)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL, *p;
    int rv, fd = -1;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;     // for bind()

    rv = getaddrinfo(NULL, PORT_STR, &hints, &res);
    if (rv != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(rv));
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == -1) continue;

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            close(fd);
            fd = -1;
            continue;
        }

        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            fd = -1;
            continue;
        }

        if (listen(fd, BACKLOG) == -1) {
            syslog(LOG_ERR, "listen failed: %s", strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    if (fd == -1) {
        syslog(LOG_ERR, "Failed to bind/listen on port %s", PORT_STR);
        return -1;
    }

    return fd;
}

/* Append len bytes from buf to DATAFILE. Return 0 success, -1 error */
static int append_to_datafile(const char *buf, size_t len)
{
    int fd = open(DATAFILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return -1;

    size_t written = 0;
    while (written < len) {
        ssize_t w = write(fd, buf + written, len - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        written += (size_t)w;
    }
    close(fd);
    return 0;
}

/* Send the entire DATAFILE to client_fd. */
static int send_file_to_client(int client_fd)
{
    int fd = open(DATAFILE, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) return 0; // nothing to send yet
        return -1;
    }

    char buf[RECV_CHUNK];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t s = send(client_fd, buf + off, r - off, 0);
            if (s <= 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -1;
            }
            off += s;
        }
    }
    close(fd);
    if (r < 0) return -1;
    return 0;
}

/* Get printable peer IP string from address */
static void sockaddr_to_ipstr(struct sockaddr *sa, socklen_t salen, char *out, size_t outlen)
{
    if (!sa) {
        strncpy(out, "unknown", outlen);
        out[outlen-1] = '\0';
        return;
    }
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &sin->sin_addr, out, outlen);
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &sin6->sin6_addr, out, outlen);
    } else {
        strncpy(out, "unknown", outlen);
        out[outlen-1] = '\0';
    }
}

/*
 * handle_client:
 *  - accumulates incoming bytes into a dynamic buffer
 *  - whenever a newline '\n' is observed, extract only that packet (up to and including '\n')
 *    and append to DATAFILE exactly once
 *  - after appending a packet, send the entire DATAFILE contents back to the client
 *  - continue processing additional packets if client sends them in the same connection
 */
static void handle_client(int client_fd, struct sockaddr *peer_addr, socklen_t peer_len)
{
    char ipstr[INET6_ADDRSTRLEN] = {0};
    sockaddr_to_ipstr(peer_addr, peer_len, ipstr, sizeof(ipstr));
    syslog(LOG_INFO, "Accepted connection from %s", ipstr);

    size_t buf_cap = RECV_CHUNK;
    size_t buf_len = 0;
    char *buf = malloc(buf_cap);
    if (!buf) {
        syslog(LOG_ERR, "malloc failed");
        close(client_fd);
        return;
    }

    char rbuf[RECV_CHUNK];
    bool conn_closed = false;

    while (!conn_closed) {
        ssize_t r = recv(client_fd, rbuf, sizeof(rbuf), 0);
        if (r == 0) {
            // client closed connection
            conn_closed = true;
            break;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "recv failed: %s", strerror(errno));
            break;
        }

        size_t pos = 0;
        while (pos < (size_t)r) {
            // ensure capacity
            if (buf_len + (r - pos) + 1 > buf_cap) {
                size_t newcap = buf_cap * 2;
                while (newcap < buf_len + (r - pos) + 1) newcap *= 2;
                char *tmp = realloc(buf, newcap);
                if (!tmp) {
                    syslog(LOG_ERR, "realloc failed");
                    free(buf);
                    close(client_fd);
                    return;
                }
                buf = tmp;
                buf_cap = newcap;
            }

            // find newline in the received chunk
            char *newline = memchr(rbuf + pos, '\n', r - pos);
            if (newline) {
                size_t chunk_len = (size_t)(newline - (rbuf + pos)) + 1; // include newline
                // append this chunk into buffer
                memcpy(buf + buf_len, rbuf + pos, chunk_len);
                buf_len += chunk_len;
                pos += chunk_len;

                // Now buf[0..buf_len-1] holds one complete packet -> append only this packet
                if (buf_len > 0) {
                    if (append_to_datafile(buf, buf_len) != 0) {
                        syslog(LOG_ERR, "append_to_datafile failed: %s", strerror(errno));
                    } else {
                        // send full file back to client
                        if (send_file_to_client(client_fd) != 0) {
                            syslog(LOG_ERR, "send_file_to_client failed to %s", ipstr);
                        }
                    }
                }
                // reset buffer to hold any further bytes (remaining bytes after this newline will be processed in the same loop)
                buf_len = 0;
            } else {
                // no newline in remaining part: copy all and continue recv
                size_t chunk_len = (size_t)r - pos;
                memcpy(buf + buf_len, rbuf + pos, chunk_len);
                buf_len += chunk_len;
                pos += chunk_len;
            }
        } // end inner loop processing this recv chunk
    } // end recv loop

    free(buf);
    syslog(LOG_INFO, "Closed connection from %s", ipstr);
    close(client_fd);
}

int main(int argc, char *argv[])
{
    bool daemon_mode = false;
    if (argc == 2 && strcmp(argv[1], "-d") == 0) daemon_mode = true;
    else if (argc > 1) {
        fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
        return EXIT_FAILURE;
    }

    openlog("aesdsocket", LOG_PID | LOG_CONS, LOG_USER);

    if (install_signal_handlers() < 0) {
        syslog(LOG_ERR, "Failed to install signal handlers: %s", strerror(errno));
        closelog();
        return -1;
    }

    // Ensure clean file at startup so tests are idempotent
    // (remove this unlink if you want to preserve file between server restarts)
    unlink(DATAFILE);

    listen_fd = setup_listen_socket();
    if (listen_fd < 0) {
        closelog();
        return -1;
    }

    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "fork failed: %s", strerror(errno));
            close(listen_fd);
            closelog();
            return -1;
        }
        if (pid > 0) {
            // parent exits
            close(listen_fd);
            closelog();
            _exit(EXIT_SUCCESS);
        }
        // child continues as daemon
        if (setsid() < 0) {
            syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
        }
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
    }

    while (!exit_requested) {
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (exit_requested) break;
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "accept failed: %s", strerror(errno));
            break;
        }

        handle_client(client_fd, (struct sockaddr *)&client_addr, addr_len);
    }

    syslog(LOG_INFO, "Caught signal, exiting");
    if (listen_fd != -1) close(listen_fd);
    unlink(DATAFILE);
    closelog();
    return 0;
}
