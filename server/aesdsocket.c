#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "queue.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define PORT_STR "9000"
#define BACKLOG 10
#define DATAFILE "/var/tmp/aesdsocketdata"
#define RECV_CHUNK 1024

static volatile sig_atomic_t exit_requested = 0;
static int listen_fd = -1;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

struct thread_data {
    pthread_t thread_id;
    int client_fd;
    struct sockaddr peer_addr;
    socklen_t peer_len;
    bool thread_complete;
    SLIST_ENTRY(thread_data) entries;
};

SLIST_HEAD(thread_list_head, thread_data) thread_list;

static void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        exit_requested = 1;
        if (listen_fd != -1) {
            close(listen_fd); // unblock accept()
            listen_fd = -1;
        }
    }
}

static int install_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    if (sigaction(SIGINT, &sa, NULL) < 0) return -1;
    if (sigaction(SIGTERM, &sa, NULL) < 0) return -1;
    return 0;
}

/* Create, bind and listen socket on PORT_STR. */
static int setup_listen_socket(void) {
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
static int append_to_datafile(const char *buf, size_t len) {
    // This function now assumes the caller holds the mutex
    int fd = open(DATAFILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) return -1;

    ssize_t bytes_written = write(fd, buf, len);
    close(fd);
    return (bytes_written == -1) ? -1 : 0;
}

/* Send the entire DATAFILE to client_fd. */
static int send_file_to_client(int client_fd) {
    // This function now assumes the caller holds the mutex
    int fd = open(DATAFILE, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) return 0; // nothing to send yet
        return -1;
    }

    char read_buf[RECV_CHUNK];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, read_buf, sizeof(read_buf))) > 0) {
        ssize_t bytes_sent = send(client_fd, read_buf, bytes_read, 0);
        if (bytes_sent == -1) {
            // EPIPE means client disconnected, which is normal for the test script
            if (errno != EPIPE) {
                syslog(LOG_ERR, "send() to client %d failed: %s", client_fd, strerror(errno));
            }
            close(fd);
            return -1;
        }
    }
    close(fd);
    if (bytes_read < 0) {
        syslog(LOG_ERR, "read() from datafile failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* Get printable peer IP string from address */
static void sockaddr_to_ipstr(struct sockaddr *sa, socklen_t salen, char *out, size_t outlen) {
    if (!sa) {
        strncpy(out, "unknown", outlen);
        out[outlen - 1] = '\0';
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
        out[outlen - 1] = '\0';
    }
}

/*
 * handle_client_connection:
 *  - accumulates incoming bytes into a dynamic buffer
 *  - whenever a newline '\n' is observed, extract only that packet (up to and including '\n')
 *    and append to DATAFILE exactly once
 *  - after appending a packet, send the entire DATAFILE contents back to the client
 *  - continue processing additional packets if client sends them in the same connection
 */
static void *handle_client_connection(void *arg) {
    struct thread_data *td = (struct thread_data *)arg;
    char ipstr[INET6_ADDRSTRLEN] = {0};
    sockaddr_to_ipstr(&td->peer_addr, td->peer_len, ipstr, sizeof(ipstr));
    syslog(LOG_INFO, "Accepted connection from %s", ipstr);

    size_t buf_cap = RECV_CHUNK;
    size_t buf_len = 0;
    char *buf = malloc(buf_cap);
    if (!buf) {
        syslog(LOG_ERR, "malloc failed");
        close(td->client_fd);
        return NULL;
    }

    char rbuf[RECV_CHUNK];
    bool conn_closed = false;

    while (!conn_closed && !exit_requested) {
        ssize_t r = recv(td->client_fd, rbuf, sizeof(rbuf), 0);
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
                    close(td->client_fd);
                    return NULL;
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
                    if (pthread_mutex_lock(&file_mutex) != 0) {
                        syslog(LOG_ERR, "Failed to lock mutex");
                        conn_closed = true; // break outer loop
                        continue;
                    }

                    if (append_to_datafile(buf, buf_len) != 0) {
                        syslog(LOG_ERR, "append_to_datafile failed: %s", strerror(errno));
                    }

                    if (send_file_to_client(td->client_fd) != 0) {
                         // This can fail if client disconnects; not necessarily an error
                    }

                    if (pthread_mutex_unlock(&file_mutex) != 0) {
                        syslog(LOG_ERR, "Failed to unlock mutex");
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
    }     // end recv loop

    free(buf);
    syslog(LOG_INFO, "Closed connection from %s", ipstr);
    close(td->client_fd);
    td->thread_complete = true;

    return NULL;
}

static void *timestamp_thread(void *arg) {
    (void)arg; // suppress unused parameter warning
    time_t timer;
    char time_buf[100];
    struct tm *tm_info;

    while (!exit_requested) {
        sleep(10);
        if (exit_requested) break;

        time(&timer);
        tm_info = localtime(&timer);

        strftime(time_buf, sizeof(time_buf), "timestamp:%a, %d %b %Y %T %z\n", tm_info);

        if (pthread_mutex_lock(&file_mutex) != 0) {
            syslog(LOG_ERR, "Failed to lock mutex");
            continue;
        }

        // The append function is now simplified and doesn't manage the lock
        int fd = open(DATAFILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd >= 0) {
            write(fd, time_buf, strlen(time_buf));
            close(fd);
        }

        pthread_mutex_unlock(&file_mutex);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
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

    // Initialize thread list
    SLIST_INIT(&thread_list);

    // Create timestamp thread
    pthread_t timer_thread;
    if (pthread_create(&timer_thread, NULL, timestamp_thread, NULL) != 0) {
        syslog(LOG_ERR, "Failed to create timestamp thread");
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

        // Create thread data
        struct thread_data *td = malloc(sizeof(struct thread_data));
        if (!td) {
            syslog(LOG_ERR, "malloc failed");
            close(client_fd);
            continue;
        }
        td->client_fd = client_fd;
        td->thread_id = 0; // Will be filled by pthread_create
        td->thread_complete = false;
        memcpy(&td->peer_addr, &client_addr, addr_len);
        td->peer_len = addr_len;

        // Create thread
        if (pthread_create(&td->thread_id, NULL, handle_client_connection, td) != 0) {
            syslog(LOG_ERR, "Failed to create thread");
            close(client_fd);
            free(td);
            continue;
        }

        // Add thread to list
        SLIST_INSERT_HEAD(&thread_list, td, entries);
    }

    // Cancel timer thread
    exit_requested = 1;
    pthread_join(timer_thread, NULL);

    // Join and clean up all client threads
    struct thread_data *td, *tmp;
    SLIST_FOREACH_SAFE(td, &thread_list, entries, tmp) {
        pthread_join(td->thread_id, NULL);
        free(td);
    }
    // This second loop is a safety net for any threads that completed
    // but were not cleaned up in the main accept loop.
    while(!SLIST_EMPTY(&thread_list)) {
        td = SLIST_FIRST(&thread_list);
        SLIST_REMOVE_HEAD(&thread_list, entries);
        free(td);
    }


    syslog(LOG_INFO, "Exiting");
    if (listen_fd != -1) close(listen_fd);
    unlink(DATAFILE);
    pthread_mutex_destroy(&file_mutex);
    closelog();
    return 0;
}