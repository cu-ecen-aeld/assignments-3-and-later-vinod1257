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

#ifdef USE_AESD_CHAR_DEVICE
#define DATAFILE "/dev/aesdchar"
#else
#define DATAFILE "/var/tmp/aesdsocketdata"
#endif

#define RECV_CHUNK 1024

static volatile sig_atomic_t exit_requested = 0;
static int listen_fd = -1;
#ifndef USE_AESD_CHAR_DEVICE
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

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
    int fd = open(DATAFILE, O_WRONLY | O_APPEND);
    if (fd < 0) return -1;

    ssize_t bytes_written = write(fd, buf, len);
    close(fd);
    return (bytes_written == -1) ? -1 : 0;
}

/* Send the entire DATAFILE to client_fd. */
static int send_file_to_client(int client_fd) {
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

    char recv_buf[RECV_CHUNK];
    ssize_t bytes_read;

    // Open /dev/aesdchar lazily
    syslog(LOG_DEBUG, "Opening %s for read/write", DATAFILE);
    int data_fd = open(DATAFILE, O_RDWR);
    if (data_fd == -1) {
        syslog(LOG_ERR, "Failed to open %s: %s", DATAFILE, strerror(errno));
        close(td->client_fd);
        return NULL;
    }

    // Use an in-memory buffer to accumulate all received data
    size_t buf_size = RECV_CHUNK;
    size_t buf_len = 0;
    char *accumulated_data = malloc(buf_size);
    if (!accumulated_data) {
        syslog(LOG_ERR, "Failed to allocate memory for accumulated data");
        close(data_fd);
        close(td->client_fd);
        return NULL;
    }

    // Receive data from the client
    while ((bytes_read = recv(td->client_fd, recv_buf, sizeof(recv_buf), 0)) > 0) {
        recv_buf[bytes_read] = '\0'; // Null-terminate for logging
        syslog(LOG_DEBUG, "Received %zd bytes from client: %s", bytes_read, recv_buf);

        // Write received data to /dev/aesdchar
        syslog(LOG_DEBUG, "Writing %zd bytes to %s: %s", bytes_read, DATAFILE, recv_buf);
        if (write(data_fd, recv_buf, bytes_read) != bytes_read) {
            syslog(LOG_ERR, "Failed to write %zd bytes to %s: %s", bytes_read, DATAFILE, strerror(errno));
            break;
        }

        // Accumulate received data in memory
        if (buf_len + bytes_read > buf_size) {
            buf_size *= 2;
            char *new_buf = realloc(accumulated_data, buf_size);
            if (!new_buf) {
                syslog(LOG_ERR, "Failed to reallocate memory for accumulated data");
                break;
            }
            accumulated_data = new_buf;
        }
        memcpy(accumulated_data + buf_len, recv_buf, bytes_read);
        buf_len += bytes_read;

        // Read data back from /dev/aesdchar
        syslog(LOG_DEBUG, "Reading back from %s", DATAFILE);
        lseek(data_fd, 0, SEEK_SET); // Reset file offset to the beginning
        char read_buf[RECV_CHUNK];
        ssize_t read_bytes;
        while ((read_bytes = read(data_fd, read_buf, sizeof(read_buf))) > 0) {
            read_buf[read_bytes] = '\0'; // Null-terminate for logging
            syslog(LOG_DEBUG, "Read %zd bytes from %s: %s", read_bytes, DATAFILE, read_buf);

            // Send the data back to the client
            syslog(LOG_DEBUG, "Sending %zd bytes to client: %s", read_bytes, read_buf);
            if (send(td->client_fd, read_buf, read_bytes, 0) == -1) {
                syslog(LOG_ERR, "Failed to send %zd bytes to client: %s", read_bytes, strerror(errno));
                break;
            }
        }

        if (read_bytes == -1) {
            syslog(LOG_ERR, "Failed to read from %s: %s", DATAFILE, strerror(errno));
        }
    }

    if (bytes_read == -1) {
        syslog(LOG_ERR, "recv failed: %s", strerror(errno));
    }

    syslog(LOG_INFO, "Closing connection from %s", ipstr);
    free(accumulated_data);
    close(data_fd);
    close(td->client_fd);
    td->thread_complete = true;

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
    syslog(LOG_INFO, "Starting aesdsocket application");

    if (install_signal_handlers() < 0) {
        syslog(LOG_ERR, "Failed to install signal handlers: %s", strerror(errno));
        closelog();
        return -1;
    }

    listen_fd = setup_listen_socket();
    if (listen_fd < 0) {
        closelog();
        return -1;
    }

    if (daemon_mode) {
        syslog(LOG_INFO, "Running as daemon");
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

    // Join and clean up all client threads
    struct thread_data *td, *tmp;
    SLIST_FOREACH_SAFE(td, &thread_list, entries, tmp) {
        pthread_join(td->thread_id, NULL);
        free(td);
    }

    syslog(LOG_INFO, "Exiting");
    if (listen_fd != -1) close(listen_fd);
    closelog();
    return 0;
}