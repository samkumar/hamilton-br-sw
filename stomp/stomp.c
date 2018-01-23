/*
 * Copyright (C) 2018 Sam Kumar <samkumar@berkeley.edu>
 * Copyright (C) 2018 University of California, Berkeley
 *
 * This is the Stream TO Message Protocol daemon, which receives a stream of
 * bytes in one unix socket (e.g., @stomp) and writes those bytes, chunked into
 * messages, to an output unix socket. The output unix socket could be a
 * channel in REthos.
 */

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define BUF_LEN 4096
char buffer[BUF_LEN];

static void check_fatal_error(const char* msg) {
    assert(errno);
    perror(msg);
    exit(1);
}

static int socket_un_create(void) {
    int dsock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (dsock == -1) {
        check_fatal_error("Could not create domain socket");
    }
    int flags = fcntl(dsock, F_GETFL);
    if (flags == -1) {
        check_fatal_error("Could not get socket flags");
    }
    flags = fcntl(dsock, F_SETFL, flags | O_NONBLOCK);
    if (flags == -1) {
        check_fatal_error("Could not set socket flags");
    }
    return dsock;
}

static size_t sockaddr_un_fill(struct sockaddr_un* addr, const char* name) {
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    strncpy(&addr->sun_path[1], name, sizeof(addr->sun_path) - 1);
    return strlen(name) + sizeof(addr->sun_family) + 1;
}

static void checked_write(int fd, const void* buffer, size_t size) {
    const char* buf = buffer;
    size_t written = 0;
    while (written < size) {
        ssize_t rv = write(fd, &buf[written], size - written);
        if (rv == -1) {
            char errbuf[50];
            snprintf(errbuf, sizeof(errbuf), "write to fd %d failed", fd);
            check_fatal_error(errbuf);
        }
        written += rv;
    }
}

int main(int argc, char** argv) {
    if (argc != 2 && argc != 3) {
        printf("Usage: %s <message socket name> [<serial socket name>]\n", argv[0]);
        return 1;
    }

    const char* message_socket_name = argv[1];
    const char* serial_socket_name;

    if (argc == 3) {
        message_socket_name = argv[2];
    } else {
        serial_socket_name = "stomp";
    }

    struct sockaddr_un addr;
    size_t addr_len;

    printf("Connecting to %s...\n", message_socket_name);
    int msock = socket_un_create();
    addr_len = sockaddr_un_fill(&addr, message_socket_name);
    if (connect(msock, (struct sockaddr*) &addr, addr_len) == -1) {
        check_fatal_error("Could not connect message socket");
    }
    printf("Done connecting to %s.\n", message_socket_name);

    printf("Listening on %s...\n", serial_socket_name);
    int lsock = socket_un_create();
    addr_len = sockaddr_un_fill(&addr, serial_socket_name);
    if (bind(lsock, (struct sockaddr*) &addr, addr_len) == -1) {
        check_fatal_error("Could not bind serial listen socket");
    }

    /* State variables for reading messages. */
    int message_header_bytes_left = 4;
    uint32_t message_body_bytes_left = 0;

    int ssock = -1;
    for (;;) {
        int first_fd = msock;
        int second_fd = (ssock == -1) ? lsock : ssock;
        int max_fd = (first_fd < second_fd) ? second_fd : first_fd;

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(msock, &read_fds);
        FD_SET(msock, &read_fds);

        int rv = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (rv == -1) {
            check_fatal_error("Could not wait for event");
        }

        if (FD_ISSET(msock, &read_fds)) {
            // Transfer message from msock to isock as bytes
            if (message_header_bytes_left != 0) {
                ssize_t bytes_read = read(msock, ((uint8_t*) &message_body_bytes_left) + (4 - message_header_bytes_left), sizeof(message_body_bytes_left));
                if (bytes_read == -1) {
                    check_fatal_error("Could not read from message socket");
                } else if (bytes_read == 0) {
                    printf("Message socket closed\n");
                    return 0;
                }
                if (message_header_bytes_left == 0) {
                    message_body_bytes_left = be32toh(message_body_bytes_left);
                }
                if (message_body_bytes_left == 0) {
                    message_header_bytes_left = 4;
                }
            } else {
                ssize_t bytes_read = read(msock, buffer, message_body_bytes_left < BUF_LEN ? message_body_bytes_left : BUF_LEN);
                if (bytes_read == -1) {
                    check_fatal_error("Could not read from message socket");
                } else if (bytes_read == 0) {
                    printf("Message socket closed\n");
                    return 0;
                } else {
                    if (ssock != -1) {
                        checked_write(ssock, buffer, bytes_read);
                    }
                    message_body_bytes_left -= bytes_read;
                    if (message_body_bytes_left == 0) {
                        message_header_bytes_left = 4;
                    }
                }
            }
        }

        if (ssock == -1) {
            if (FD_ISSET(lsock, &read_fds)) {
                // Accept incoming connection
                ssock = accept(lsock, NULL, NULL);
                if (ssock == -1) {
                    check_fatal_error("Could not accept serial connection");
                }
            }
        } else if (FD_ISSET(ssock, &read_fds)) {
            // Transfer bytes from ssock to msock, chunked as a message
            ssize_t bytes_read = read(ssock, buffer, BUF_LEN);
            if (bytes_read == -1) {
                check_fatal_error("Could not read from serial socket");
            } else if (bytes_read == 0) {
                int rv = close(ssock);
                if (rv == -1) {
                    check_fatal_error("Could not close serial socket");
                }
                ssock = -1;
            } else {
                uint32_t header = (uint32_t) bytes_read;
                header = htobe32(header);
                checked_write(msock, &header, sizeof(header));
                checked_write(msock, buffer, bytes_read);
            }
        }
    }

    return 0;
}
