/* coap_io.c -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014,2016-2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

#include "coap3/coap_internal.h"

#ifdef HAVE_STDIO_H
#  include <stdio.h>
#endif

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H

# include <sys/socket.h>

# define OPTVAL_T(t)         (t)
# define OPTVAL_GT(t)        (t)
#endif
#ifdef HAVE_SYS_IOCTL_H

#include <sys/ioctl.h>

#endif
#ifdef HAVE_NETINET_IN_H

# include <netinet/in.h>

#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
# define OPTVAL_T(t)         (const char*)(t)
# define OPTVAL_GT(t)        (char*)(t)
# undef CMSG_DATA
# define CMSG_DATA WSA_CMSG_DATA
#endif
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#ifdef HAVE_UNISTD_H

# include <unistd.h>

#endif

#ifdef COAP_EPOLL_SUPPORT

#include <sys/epoll.h>
#include <sys/timerfd.h>

#ifdef HAVE_LIMITS_H

#include <limits.h>

#endif
#endif /* COAP_EPOLL_SUPPORT */

#ifdef WITH_CONTIKI
# include "uip.h"
#endif

#if !defined(WITH_CONTIKI) && !defined(RIOT_VERSION)
/* define generic PKTINFO for IPv4 */
#if defined(IP_PKTINFO)
#  define GEN_IP_PKTINFO IP_PKTINFO
#elif defined(IP_RECVDSTADDR)
#  define GEN_IP_PKTINFO IP_RECVDSTADDR
#else
#  error "Need IP_PKTINFO or IP_RECVDSTADDR to request ancillary data from OS."
#endif /* IP_PKTINFO */

/* define generic KTINFO for IPv6 */
#ifdef IPV6_RECVPKTINFO
#  define GEN_IPV6_PKTINFO IPV6_RECVPKTINFO
#elif defined(IPV6_PKTINFO)
#  define GEN_IPV6_PKTINFO IPV6_PKTINFO
#else
#  error "Need IPV6_PKTINFO or IPV6_RECVPKTINFO to request ancillary data from OS."
#endif /* IPV6_RECVPKTINFO */
#endif /* !(WITH_CONTIKI || RIOT_VERSION) */

#ifdef WITH_CONTIKI
static int ep_initialized = 0;

coap_endpoint_t *
coap_malloc_endpoint() {
    static coap_endpoint_t ep;

    if (ep_initialized) {
        return NULL;
    } else {
        ep_initialized = 1;
        return &ep;
    }
}

void
coap_mfree_endpoint(coap_endpoint_t *ep) {
    ep_initialized = 0;
}

int
coap_socket_bind_udp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
    sock->conn = udp_new(NULL, 0, NULL);

    if (!sock->conn) {
        coap_log(LOG_WARNING, "coap_socket_bind_udp");
        return 0;
    }

    coap_address_init(bound_addr);
    uip_ipaddr_copy(&bound_addr->addr, &listen_addr->addr);
    bound_addr->port = listen_addr->port;
    udp_bind((struct uip_udp_conn *)sock->conn, bound_addr->port);
    return 1;
}

int
coap_socket_connect_udp(coap_socket_t *sock,
                        const coap_address_t *local_if,
                        const coap_address_t *server,
                        int default_port,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr) {
    return 0;
}

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
    return -1;
}

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
    return -1;
}

void coap_socket_close(coap_socket_t *sock) {
    if (sock->conn)
        uip_udp_remove((struct uip_udp_conn *)sock->conn);
    sock->flags = COAP_SOCKET_EMPTY;
}

#else

#include "coap_config.h"
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>

#define SLIP_END     ((uint8_t)0300)
#define SLIP_ESC     ((uint8_t)0333)
#define SLIP_ESC_END ((uint8_t)0334)
#define SLIP_ESC_ESC ((uint8_t)0335)

#define IP_HDR_VER4 ((uint8_t)0004)
#define IP_HDR_VER6 ((uint8_t)0006)
#define IP_HDR_INDEX_ADDR_REMOTE_VER4 ((ssize_t)1)
#define IP_HDR_INDEX_ADDR_LOCAL_VER4 ((ssize_t)5)
#define IP_HDR_INDEX_PORT_REMOTE_VER4 ((ssize_t)9)
#define IP_HDR_INDEX_PORT_LOCAL_VER4 ((ssize_t)11)
#define IP_HDR_SIZE_VER4 ((ssize_t)13)
#define IP_HDR_INDEX_ADDR_REMOTE_VER6 ((ssize_t)1)
#define IP_HDR_INDEX_ADDR_LOCAL_VER6 ((ssize_t)17)
#define IP_HDR_INDEX_PORT_REMOTE_VER6 ((ssize_t)33)
#define IP_HDR_INDEX_PORT_LOCAL_VER6 ((ssize_t)35)
#define IP_HDR_SIZE_VER6 ((ssize_t)37)
#define BUFFER_SIZE UINT16_MAX

ssize_t slip_proto(uint8_t *p, const uint8_t *data, size_t len) {
    ssize_t send = 0;
    p[send++] = SLIP_END;

    while (len--) {
        switch (*data) {
            case SLIP_END:
                p[send++] = SLIP_ESC;
                p[send++] = SLIP_ESC_END;
                break;
            case SLIP_ESC:
                p[send++] = SLIP_ESC;
                p[send++] = SLIP_ESC_ESC;
                break;
            default:
                p[send++] = *data;
        }

        data++;
    }
    p[send++] = SLIP_END;
    return send;
}

ssize_t recv_packet(uint8_t *p, const uint8_t *data, size_t len) {
    uint8_t c;
    int received = 0;
    for (int i = 0; i < len; i++) {
        c = data[i];
        switch (c) {
            case SLIP_END:
                if (received)
                    return received;
                else
                    break;
            case SLIP_ESC:
                assert(i + 1 < len);
                i++;
                c = data[i];
                switch (c) {
                    case SLIP_ESC_END:
                        c = SLIP_END;
                        break;
                    case SLIP_ESC_ESC:
                        c = SLIP_ESC;
                        break;
                    default:
                        return -1;
                }
            default:
                if (received < len)
                    p[received++] = c;
        }
    }
    return received;
}

ssize_t slip_recv_packet(uint8_t *p, size_t len, coap_fd_t fd) {
    uint8_t c[BUFFER_SIZE];
    ssize_t received = 0;
    ssize_t index = 0;
    ssize_t received_packet_len = -1;

    do {
        memset(c,'\000',BUFFER_SIZE);
        received_packet_len = recv(fd, c, len, 0);
        if (received_packet_len == -1 && errno != EAGAIN) {
            coap_log(LOG_ERR,
                     "%s: read AF_UNIX socket failed: %s (%d)\n",
                     "coap_network_read",
                     coap_socket_strerror(), errno);
        }
        for (int index = 0; index < received_packet_len; index++) {

            switch (c[index]) {

                case SLIP_END:
                    if (received) {
                        return received;
                    } else
                        break;

                case SLIP_ESC:
                    if (index + 1 < received_packet_len) {
                        index++;
                    } else {
                        index = 0;
                        memset(&c, 0, UINT16_MAX);
                        received_packet_len = recv(fd, c, len, 0);
                        if (received_packet_len == -1 && errno != EAGAIN) {
                            coap_log(LOG_ERR,
                                     "%s: read AF_UNIX socket failed or wrong SLIP protocol: %s (%d)\n",
                                     "coap_network_read",
                                     coap_socket_strerror(), errno);
                        }

                    }
                    switch (c[index]) {
                        case SLIP_ESC_END:
                            c[index] = SLIP_END;
                            break;
                        case SLIP_ESC_ESC:
                            c[index] = SLIP_ESC;
                            break;
                        default:
                            return -1;
                    }

                default:
                    p[received++] = c[index];

            }
        }
    } while (received_packet_len > 0);
    return received;
}


coap_endpoint_t *
coap_malloc_endpoint(void) {
    return (coap_endpoint_t *) coap_malloc_type(COAP_ENDPOINT, sizeof(coap_endpoint_t));
}

void
coap_mfree_endpoint(coap_endpoint_t *ep) {
    coap_free_type(COAP_ENDPOINT, ep);
}

int
coap_socket_bind_udp(coap_socket_t *sock,
                     const coap_address_t *listen_addr,
                     coap_address_t *bound_addr) {
#ifndef RIOT_VERSION
    int on = 1, off = 0;
#endif /* RIOT_VERSION */
#ifdef _WIN32
    u_long u_on = 1;
#endif

    if (listen_addr->addr.sa.sa_family == AF_UNIX) {
        unlink(listen_addr->addr.su.sun_path);
    }

    sock->fd = socket(listen_addr->addr.sa.sa_family, SOCK_DGRAM, 0);

    if (sock->fd == COAP_INVALID_SOCKET) {
        coap_log(LOG_WARNING,
                 "coap_socket_bind_udp: socket: %s\n", coap_socket_strerror());
        goto error;
    }
#ifndef RIOT_VERSION
#ifdef _WIN32
    if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
    if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
        coap_log(LOG_WARNING,
                 "coap_socket_bind_udp: ioctl FIONBIO: %s\n", coap_socket_strerror());
    }

#ifndef RIOT_VERSION
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
        coap_log(LOG_WARNING,
                 "coap_socket_bind_udp: setsockopt SO_REUSEADDR: %s\n",
                 coap_socket_strerror());
#endif /* RIOT_VERSION */

    switch (listen_addr->addr.sa.sa_family) {
        case AF_INET:
            if (setsockopt(sock->fd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
                coap_log(LOG_ALERT,
                         "coap_socket_bind_udp: setsockopt IP_PKTINFO: %s\n",
                         coap_socket_strerror());
            break;
        case AF_INET6:
            /* Configure the socket as dual-stacked */
            if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
                coap_log(LOG_ALERT,
                         "coap_socket_bind_udp: setsockopt IPV6_V6ONLY: %s\n",
                         coap_socket_strerror());
#if !defined(ESPIDF_VERSION)
            if (setsockopt(sock->fd, IPPROTO_IPV6, GEN_IPV6_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
                coap_log(LOG_ALERT,
                         "coap_socket_bind_udp: setsockopt IPV6_PKTINFO: %s\n",
                         coap_socket_strerror());
#endif /* !defined(ESPIDF_VERSION) */
            setsockopt(sock->fd, IPPROTO_IP, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on));
            /* ignore error, because likely cause is that IPv4 is disabled at the os
               level */
            break;
        case AF_UNIX:
            if (setsockopt(sock->fd, SOL_SOCKET, GEN_IP_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR) {
                coap_log(LOG_ALERT,
                         "coap_socket_bind_udp: setsockopt SO_PASSCRED: %s\n",
                         coap_socket_strerror());
            }
            break;
        default:
            coap_log(LOG_ALERT, "coap_socket_bind_udp: unsupported sa_family\n");
            break;
    }
#endif /* RIOT_VERSION */

    if (bind(sock->fd, &listen_addr->addr.sa,
             listen_addr->addr.sa.sa_family == AF_INET ?
             (socklen_t) sizeof(struct sockaddr_in) :
             listen_addr->addr.sa.sa_family == AF_UNIX ?
             (socklen_t) sizeof(struct sockaddr_un) :
             (socklen_t) listen_addr->size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_bind_udp: bind: %s\n",
                 coap_socket_strerror());
        goto error;
    }

    bound_addr->size = (socklen_t)
            sizeof(*bound_addr);
    if (getsockname(sock->fd, &bound_addr->addr.sa, &bound_addr->size) < 0) {
        coap_log(LOG_WARNING,
                 "coap_socket_bind_udp: getsockname: %s\n",
                 coap_socket_strerror());
        goto error;
    }

    return 1;

    error:
    coap_socket_close(sock);
    return 0;
}

int
coap_socket_connect_udp(coap_socket_t *sock,
                        const coap_address_t *local_if,
                        const coap_address_t *server,
                        int default_port,
                        coap_address_t *local_addr,
                        coap_address_t *remote_addr) {
#ifndef RIOT_VERSION
    int on = 1;
    int off = 0;
#endif /* RIOT_VERSION */
#ifdef _WIN32
    u_long u_on = 1;
#endif
    coap_address_t connect_addr;
    int is_mcast = coap_is_mcast(server);
    coap_address_copy(&connect_addr, server);

    sock->flags &= ~(COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST);
    sock->fd = socket(connect_addr.addr.sa.sa_family, SOCK_DGRAM, 0);

    if (sock->fd == COAP_INVALID_SOCKET) {
        coap_log(LOG_WARNING, "coap_socket_connect_udp: socket: %s\n",
                 coap_socket_strerror());
        goto error;
    }

#ifndef RIOT_VERSION
#ifdef _WIN32
    if (ioctlsocket(sock->fd, FIONBIO, &u_on) == COAP_SOCKET_ERROR) {
#else
    if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
#endif
        coap_log(LOG_WARNING, "coap_socket_connect_udp: ioctl FIONBIO: %s\n",
                 coap_socket_strerror());
    }
#endif /* RIOT_VERSION */

    switch (connect_addr.addr.sa.sa_family) {
        case AF_INET:
            if (connect_addr.addr.sin.sin_port == 0)
                connect_addr.addr.sin.sin_port = htons(default_port);
            break;
        case AF_INET6:
            if (connect_addr.addr.sin6.sin6_port == 0)
                connect_addr.addr.sin6.sin6_port = htons(default_port);
#ifndef RIOT_VERSION
            /* Configure the socket as dual-stacked */
            if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
                coap_log(LOG_WARNING,
                         "coap_socket_connect_udp: setsockopt IPV6_V6ONLY: %s\n",
                         coap_socket_strerror());
#endif /* RIOT_VERSION */
            break;
        case AF_UNIX:
            strncpy(connect_addr.addr.su.sun_path, connect_addr.addr.su.sun_path,
                    sizeof(connect_addr.addr.su.sun_path) - 1);
            //connect_addr.addr.su.sun_path[sizeof(connect_addr.addr.su.sun_path) - 1] = '\000';
        default:
            coap_log(LOG_ALERT, "coap_socket_connect_udp: unsupported sa_family\n");
            break;
    }

    if (local_if && local_if->addr.sa.sa_family) {
#ifndef RIOT_VERSION
        if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
            coap_log(LOG_WARNING,
                     "coap_socket_connect_udp: setsockopt SO_REUSEADDR: %s\n",
                     coap_socket_strerror());
#endif /* RIOT_VERSION */
        if (bind(sock->fd, &local_if->addr.sa,
                 local_if->addr.sa.sa_family == AF_INET ?
                 (socklen_t) sizeof(struct sockaddr_in) :
                 local_if->addr.sa.sa_family == AF_UNIX ?
                 (socklen_t) sizeof(struct sockaddr_un) :
                 (socklen_t) local_if->size) == COAP_SOCKET_ERROR) {
            coap_log(LOG_WARNING, "coap_socket_connect_udp: bind: %s\n",
                     coap_socket_strerror());
            goto error;
        }
    }

    /* special treatment for sockets that are used for multicast communication */
    if (is_mcast) {
        if (!(local_if && local_if->addr.sa.sa_family)) {
            /* Bind to a (unused) port to simplify logging */
            coap_address_t bind_addr;

            coap_address_init(&bind_addr);
            bind_addr.addr.sa.sa_family = connect_addr.addr.sa.sa_family;
            if (bind(sock->fd, &bind_addr.addr.sa,
                     bind_addr.addr.sa.sa_family == AF_INET ?
                     (socklen_t) sizeof(struct sockaddr_in) :
                     (socklen_t) bind_addr.size) == COAP_SOCKET_ERROR) {
                coap_log(LOG_WARNING, "coap_socket_connect_udp: bind: %s\n",
                         coap_socket_strerror());
                goto error;
            }
        }
        if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
            coap_log(LOG_WARNING,
                     "coap_socket_connect_udp: getsockname for multicast socket: %s\n",
                     coap_socket_strerror());
        }
        coap_address_copy(remote_addr, &connect_addr);
        sock->flags |= COAP_SOCKET_MULTICAST;
        return 1;
    }

    if (connect(sock->fd, &connect_addr.addr.sa, connect_addr.size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_connect_udp: connect: %s\n",
                 coap_socket_strerror());
        goto error;
    }

    if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_connect_udp: getsockname: %s\n",
                 coap_socket_strerror());
    }

    if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_connect_udp: getpeername: %s\n",
                 coap_socket_strerror());
    }

    sock->flags |= COAP_SOCKET_CONNECTED;
    return 1;

    error:
    coap_socket_close(sock);
    return 0;
}

void coap_socket_close(coap_socket_t *sock) {
    if (sock->fd != COAP_INVALID_SOCKET) {
#ifdef COAP_EPOLL_SUPPORT
        coap_context_t *context = sock->session ? sock->session->context :
                                  sock->endpoint ? sock->endpoint->context : NULL;
        if (context != NULL) {
            int ret;
            struct epoll_event event;

            /* Kernels prior to 2.6.9 expect non NULL event parameter */
            ret = epoll_ctl(context->epfd, EPOLL_CTL_DEL, sock->fd, &event);
            if (ret == -1) {
                coap_log(LOG_ERR,
                         "%s: epoll_ctl DEL failed: %s (%d)\n",
                         "coap_socket_close",
                         coap_socket_strerror(), errno);
            }
        }
        sock->endpoint = NULL;
        sock->session = NULL;
#endif /* COAP_EPOLL_SUPPORT */
        coap_closesocket(sock->fd);
        sock->fd = COAP_INVALID_SOCKET;
    }
    sock->flags = COAP_SOCKET_EMPTY;
}

#ifdef COAP_EPOLL_SUPPORT

void
coap_epoll_ctl_mod(coap_socket_t *sock,
                   uint32_t events,
                   const char *func
) {
    int ret;
    struct epoll_event event;
    coap_context_t *context;

    if (sock == NULL)
        return;

    context = sock->session ? sock->session->context :
              sock->endpoint ? sock->endpoint->context : NULL;
    if (context == NULL)
        return;

    event.events = events;
    event.data.ptr = sock;

    ret = epoll_ctl(context->epfd, EPOLL_CTL_MOD, sock->fd, &event);
    if (ret == -1) {
        coap_log(LOG_ERR,
                 "%s: epoll_ctl MOD failed: %s (%d)\n",
                 func,
                 coap_socket_strerror(), errno);
    }
}

#endif /* COAP_EPOLL_SUPPORT */

ssize_t
coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
    ssize_t r;

    sock->flags &= ~(COAP_SOCKET_WANT_WRITE | COAP_SOCKET_CAN_WRITE);
#ifdef _WIN32
    r = send(sock->fd, (const char *)data, (int)data_len, 0);
#else
    r = send(sock->fd, data, data_len, 0);
#endif
    if (r == COAP_SOCKET_ERROR) {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
#elif EAGAIN != EWOULDBLOCK
        if (errno==EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
#else
        if (errno == EAGAIN || errno == EINTR) {
#endif
            sock->flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
            coap_epoll_ctl_mod(sock,
                               EPOLLOUT |
                               ((sock->flags & COAP_SOCKET_WANT_READ) ?
                                EPOLLIN : 0),
                               __func__);
#endif /* COAP_EPOLL_SUPPORT */
            return 0;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            coap_log(LOG_INFO, "coap_socket_write: send: %s\n",
                     coap_socket_strerror());
        } else {
            coap_log(LOG_WARNING, "coap_socket_write: send: %s\n",
                     coap_socket_strerror());
        }
        return -1;
    }
    if (r < (ssize_t) data_len) {
        sock->flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
        coap_epoll_ctl_mod(sock,
                           EPOLLOUT |
                           ((sock->flags & COAP_SOCKET_WANT_READ) ?
                            EPOLLIN : 0),
                           __func__);
#endif /* COAP_EPOLL_SUPPORT */
    }
    return r;
}

ssize_t
coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
    ssize_t r;
#ifdef _WIN32
    int error;
#endif

#ifdef _WIN32
    r = recv(sock->fd, (char *)data, (int)data_len, 0);
#else
    //r = slip_recv_packet(data, data_len, sock->fd);
    r = recv(sock->fd, data, data_len, 0);
#endif
    if (r == 0) {
        /* graceful shutdown */
        sock->flags &= ~COAP_SOCKET_CAN_READ;
        return -1;
    } else if (r == COAP_SOCKET_ERROR) {
        sock->flags &= ~COAP_SOCKET_CAN_READ;
#ifdef _WIN32
        error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
#elif EAGAIN != EWOULDBLOCK
        if (errno==EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
#else
        if (errno == EAGAIN || errno == EINTR) {
#endif
            return 0;
        }
#ifdef _WIN32
        if (error != WSAECONNRESET)
#else
        if (errno != ECONNRESET)
#endif
            coap_log(LOG_WARNING, "coap_socket_read: recv: %s\n",
                     coap_socket_strerror());
        return -1;
    }
    if (r < (ssize_t) data_len)
        sock->flags &= ~COAP_SOCKET_CAN_READ;
    return r;
}

#endif  /* WITH_CONTIKI */

#if (!defined(WITH_CONTIKI)) != (defined(HAVE_NETINET_IN_H) || defined(HAVE_WS2TCPIP_H))
/* define struct in6_pktinfo and struct in_pktinfo if not available
   FIXME: check with configure
*/
struct in6_pktinfo {
    struct in6_addr ipi6_addr;        /* src/dst IPv6 address */
    unsigned int ipi6_ifindex;        /* send/recv interface index */
};

struct in_pktinfo {
    int ipi_ifindex;
    struct in_addr ipi_spec_dst;
    struct in_addr ipi_addr;
};
#endif

#if !defined(WITH_CONTIKI) && !defined(SOL_IP)
/* Solaris expects level IPPROTO_IP for ancillary data. */
#define SOL_IP IPPROTO_IP
#endif

#if defined(_WIN32)
#include <mswsock.h>
static __declspec(thread) LPFN_WSARECVMSG lpWSARecvMsg = NULL;
/* Map struct WSABUF fields to their posix counterpart */
#define msghdr _WSAMSG
#define msg_name name
#define msg_namelen namelen
#define msg_iov lpBuffers
#define msg_iovlen dwBufferCount
#define msg_control Control.buf
#define msg_controllen Control.len
#define iovec _WSABUF
#define iov_base buf
#define iov_len len
#define iov_len_t u_long
#undef CMSG_DATA
#define CMSG_DATA WSA_CMSG_DATA
#define ipi_spec_dst ipi_addr
#pragma warning( disable : 4116 )
#else
#define iov_len_t size_t
#endif

#if defined(_CYGWIN_ENV)
#define ipi_spec_dst ipi_addr
#endif

#ifndef RIOT_VERSION

ssize_t
coap_network_send(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen) {
    ssize_t bytes_written = 0;
    uint8_t ip_packet[datalen + IP_HDR_SIZE_VER6];
    ssize_t packet_index = 0;
    memset(&ip_packet, '\000', datalen + IP_HDR_SIZE_VER6);

    switch (session->addr_info.remote.addr.sa.sa_family) {

        case AF_INET:
            ip_packet[0] = IP_HDR_VER4;
            packet_index = IP_HDR_SIZE_VER4;
            memcpy(&ip_packet[IP_HDR_INDEX_ADDR_REMOTE_VER4], &session->addr_info.remote.addr.sin.sin_addr,
                   sizeof(in_addr_t));
            memcpy(&ip_packet[IP_HDR_INDEX_ADDR_LOCAL_VER4], &session->addr_info.local.addr.sin.sin_addr,
                   sizeof(in_addr_t));
            memcpy(&ip_packet[IP_HDR_INDEX_PORT_REMOTE_VER4], &session->addr_info.remote.addr.sin.sin_port,
                   sizeof(in_port_t));
            memcpy(&ip_packet[IP_HDR_INDEX_PORT_LOCAL_VER4], &session->addr_info.local.addr.sin.sin_port,
                   sizeof(in_port_t));
            break;

        case AF_INET6:
            ip_packet[0] = IP_HDR_VER6;
            packet_index = IP_HDR_SIZE_VER6;
            memcpy(&ip_packet[IP_HDR_INDEX_ADDR_REMOTE_VER6], &session->addr_info.remote.addr.sin6.sin6_addr,
                   sizeof(uint8_t) * 16);
            memcpy(&ip_packet[IP_HDR_INDEX_ADDR_LOCAL_VER6], &session->addr_info.local.addr.sin6.sin6_addr,
                   sizeof(uint8_t) * 16);
            memcpy(&ip_packet[IP_HDR_INDEX_PORT_REMOTE_VER6], &session->addr_info.remote.addr.sin6.sin6_port,
                   sizeof(in_port_t));
            memcpy(&ip_packet[IP_HDR_INDEX_PORT_LOCAL_VER6], &session->addr_info.local.addr.sin6.sin6_port,
                   sizeof(in_port_t));
            break;

    }
    memcpy(&ip_packet[packet_index], data, datalen);

    // To ensure that the control data of the slip protocol fits into the slip_packet.
    uint8_t slip_packet[(datalen + packet_index) * 3];
    memset(slip_packet, '\000', (datalen + packet_index) * 3);
    ssize_t slip_packet_len = slip_proto(slip_packet, ip_packet, datalen + packet_index);

    if (!coap_debug_send_packet()) {
        bytes_written = slip_packet_len;
    } else {
        bytes_written = sendto(sock->fd, slip_packet, slip_packet_len, 0,
                               (const struct sockaddr *) &sock->remote_endpoint.addr.su,
                               sizeof(struct sockaddr_un));
    }
    return bytes_written;
}

#endif /* RIOT_VERSION */

#define SIN6(A) ((struct sockaddr_in6 *)(A))

void
coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length) {
    *address = packet->payload;
    *length = packet->length;
}

#ifndef RIOT_VERSION

ssize_t
coap_network_read(coap_socket_t *sock, coap_packet_t *packet) {
    assert(sock);
    assert(packet);

    uint8_t buffer[BUFFER_SIZE];
    uint8_t ip_packet[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    memset(ip_packet, 0, BUFFER_SIZE);
    ssize_t len = -1;
    ssize_t payload_len = -1;
    ssize_t hdr_len = -1;
    uint16_t port;
    uint32_t ip_address;

    socklen_t sock_size = sizeof(struct sockaddr_un);
    memset(&sock->remote_endpoint, 0, sizeof(coap_address_t));
    len = recvfrom(sock->fd, ip_packet, BUFFER_SIZE, 0, (struct sockaddr *) &sock->remote_endpoint, &sock_size);
    uint8_t slip_packet[len];
    memset(slip_packet, 0, len);
    len = recv_packet(slip_packet, ip_packet, len);

    char path[108];
    memset(path, 0, 108);
    snprintf(path, 108, "/tmp%s", sock->remote_endpoint.addr.su.sun_path);
    memcpy(sock->remote_endpoint.addr.su.sun_path, path, 108);
    if (len == -1) {
        coap_log(LOG_ERR,
                 "%s: read AF_UNIX socket failed: %s (%d)\n",
                 "coap_network_read",
                 coap_socket_strerror(), errno);
    }
    sock->remote_endpoint.addr.su.sun_family = AF_UNIX;
    socklen_t socklen = sizeof(struct sockaddr_un);
    sock->remote_endpoint.size = socklen;
    packet->ifindex = sock->fd;
    buffer[BUFFER_SIZE - 1] = '\000';

    coap_log(LOG_DEBUG, "coap_network_read: read got %zd bytes\n", len);

    switch (slip_packet[0]) {
        case IP_HDR_VER4:
            hdr_len = IP_HDR_SIZE_VER4;
            payload_len = (len - hdr_len) < -1 ? -1 : len - hdr_len;
            if (payload_len < 0) {
                coap_log(LOG_ERR,
                         "%s: receive header for ipv4 failed: %s (%d)\n",
                         "coap_network_read",
                         coap_socket_strerror(), errno);
                break;
            }
            payload_len = len - hdr_len;
            packet->addr_info.remote.size = sizeof(struct sockaddr_in);
            packet->addr_info.local.size = sizeof(struct sockaddr_in);
            packet->addr_info.remote.addr.sin.sin_family = AF_INET;
            packet->addr_info.local.addr.sin.sin_family = AF_INET;
            memcpy(&ip_address, &slip_packet[IP_HDR_INDEX_ADDR_REMOTE_VER4], sizeof(in_addr_t));
            memcpy(&packet->addr_info.remote.addr.sin.sin_addr, &ip_address, sizeof(in_addr_t));
            memcpy(&ip_address, &slip_packet[IP_HDR_INDEX_ADDR_LOCAL_VER4], sizeof(in_addr_t));
            memcpy(&packet->addr_info.local.addr.sin.sin_addr, &ip_address, sizeof(in_addr_t));
            memcpy(&port, &slip_packet[IP_HDR_INDEX_PORT_REMOTE_VER4], sizeof(in_port_t));
            packet->addr_info.remote.addr.sin.sin_port = htons(port);
            memcpy(&port, &slip_packet[IP_HDR_INDEX_PORT_LOCAL_VER4], sizeof(in_port_t));
            packet->addr_info.local.addr.sin.sin_port = htons(port);
            break;

        case IP_HDR_VER6:
            hdr_len = IP_HDR_SIZE_VER6;
            payload_len = len - hdr_len < -1 ? -1 : len - hdr_len;
            if (payload_len < 0) {
                coap_log(LOG_ERR,
                         "%s: receive header fpr ipv6 failed: %s (%d)\n",
                         "coap_network_read",
                         coap_socket_strerror(), errno);
                break;
            }
            packet->addr_info.remote.size = sizeof(struct sockaddr_in6);
            packet->addr_info.local.size = sizeof(struct sockaddr_in6);
            packet->addr_info.remote.addr.sin6.sin6_family = AF_INET6;
            packet->addr_info.local.addr.sin6.sin6_family = AF_INET6;
            memcpy(&packet->addr_info.remote.addr.sin6.sin6_addr, &slip_packet[IP_HDR_INDEX_ADDR_REMOTE_VER6],
                   sizeof(uint8_t) * 16);
            memcpy(&packet->addr_info.local.addr.sin6.sin6_addr, &slip_packet[IP_HDR_INDEX_ADDR_LOCAL_VER6],
                   sizeof(uint8_t) * 16);
            memcpy(&port, &slip_packet[IP_HDR_INDEX_PORT_REMOTE_VER6], sizeof(in_port_t));
            packet->addr_info.remote.addr.sin.sin_port = htons(port);
            memcpy(&port, &slip_packet[IP_HDR_INDEX_PORT_LOCAL_VER6], sizeof(in_port_t));
            packet->addr_info.local.addr.sin.sin_port = htons(port);
            break;

        default:
            coap_log(LOG_ERR,
                     "%s: ip address version not correct: %s (%d)\n",
                     "coap_network_read",
                     coap_socket_strerror(), errno);
            break;
    }
    if (payload_len > COAP_RXBUFFER_SIZE) {
        coap_log(LOG_WARNING, "packet exceeds buffer size, truncated\n");
        payload_len = COAP_RXBUFFER_SIZE;
    }
    if (payload_len >= 0) {
        packet->length = (payload_len > 0) ? payload_len : 0;
        memset(packet->payload, '\000', COAP_RXBUFFER_SIZE);
        memcpy(packet->payload, &slip_packet[hdr_len], payload_len);
        if (LOG_DEBUG <= coap_get_log_level()) {
            unsigned char addr_str[INET6_ADDRSTRLEN + 8];

            if (coap_print_addr(&packet->addr_info.remote, addr_str, INET6_ADDRSTRLEN + 8)) {
                coap_log(LOG_DEBUG, "received %zd bytes from %s\n", payload_len, addr_str);
            }
        }
    }
    return payload_len;

}

#endif /* RIOT_VERSION */

#if !defined(WITH_CONTIKI)

unsigned int
coap_io_prepare_epoll(coap_context_t *ctx, coap_tick_t now) {
#ifndef COAP_EPOLL_SUPPORT
    (void)ctx;
    (void)now;
    coap_log(LOG_EMERG,
             "coap_io_prepare_epoll() requires libcoap compiled for using epoll\n");
    return 0;
#else /* COAP_EPOLL_SUPPORT */
    coap_socket_t *sockets[1];
    unsigned int max_sockets = sizeof(sockets) / sizeof(sockets[0]);
    unsigned int num_sockets;
    unsigned int timeout;

    /* Use the common logic */
    timeout = coap_io_prepare_io(ctx, sockets, max_sockets, &num_sockets, now);
    /* Save when the next expected I/O is to take place */
    ctx->next_timeout = timeout ? now + timeout : 0;
    if (ctx->eptimerfd != -1) {
        struct itimerspec new_value;
        int ret;

        memset(&new_value, 0, sizeof(new_value));
        coap_ticks(&now);
        if (ctx->next_timeout != 0 && ctx->next_timeout > now) {
            coap_tick_t rem_timeout = ctx->next_timeout - now;
            /* Need to trigger an event on ctx->epfd in the future */
            new_value.it_value.tv_sec = rem_timeout / COAP_TICKS_PER_SECOND;
            new_value.it_value.tv_nsec = (rem_timeout % COAP_TICKS_PER_SECOND) *
                                         1000000;
        }
#ifdef COAP_DEBUG_WAKEUP_TIMES
        coap_log(LOG_INFO, "****** Next wakeup time %ld.%09ld\n",
                 new_value.it_value.tv_sec, new_value.it_value.tv_nsec);
#endif /* COAP_DEBUG_WAKEUP_TIMES */
        /* reset, or specify a future time for eptimerfd to trigger */
        ret = timerfd_settime(ctx->eptimerfd, 0, &new_value, NULL);
        if (ret == -1) {
            coap_log(LOG_ERR,
                     "%s: timerfd_settime failed: %s (%d)\n",
                     "coap_io_prepare_epoll",
                     coap_socket_strerror(), errno);
        }
    }
    return timeout;
#endif /* COAP_EPOLL_SUPPORT */
    }

/*
 * return  0 No i/o pending
 *       +ve millisecs to next i/o activity
 */
    unsigned int
    coap_io_prepare_io(coap_context_t *ctx,
                       coap_socket_t *sockets[],
                       unsigned int max_sockets,
                       unsigned int *num_sockets,
                       coap_tick_t now) {
        coap_queue_t *nextpdu;
        coap_endpoint_t *ep;
        coap_session_t *s, *rtmp;
        coap_tick_t session_timeout;
        coap_tick_t timeout = 0;
        coap_tick_t s_timeout;
#ifdef COAP_EPOLL_SUPPORT
        (void) sockets;
        (void) max_sockets;
#endif /* COAP_EPOLL_SUPPORT */

        *num_sockets = 0;

        /* Check to see if we need to send off any Observe requests */
        coap_check_notify(ctx);

        if (ctx->session_timeout > 0)
            session_timeout = ctx->session_timeout * COAP_TICKS_PER_SECOND;
        else
            session_timeout = COAP_DEFAULT_SESSION_TIMEOUT * COAP_TICKS_PER_SECOND;

#ifndef WITHOUT_ASYNC
        /* Check to see if we need to send off any Async requests */
        timeout = coap_check_async(ctx, now);
#endif /* WITHOUT_ASYNC */

        LL_FOREACH(ctx->endpoint, ep) {
#ifndef COAP_EPOLL_SUPPORT
            if (ep->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_ACCEPT)) {
                if (*num_sockets < max_sockets)
                    sockets[(*num_sockets)++] = &ep->sock;
            }
#endif /* ! COAP_EPOLL_SUPPORT */
            SESSIONS_ITER_SAFE(ep->sessions, s, rtmp) {
                if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 &&
                    s->delayqueue == NULL &&
                    (s->last_rx_tx + session_timeout <= now ||
                     s->state == COAP_SESSION_STATE_NONE)) {
                    coap_session_free(s);
                } else {
                    if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 && s->delayqueue == NULL) {
                        s_timeout = (s->last_rx_tx + session_timeout) - now;
                        if (timeout == 0 || s_timeout < timeout)
                            timeout = s_timeout;
                    }
                    /* Check if any server large receives have timed out */
                    if (s->lg_srcv) {
                        s_timeout = coap_block_check_lg_srcv_timeouts(s, now);
                        if (timeout == 0 || s_timeout < timeout)
                            timeout = s_timeout;
                    }
#ifndef COAP_EPOLL_SUPPORT
                    if (s->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE)) {
                        if (*num_sockets < max_sockets)
                            sockets[(*num_sockets)++] = &s->sock;
                    }
#endif /* ! COAP_EPOLL_SUPPORT */
                }
            }
        }
        SESSIONS_ITER_SAFE(ctx->sessions, s, rtmp) {
            if (!COAP_DISABLE_TCP
                && s->type == COAP_SESSION_TYPE_CLIENT
                && s->state == COAP_SESSION_STATE_ESTABLISHED
                && ctx->ping_timeout > 0
                    ) {
                if (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND <= now) {
                    if ((s->last_ping > 0 && s->last_pong < s->last_ping)
                        || ((s->last_ping_mid = coap_session_send_ping(s)) == COAP_INVALID_MID)) {
                        /* Make sure the session object is not deleted in the callback */
                        coap_session_reference(s);
                        coap_session_disconnected(s, COAP_NACK_NOT_DELIVERABLE);
                        coap_session_release(s);
                        continue;
                    }
                    s->last_rx_tx = now;
                    s->last_ping = now;
                }
                s_timeout = (s->last_rx_tx + ctx->ping_timeout * COAP_TICKS_PER_SECOND) - now;
                if (timeout == 0 || s_timeout < timeout)
                    timeout = s_timeout;
            }

            if (!COAP_DISABLE_TCP
                && s->type == COAP_SESSION_TYPE_CLIENT
                && COAP_PROTO_RELIABLE(s->proto)
                && s->state == COAP_SESSION_STATE_CSM
                && ctx->csm_timeout > 0
                    ) {
                if (s->csm_tx == 0) {
                    s->csm_tx = now;
                } else if (s->csm_tx + ctx->csm_timeout * COAP_TICKS_PER_SECOND <= now) {
                    /* Make sure the session object is not deleted in the callback */
                    coap_session_reference(s);
                    coap_session_disconnected(s, COAP_NACK_NOT_DELIVERABLE);
                    coap_session_release(s);
                    continue;
                }
                s_timeout = (s->csm_tx + ctx->csm_timeout * COAP_TICKS_PER_SECOND) - now;
                if (timeout == 0 || s_timeout < timeout)
                    timeout = s_timeout;
            }

            /* Check if any client large receives have timed out */
            if (s->lg_crcv) {
                s_timeout = coap_block_check_lg_crcv_timeouts(s, now);
                if (timeout == 0 || s_timeout < timeout)
                    timeout = s_timeout;
            }

#ifndef COAP_EPOLL_SUPPORT
            if (s->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_CONNECT)) {
                if (*num_sockets < max_sockets)
                    sockets[(*num_sockets)++] = &s->sock;
            }
#endif /* ! COAP_EPOLL_SUPPORT */
        }

        nextpdu = coap_peek_next(ctx);

        while (nextpdu && now >= ctx->sendqueue_basetime && nextpdu->t <= now - ctx->sendqueue_basetime) {
            coap_retransmit(ctx, coap_pop_next(ctx));
            nextpdu = coap_peek_next(ctx);
        }

        if (nextpdu && (timeout == 0 || nextpdu->t - (now - ctx->sendqueue_basetime) < timeout))
            timeout = nextpdu->t - (now - ctx->sendqueue_basetime);

        if (ctx->dtls_context) {
            if (coap_dtls_is_context_timeout()) {
                coap_tick_t tls_timeout = coap_dtls_get_context_timeout(ctx->dtls_context);
                if (tls_timeout > 0) {
                    if (tls_timeout < now + COAP_TICKS_PER_SECOND / 10)
                        tls_timeout = now + COAP_TICKS_PER_SECOND / 10;
                    coap_log(LOG_DEBUG, "** DTLS global timeout set to %dms\n",
                             (int) ((tls_timeout - now) * 1000 / COAP_TICKS_PER_SECOND));
                    if (timeout == 0 || tls_timeout - now < timeout)
                        timeout = tls_timeout - now;
                }
            } else {
                LL_FOREACH(ctx->endpoint, ep) {
                    if (ep->proto == COAP_PROTO_DTLS) {
                        SESSIONS_ITER(ep->sessions, s, rtmp) {
                            if (s->state == COAP_SESSION_STATE_HANDSHAKE &&
                                s->proto == COAP_PROTO_DTLS && s->tls) {
                                coap_tick_t tls_timeout = coap_dtls_get_timeout(s, now);
                                while (tls_timeout > 0 && tls_timeout <= now) {
                                    coap_log(LOG_DEBUG, "** %s: DTLS retransmit timeout\n",
                                             coap_session_str(s));
                                    /* Make sure the session object is not deleted in any callbacks */
                                    coap_session_reference(s);
                                    coap_dtls_handle_timeout(s);
                                    if (s->tls)
                                        tls_timeout = coap_dtls_get_timeout(s, now);
                                    else {
                                        tls_timeout = 0;
                                        timeout = 1;
                                    }
                                    coap_session_release(s);
                                }
                                if (tls_timeout > 0 && (timeout == 0 || tls_timeout - now < timeout))
                                    timeout = tls_timeout - now;
                            }
                        }
                    }
                }
                SESSIONS_ITER(ctx->sessions, s, rtmp) {
                    if (s->state == COAP_SESSION_STATE_HANDSHAKE &&
                        s->proto == COAP_PROTO_DTLS && s->tls) {
                        coap_tick_t tls_timeout = coap_dtls_get_timeout(s, now);
                        while (tls_timeout > 0 && tls_timeout <= now) {
                            coap_log(LOG_DEBUG, "** %s: DTLS retransmit timeout\n", coap_session_str(s));
                            /* Make sure the session object is not deleted in any callbacks */
                            coap_session_reference(s);
                            coap_dtls_handle_timeout(s);
                            if (s->tls)
                                tls_timeout = coap_dtls_get_timeout(s, now);
                            else {
                                tls_timeout = 0;
                                timeout = 1;
                            }
                            coap_session_release(s);
                        }
                        if (tls_timeout > 0 && (timeout == 0 || tls_timeout - now < timeout))
                            timeout = tls_timeout - now;
                    }
                }
            }
        }

        return (unsigned int) ((timeout * 1000 + COAP_TICKS_PER_SECOND - 1) / COAP_TICKS_PER_SECOND);
    }

#ifndef RIOT_VERSION

    int
    coap_io_process(coap_context_t *ctx, uint32_t timeout_ms) {
        return coap_io_process_with_fds(ctx, timeout_ms, 0, NULL, NULL, NULL);
    }

    int
    coap_io_process_with_fds(coap_context_t *ctx, uint32_t timeout_ms,
                             int enfds, fd_set *ereadfds, fd_set *ewritefds,
                             fd_set *eexceptfds) {
#if COAP_CONSTRAINED_STACK
        static coap_mutex_t static_mutex = COAP_MUTEX_INITIALIZER;
# ifndef COAP_EPOLL_SUPPORT
        static fd_set readfds, writefds, exceptfds;
        static coap_socket_t *sockets[64];
        unsigned int num_sockets = 0;
# endif /* ! COAP_EPOLL_SUPPORT */
#else /* ! COAP_CONSTRAINED_STACK */
# ifndef COAP_EPOLL_SUPPORT
        fd_set readfds, writefds, exceptfds;
        coap_socket_t *sockets[64];
        unsigned int num_sockets = 0;
# endif /* ! COAP_EPOLL_SUPPORT */
#endif /* ! COAP_CONSTRAINED_STACK */
        coap_fd_t nfds = 0;
        coap_tick_t before, now;
        unsigned int timeout;
#ifndef COAP_EPOLL_SUPPORT
        struct timeval tv;
        int result;
        unsigned int i;
#endif /* ! COAP_EPOLL_SUPPORT */

#if COAP_CONSTRAINED_STACK
        coap_mutex_lock(&static_mutex);
#endif /* COAP_CONSTRAINED_STACK */

        coap_ticks(&before);

#ifndef COAP_EPOLL_SUPPORT
        timeout = coap_io_prepare_io(ctx, sockets,
                                     (sizeof(sockets) / sizeof(sockets[0])),
                                     &num_sockets, before);
        if (timeout == 0 || timeout_ms < timeout)
            timeout = timeout_ms;

        if (ereadfds) {
            readfds = *ereadfds;
            nfds = enfds;
        }
        else {
            FD_ZERO(&readfds);
        }
        if (ewritefds) {
            writefds = *ewritefds;
            nfds = enfds;
        }
        else {
            FD_ZERO(&writefds);
        }
        if (eexceptfds) {
            exceptfds = *eexceptfds;
            nfds = enfds;
        }
        else {
            FD_ZERO(&exceptfds);
        }
        for (i = 0; i < num_sockets; i++) {
            if (sockets[i]->fd + 1 > nfds)
                nfds = sockets[i]->fd + 1;
            if (sockets[i]->flags & COAP_SOCKET_WANT_READ)
                FD_SET(sockets[i]->fd, &readfds);
            if (sockets[i]->flags & COAP_SOCKET_WANT_WRITE)
                FD_SET(sockets[i]->fd, &writefds);
#if !COAP_DISABLE_TCP
            if (sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT)
                FD_SET(sockets[i]->fd, &readfds);
            if (sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) {
                FD_SET(sockets[i]->fd, &writefds);
                FD_SET(sockets[i]->fd, &exceptfds);
            }
#endif /* !COAP_DISABLE_TCP */
        }

        if (timeout_ms == COAP_IO_NO_WAIT) {
            tv.tv_usec = 0;
            tv.tv_sec = 0;
            timeout = 1;
        }
        else if (timeout > 0) {
            tv.tv_usec = (timeout % 1000) * 1000;
            tv.tv_sec = (long)(timeout / 1000);
        }

        result = select((int)nfds, &readfds, &writefds, &exceptfds, timeout > 0 ? &tv : NULL);

        if (result < 0) {   /* error */
#ifdef _WIN32
            if (WSAGetLastError() != WSAEINVAL) { /* May happen because of ICMP */
#else
                if (errno != EINTR) {
#endif
                    coap_log(LOG_DEBUG, "%s", coap_socket_strerror());
#if COAP_CONSTRAINED_STACK
                    coap_mutex_unlock(&static_mutex);
#endif /* COAP_CONSTRAINED_STACK */
                    return -1;
                }
            }

            if (result > 0) {
                for (i = 0; i < num_sockets; i++) {
                    if ((sockets[i]->flags & COAP_SOCKET_WANT_READ) && FD_ISSET(sockets[i]->fd, &readfds))
                        sockets[i]->flags |= COAP_SOCKET_CAN_READ;
#if !COAP_DISABLE_TCP
                    if ((sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT) && FD_ISSET(sockets[i]->fd, &readfds))
                        sockets[i]->flags |= COAP_SOCKET_CAN_ACCEPT;
                    if ((sockets[i]->flags & COAP_SOCKET_WANT_WRITE) && FD_ISSET(sockets[i]->fd, &writefds))
                        sockets[i]->flags |= COAP_SOCKET_CAN_WRITE;
                    if ((sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) && (FD_ISSET(sockets[i]->fd, &writefds) || FD_ISSET(sockets[i]->fd, &exceptfds)))
                        sockets[i]->flags |= COAP_SOCKET_CAN_CONNECT;
#endif /* !COAP_DISABLE_TCP */
                }
            }

            coap_ticks(&now);
            coap_io_do_io(ctx, now);
            if (ereadfds) {
                *ereadfds = readfds;
            }
            if (ewritefds) {
                *ewritefds = writefds;
            }
            if (eexceptfds) {
                *eexceptfds = exceptfds;
            }

#else /* COAP_EPOLL_SUPPORT */
        (void) ereadfds;
        (void) ewritefds;
        (void) eexceptfds;
        (void) enfds;

        timeout = coap_io_prepare_epoll(ctx, before);

        if (timeout == 0 || timeout_ms < timeout)
            timeout = timeout_ms;

        do {
            struct epoll_event events[COAP_MAX_EPOLL_EVENTS];
            int etimeout = timeout;

            /* Potentially adjust based on what the caller wants */
            if (timeout_ms == COAP_IO_NO_WAIT) {
                etimeout = 0;
            } else if (timeout == COAP_IO_WAIT) {
                /* coap_io_prepare_epoll() returned 0 and timeout_ms COAP_IO_WAIT (0) */
                etimeout = -1;
            } else if (etimeout < 0) {
                /* epoll_wait cannot wait longer than this as int timeout parameter */
                etimeout = INT_MAX;
            }

            nfds = epoll_wait(ctx->epfd, events, COAP_MAX_EPOLL_EVENTS, etimeout);
            if (nfds < 0) {
                if (errno != EINTR) {
                    coap_log(LOG_ERR, "epoll_wait: unexpected error: %s (%d)\n",
                             coap_socket_strerror(), nfds);
                }
                break;
            }

            coap_io_do_epoll(ctx, events, nfds);

            /*
             * reset to COAP_IO_NO_WAIT (which causes etimeout to become 0)
             * incase we have to do another iteration
             * (COAP_MAX_EPOLL_EVENTS insufficient)
             */
            timeout_ms = COAP_IO_NO_WAIT;

            /* Keep retrying until less than COAP_MAX_EPOLL_EVENTS are returned */
        } while (nfds == COAP_MAX_EPOLL_EVENTS);

#endif /* COAP_EPOLL_SUPPORT */
        coap_expire_cache_entries(ctx);
        coap_ticks(&now);
#ifndef WITHOUT_ASYNC
        /* Check to see if we need to send off any Async requests as delay might
           have been updated */
        coap_check_async(ctx, now);
        coap_ticks(&now);
#endif /* WITHOUT_ASYNC */

#if COAP_CONSTRAINED_STACK
        coap_mutex_unlock(&static_mutex);
#endif /* COAP_CONSTRAINED_STACK */

        return (int) (((now - before) * 1000) / COAP_TICKS_PER_SECOND);
    }

#endif /* RIOT_VERSION */

#else /* WITH_CONTIKI */
    int coap_io_process(coap_context_t *ctx, uint32_t timeout_ms) {
        coap_tick_t now;

        coap_ticks(&now);
        /* There is something to read on the endpoint */
        ctx->endpoint->sock.flags |= COAP_SOCKET_CAN_READ;
        /* read in, and send off any responses */
        coap_io_do_io(ctx, now);  /* read received data */
        return -1;
    }

    unsigned int
    coap_io_prepare(coap_context_t *ctx,
                    coap_socket_t *sockets[],
                    unsigned int max_sockets,
                    unsigned int *num_sockets,
                    coap_tick_t now)
                    {
        *num_sockets = 0;
        return 0;
                    }
#endif /* WITH_CONTIKI */

#ifdef _WIN32
    const char *coap_socket_format_errno(int error) {
        static char szError[256];
        if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)szError, (DWORD)sizeof(szError), NULL) == 0)
            strcpy(szError, "Unknown error");
        return szError;
    }

    const char *coap_socket_strerror(void) {
        return coap_socket_format_errno(WSAGetLastError());
    }
#else /* _WIN32 */

    const char *coap_socket_format_errno(int error) {
        return strerror(error);
    }

    const char *coap_socket_strerror(void) {
        return coap_socket_format_errno(errno);
    }

#endif /* _WIN32 */

    ssize_t
    coap_socket_send(coap_socket_t *sock, coap_session_t *session,
                     const uint8_t *data, size_t data_len) {
        return session->context->network_send(sock, session, data, data_len);
    }

#undef SIN6
