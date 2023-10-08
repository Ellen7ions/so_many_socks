#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// network
#include <arpa/inet.h>
#include <netinet/in.h>

// thread
#include <pthread.h>
#include <sys/poll.h>
#include <errno.h>

#define str_eq(x, y) (strcmp(x, y) == 0)
#define str_eqc(x, y) (strcasecmp(x, y) == 0)

#define DEFAULT_ADDR "127.0.0.1"
#define DEFAULT_PORT 23333

#ifdef SOCKS_DEBUG

#define SS_DEBUG(...)                                                        \
    printf("\033[32m[SOCKS INFO at\033[0m %d \033[32m]\033[0m ", __LINE__); \
    printf(__VA_ARGS__);                                                    \
    printf("\n");

#else
#define SS_DEBUG(...)
#endif

#define SS_UNUSED(x) (void)(x)

// parse args

typedef enum {
    OK,
    DEFAULT_ARG,
    MISS_ARGS,
    ERROR_FORMAT
} arg_result_t;

typedef struct {
    struct in_addr ip;
    in_port_t port;
} args_t;

arg_result_t parse_args(args_t *args, int argc, char *argv[]);

// socks
typedef enum {
    NO_AUTHENTICATION = 0,
    GSSAPI,
    USERNAME_PASSWORD,
    NO_ACCEPTABLE = -1
} ss_method;

typedef struct {
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[256];
} ss_cli_shake_req;

typedef struct {
    uint8_t ver;
    uint8_t method;
} ss_ser_shake_resp;


typedef enum {
    CONNECT = 1,
    BIND,
    UDP,
} ss_svc_cmd;

enum ss_svc_addr_type {
    IPv4 = 1,
    DOMAIN = 3,
    IPv6 = 4,
};

enum svc_statu_code {
    SUCCEED = 0,
    GENERAL_FAILURE,
    CONNECTION_NOT_ALLOWED,
    NETWORK_UNREACHABLE,
    HOST_UNREACHABLE,
    CONNECTION_REFUSED,
    TTL_EXPIRED,
    COMMAND_NOT_SUP,
    ADDR_TYPE_NOT_SUP,
};

typedef struct {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    union {
        struct {
            uint8_t addr[4];
        } ipv4_addr;
        struct {
            uint8_t addr[16];
        } ipv6_addr;
        struct {
            uint8_t len;
            char domain[256];
        } domain;
    } addr;
    uint16_t port;
} ss_cli_svc_req;

int ss_parse_cli_shake_req(const char *buf, ssize_t n, ss_cli_shake_req *req);

int ss_send_ser_shake_resp(int fd, ss_cli_shake_req *req);

int ss_parse_cli_svc_req(char *buf, ssize_t n, ss_cli_svc_req *req);

int ss_send_ser_svc_resp(int fd, ss_cli_svc_req *req);

// server

typedef struct {
    int fd;
} socks_server;

typedef enum {
    SS_CONNECT,
    SS_NEED_AUTH,
    SS_AUTHED,
} server_state;

typedef struct {
    int client_fd;
    server_state state;
} serve_params;

int ss_startup(args_t args, socks_server *server);

void *ss_serve(void *);

int ss_remote_conn(struct sockaddr_in addr);

int main(int argc, char *argv[]) {
    args_t args;
    arg_result_t arg_res = parse_args(&args, argc, argv);
    switch (arg_res) {
        case OK: {
            printf("parse args successfully ! listening on %s:%d\n",
                   inet_ntoa(args.ip), ntohs(args.port));
            break;
        }
        case DEFAULT_ARG: {
            printf("use default settings. listening on %s:%d\n",
                   inet_ntoa(args.ip), ntohs(args.port));
            break;
        }
        case MISS_ARGS:
            perror("miss args !");
            return EXIT_FAILURE;
        case ERROR_FORMAT:
            perror("error format !");
            return EXIT_FAILURE;
        default:
            SS_UNUSED(0);
    }

    socks_server server;
    ss_startup(args, &server);

    close(server.fd);
    return EXIT_SUCCESS;
}

void build_ip_port_raw(struct sockaddr_in *addr, const char *ip, const char *port) {
    addr->sin_family = AF_INET;
    addr->sin_port = htons(atoi(port));
    addr->sin_addr.s_addr = inet_addr(ip);
}

void build_ip_port(struct sockaddr_in *addr, struct in_addr ip, in_port_t port) {
    addr->sin_family = AF_INET;
    addr->sin_port = port;
    addr->sin_addr = ip;
}

arg_result_t parse_args(args_t *args, int argc, char *argv[]) {
    args->ip.s_addr = inet_addr(DEFAULT_ADDR);
    args->port = htons(DEFAULT_PORT);
    if (argc == 1) {
        return DEFAULT_ARG;
    }
    SS_DEBUG("argc = %d", argc);
    for (int i = 1; i < argc; i++) {
        if (str_eqc(argv[i], "-a") || str_eqc(argv[i], "--addr")) {
            if (i + 1 == argc) {
                return MISS_ARGS;
            }

            args->ip.s_addr = inet_addr(argv[i + 1]);
            if (args->ip.s_addr == -1)
                return ERROR_FORMAT;
        } else if (str_eqc(argv[i], "-p") || str_eqc(argv[i], "--port")) {
            if (i + 1 == argc) {
                return MISS_ARGS;
            }
            args->port = htons(atoi(argv[i + 1]));
        }
    }

    return OK;
}


int ss_parse_cli_shake_req(const char *buf, ssize_t n, ss_cli_shake_req *req) {
    if (n < 3) return -1;
    if (buf[0] != 5 || buf[1] <= 0) return -1;
    req->ver = buf[0];
    req->nmethods = buf[1];
    for (int i = 0; i < req->nmethods; i++)
        req->methods[i] = buf[2 + i];
    return 0;
}

int ss_send_ser_shake_resp(int fd, ss_cli_shake_req *req) {
    for (int i = 0; i < req->nmethods; i++) {
        if (req->methods[i] == NO_AUTHENTICATION) goto ok;
    }
    return -1;
    ok:
    SS_UNUSED(0);
    ss_ser_shake_resp resp = (ss_ser_shake_resp) {
            .ver = 5,
            .method = NO_AUTHENTICATION,
    };

    write(fd, &resp, sizeof(ss_ser_shake_resp));
    return NO_AUTHENTICATION;
}

int ss_parse_cli_svc_req(char *buf, ssize_t n, ss_cli_svc_req *req) {
    if (n < 5) return -1;
    req->ver = buf[0];
    req->cmd = buf[1];
    req->rsv = buf[2];
    req->atyp = buf[3];
    if (req->ver != 5 || req->rsv != 0) return -1;
    ssize_t rn = 4;
    switch (req->atyp) {
        case IPv4:
            memcpy(&req->addr, buf + rn, 4);
            rn += 4;
            break;
        case IPv6:
            memcpy(&req->addr, buf + rn, 16);
            rn += 16;
            break;
        case DOMAIN: {
            req->addr.domain.len = buf[rn];
            rn += 1;
            memcpy(&req->addr, buf + rn + 1, req->addr.domain.len);
            rn += req->addr.domain.len;
            break;
        }
    }
    memcpy(&req->port, buf + rn, 2);
    req->port = ntohs(req->port);
    return 0;
}

int ss_send_ser_svc_resp(int fd, ss_cli_svc_req *req) {
    struct sockaddr_in addr;
    build_ip_port(&addr,
                  *(struct in_addr *) (req->addr.ipv4_addr.addr),
                  htons(req->port));
    int rmt_fd = ss_remote_conn(addr);
    char buf[10] = {5, SUCCEED, 0, 1 /*AT_IPV4*/, 0, 0, 0, 0, 0, 0};
    write(fd, buf, 10);
    return rmt_fd;
}

int ss_startup(args_t args, socks_server *server) {
    server->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (server->fd == -1) {
        perror("socket create error !");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    build_ip_port(&server_addr, args.ip, args.port);

    SS_DEBUG("%s:%d\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

    if (bind(server->fd, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in)) == -1) {
        perror("bind error !");
        exit(EXIT_FAILURE);
    }

    if (listen(server->fd, SOMAXCONN) == -1) {
        perror("listen error !");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in client_addr;
    socklen_t addr_sz = sizeof(struct sockaddr_in);
    while (1) {
        int client_fd = accept(server->fd, (struct sockaddr *) &client_addr, &addr_sz);
        if (client_fd != -1) {
            pthread_t pth;
            serve_params param = (serve_params) {
                    .client_fd = client_fd,
                    .state = SS_CONNECT
            };
            pthread_create(&pth, NULL, ss_serve, (void *) &param);
        } else {
            perror("Failed to accept a client connection !");
        }
    }

}


static void copyloop(int fd1, int fd2) {
    struct pollfd fds[2] = {
            [0] = {.fd = fd1, .events = POLLIN},
            [1] = {.fd = fd2, .events = POLLIN},
    };

    while (1) {
        /* inactive connections are reaped after 15 min to free resources.
           usually programs send keep-alive packets so this should only happen
           when a connection is really unused. */
        switch (poll(fds, 2, 60 * 15 * 1000)) {
            case 0:
                return;
            case -1:
                if (errno == EINTR || errno == EAGAIN) continue;
                else perror("poll");
                return;
        }
        int infd = (fds[0].revents & POLLIN) ? fd1 : fd2;
        int outfd = infd == fd2 ? fd1 : fd2;
        char buf[1024];
        ssize_t sent = 0, n = read(infd, buf, sizeof buf);
        if (n <= 0) return;
        while (sent < n) {
            ssize_t m = write(outfd, buf + sent, n - sent);
            if (m < 0) return;
            sent += m;
        }
    }
}

void *ss_serve(void *void_p) {
    serve_params params = *(serve_params *) void_p;
    int rmt_fd = -1;
    char buf[1024];
    ssize_t n;

    while ((n = read(params.client_fd, buf, sizeof(buf))) > 0) {
        SS_DEBUG("state: %d", params.state);
        switch (params.state) {
            case SS_CONNECT: {
                ss_cli_shake_req sk_req;
                int res = ss_parse_cli_shake_req(buf, n, &sk_req);
                SS_DEBUG("rev ss req from client; ver=%d; nmethods=%d; mtd[0]=%d",
                         sk_req.ver, sk_req.nmethods, sk_req.methods[0]);

                if (res < 0) goto end;
                int auth_mtd = ss_send_ser_shake_resp(params.client_fd, &sk_req);
                SS_DEBUG("send ss resp to client;");
                if (auth_mtd < 0) goto end;

                if (auth_mtd == NO_AUTHENTICATION) params.state = SS_AUTHED;
                if (auth_mtd == SS_NEED_AUTH) params.state = SS_AUTHED;
                break;
            }
            case SS_NEED_AUTH: {
                // TODO: But I am lazy :)
                perror("we do not support to auth !");
                goto end;
            }
            case SS_AUTHED: {
                ss_cli_svc_req svc_req;
                int res = ss_parse_cli_svc_req(buf, n, &svc_req);

                SS_DEBUG("rev ss svc req from client;\n"
                         "ver=%d; cmd=%d; rsv=%d; atyp=%d; addr=%d.%d.%d.%d:%d",
                         svc_req.ver, svc_req.cmd, svc_req.rsv, svc_req.atyp,
                         svc_req.addr.ipv4_addr.addr[0],
                         svc_req.addr.ipv4_addr.addr[1],
                         svc_req.addr.ipv4_addr.addr[2],
                         svc_req.addr.ipv4_addr.addr[3],
                         svc_req.port);

                if (res < 0) goto end;
                rmt_fd = ss_send_ser_svc_resp(params.client_fd, &svc_req);
                if (rmt_fd < 0) goto end;

                copyloop(params.client_fd, rmt_fd);
                break;
            }
        }
    }


    end:
    if (rmt_fd != -1)
        close(rmt_fd);
    close(params.client_fd);
}

int ss_remote_conn(struct sockaddr_in addr) {
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

    if (sockfd == -1) {
        perror("failed to create socket !");
        return -1;
    }
    socklen_t len = sizeof(struct sockaddr_in);
    SS_DEBUG("connecting to %s:%d", inet_ntoa(addr.sin_addr), htons(addr.sin_port));
    if (connect(sockfd, (struct sockaddr *) &addr, len) == -1) {
        perror("connect failed !");
        return -1;
    }
    return sockfd;
}

