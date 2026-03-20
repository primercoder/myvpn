#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <sqlite3.h>

#define RESET           "\033[0m"
#define WARN_YELLOW     "\033[93m"
#define ERROR_RED       "\033[31m"
#define MAIN_GREEN      "\033[92m"
#define TUN_MAGENTA     "\033[35m"
#define SESSION_CYAN    "\033[96m"
#define SIG_BLUE        "\033[94m"

#define CACERT "./keys/ca.crt"
#define MYCERT "./keys/server.crt"
#define MYKEY  "./keys/server.key"
#define MSGQUE "/writetun"
#define SQLFILE "./vpnserver.db"
#define SRVPORT 8888
#define TUNIPNET "192.168.53.1/24"
#define INTRANET "192.168.60.0/24"
#define BUFFERSIZE 2048
#define MAXEVENTS 256

struct clientinfo {
    pid_t pid;
    uint32_t ip;
    int fifo_write;
};
struct clientinfo *clientlist;
struct mq_attr mqattr = {
    .mq_flags = O_NONBLOCK,
    .mq_maxmsg = 256,
    .mq_msgsize = BUFFERSIZE,
    .mq_curmsgs = 0
};
pid_t mainpid, managerpid;
int tunfd, pipefd[2];
uint16_t port;
uint32_t tunip, tunnetid, tunhostid, tunmask, maxclients;   // 主机字节序
char intranet[20], tundevname[16];

int MAIN_argparse(int argc, char *argv[]);
/*
    通过形如 ipnetstr= "192.168.53.1/24" 的字符串获得如下信息:
    获得int类型ip地址 ip = 0xc0a83501
    获得int类型网络号 netid = 0xc0a83500
    获得int形式的主机号 hostid = 0x01
    获得int形式的掩码 mask = 0xffffff00
    获得网络中的最大主机数量 maxhosts = 256
*/
void PUB_netstrparse(const char *ipnetstr, uint32_t *ip, uint32_t *netid, uint32_t *hostid, uint32_t *mask, uint32_t *maxhosts);
void MAIN_printconfig();
int MAIN_createtun(uint32_t ip, uint32_t mask, char name[16]);
int MAIN_createmsgque(const char *mqname, struct mq_attr attr);
int PUB_add_to_epoll(char *colortag, char *processname, int epoll_fd, int fd, uint32_t events, const char *desc);
void TunManagerProcess();
void MANAGER_recv_mainpipe(int pipereadfd);
void MANAGER_recv_tunfd(int tunfd);
void MANAGER_recv_mqfd(int mqfd);
SSL_CTX *MAIN_create_sslctx();
int MAIN_setupsocket(uint16_t port);
void HandleSession(SSL_CTX *ctx, uint32_t assign_hostid, int client_sockfd);
int SESSION_sha256(const uint8_t *data, size_t data_len, uint8_t *hashstr);
int SESSION_recv_managerfifo(int pipereadfd, SSL *ssl, uint32_t assign_hostid);
int SESSION_recv_client(SSL *ssl, int mqfd, uint32_t assign_hostid);
int SESSION_sql_search(char *user, char *sqlhash);
void MAIN_sigchld_handler(int sig);
int SESSION_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

int main(int argc, char *argv[])
{
    mainpid = getpid();
    printf(MAIN_GREEN"[MAIN]: Initial pid: %d\n"RESET, mainpid);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = MAIN_sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    if(sigaction(SIGCHLD, &sa, NULL) == -1) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to setup sigchld process\n"RESET);
        return 0;
    }
    if(sigaction(SIGINT, &sa, NULL) == -1) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to setup sigint process\n"RESET);
        return 0;
    }
    if(MAIN_argparse(argc, argv)<0) {
        return 0;
    }
    MAIN_printconfig();
    tunfd = MAIN_createtun(tunip, tunmask, tundevname);
    if(tunfd < 0) {
        return 0;
    }
    printf(MAIN_GREEN"[MAIN]: Created tun device: %s\n"RESET, tundevname);
    if(MAIN_createmsgque(MSGQUE, mqattr) < 0) {
        return 0;
    }
    printf(MAIN_GREEN"[MAIN]: Created msg queue file: %s\n"RESET, MSGQUE);
    if(pipe(pipefd) == -1) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to create pipe\n"RESET);
        return 0;
    }
    managerpid = fork();
    if(managerpid==0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(pipefd[1]);
        printf(TUN_MAGENTA"[TunManager]: Process start: %d\n"RESET, getpid());
        TunManagerProcess();
        exit(0);
    }
    close(tunfd);
    close(pipefd[0]);
    SSL_CTX *ctx = MAIN_create_sslctx();
    if(ctx == NULL) {
        return 0;
    }
    printf(MAIN_GREEN"[MAIN]: Created new ssl ctx\n"RESET);
    int sockfd = MAIN_setupsocket(port);
    if(sockfd < 0) {
        return 0;
    }
    printf(MAIN_GREEN"[MAIN]: Server is listening at port %hu\n"RESET, port);
    
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in client_addr;
    int client_sockfd;
    while(1) {
        printf(MAIN_GREEN"[MAIN]: Waiting for the next client...\n"RESET);
        client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &addrlen);
        if(client_sockfd < 0) {
            printf(MAIN_GREEN"[MAIN]: "WARN_YELLOW"Failed to accept this TCP connect\n"RESET);
            continue;
        }
        printf(MAIN_GREEN"[MAIN]: Accepted client %s:%hu\n"RESET, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        uint32_t assign_hostid = 0;
        for(int i=1;i<maxclients;i++) {
            if(clientlist[i].pid==-1) {
                assign_hostid = i;
                break;
            }
        }
        if(assign_hostid == 0) {
            printf(MAIN_GREEN"[MAIN]: "WARN_YELLOW"There is no more tun ip to assign\n"RESET);
            close(client_sockfd);
            continue;
        }
        char fifoname[32];
        sprintf(fifoname, "./fifodir/fifo%u", assign_hostid);
        if(mkfifo(fifoname, 0644)<0) {
            printf(MAIN_GREEN"[MAIN]: "WARN_YELLOW"Failed to create fifo for this session\n"RESET);
            close(client_sockfd);
            continue;
        }
        printf(MAIN_GREEN"[MAIN]: Created fifo: %s for this session\n"RESET, fifoname);
        pid_t pid = fork();
        if(pid==0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            close(sockfd);
            close(tunfd);
            close(pipefd[1]);
            free(clientlist);
            printf(SESSION_CYAN"[Session:%2u] Process start: %d\n"RESET, assign_hostid, getpid());
            HandleSession(ctx, assign_hostid, client_sockfd);
            exit(0);
        }
        clientlist[assign_hostid].pid = pid;
        write(pipefd[1], &clientlist[assign_hostid], sizeof(struct clientinfo));
        close(client_sockfd);
    }
    return 0;
}

int MAIN_argparse(int argc, char *argv[]) {
    if(argc == 1) {
        port = SRVPORT;
        PUB_netstrparse(TUNIPNET, &tunip, &tunnetid, &tunhostid, &tunmask, &maxclients);
        clientlist = (struct clientinfo *)malloc(maxclients * sizeof(struct clientinfo));
        strcpy(intranet, INTRANET);
    } else if(argc==2 && strcmp(argv[1], "--help")==0) {
        printf("USAGE1: %s\n", argv[0]);
        printf("USAGE2: %s <port> <tun net> <intranet\n", argv[0]);
        printf("    eg: %s %hu %s %s\n", argv[0], SRVPORT, TUNIPNET, INTRANET);
        return -1;
    } else if(argc==4) {
        sscanf(argv[1], "%hu", &port);
        PUB_netstrparse(argv[2], &tunip, &tunnetid, &tunhostid, &tunmask, &maxclients);
        clientlist = (struct clientinfo *)malloc(maxclients * sizeof(struct clientinfo));
        strcpy(intranet, argv[3]);
    } else {
        printf("INVALID USAGE\n");
        printf("Use --help to see more about it\n");
        return -1;
    }
    for(uint32_t i=0;i<maxclients;i++) {
        clientlist[i].pid = -1;
        clientlist[i].ip = tunnetid+i;
        clientlist[i].fifo_write = -1;
    }
    clientlist[0].pid = clientlist[tunhostid].pid = getpid();
    return 0;
}

void PUB_netstrparse(const char *ipnetstr, uint32_t *ip, uint32_t *netid, uint32_t *hostid, uint32_t *mask, uint32_t *maxhosts) {
    uint8_t masklen;
    sscanf(ipnetstr, "%hhu.%hhu.%hhu.%hhu/%hhu",
        (uint8_t *)ip+3, (uint8_t *)ip+2,
        (uint8_t *)ip+1, (uint8_t *)ip, &masklen);
    *mask = (uint32_t)0xffffffff << (32-masklen);
    *netid = *ip & *mask;
    *hostid = *ip & ((uint32_t)0xffffffff >> masklen);
    *maxhosts = 1 << (32-masklen);
}

void MAIN_printconfig() {
    printf(MAIN_GREEN"[MAIN]: Configuration:\n");
    printf("    Listen Port: %hu\n", port);
    printf("    TUN IP     : %hhu.%hhu.%hhu.%hhu\n", 
        *((uint8_t *)&tunip+3), *((uint8_t *)&tunip+2), *((uint8_t *)&tunip+1), *((uint8_t *)&tunip));
    printf("    TUN MASK   : %hhu.%hhu.%hhu.%hhu\n",
        *((uint8_t *)&tunmask+3), *((uint8_t *)&tunmask+2), *((uint8_t *)&tunmask+1), *((uint8_t *)&tunmask));
    printf("    MAX CLIENTS: %u\n", maxclients);
    printf("    INTRA NET  : %s\n\n"RESET, intranet);
}

int MAIN_createtun(uint32_t ip, uint32_t mask, char name[16]) {
    int fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to open /dev/net/tun\n"RESET);
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if(ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to ioctl setup tun\n"RESET);
        close(fd);
        return -1;
    }
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to create sockfd for tun setup\n"RESET);
        close(fd);
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ip);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to set tun ip\n"RESET);
        close(sockfd);
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(mask);
    memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to set tun mask\n"RESET);
        close(sockfd);
        close(fd);
        return -1;
    }
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to turn on tun\n"RESET);
        close(sockfd);
        close(fd);
        return -1;
    }
    close(sockfd);
    strcpy(name, ifr.ifr_name);
    return fd;
}

int MAIN_createmsgque(const char *mqname, struct mq_attr attr) {
    mq_unlink(mqname);
    int fd = mq_open(MSGQUE, O_CREAT, 0644, &attr);
    if(fd == -1) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to create msg queue\n"RESET);
        return -1;
    }
    mq_close(fd);
    return 0;
}

void TunManagerProcess() {
    int mqfd = mq_open(MSGQUE, O_RDONLY, 0644, NULL);
    if(mqfd == -1) {
        printf(TUN_MAGENTA"[TunManager]: "ERROR_RED"Failed to open msg queue\n"RESET);
        close(pipefd[0]);
        exit(0);
    }
    printf(TUN_MAGENTA"[TunManager]: Opened msg queue: %s\n"RESET, MSGQUE);
    int epoll_fd = epoll_create1(0);
    if(epoll_fd == -1) {
        printf(TUN_MAGENTA"[TunManager]: "ERROR_RED"Failed to create epoll fd\n");
        close(mqfd);
        close(pipefd[0]);
        exit(0);
    }
    printf(TUN_MAGENTA"[TunManager]: Created epoll (fd=%d)\n"RESET, epoll_fd);
    if(PUB_add_to_epoll(TUN_MAGENTA, "[TunManager]", epoll_fd, pipefd[0], EPOLLIN, "PIPE_FROM_MAIN")<0) {
        goto clear;
    }
    if(PUB_add_to_epoll(TUN_MAGENTA, "[TunManager]", epoll_fd, mqfd, EPOLLIN, "MSGQUEUE_FROM_SESSION")<0) {
        goto clear;
    }
    if(PUB_add_to_epoll(TUN_MAGENTA, "[TunManager]", epoll_fd, tunfd, EPOLLIN, "TUN_TO_CLIENTS")<0) {
        goto clear;
    }
    int nfds;
    struct epoll_event events[MAXEVENTS];
    while(1) {
        nfds = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
        if(nfds == -1) {
            if(errno == EINTR) {
                printf(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Interpreted by Signal\n"RESET);
                continue;
            }
            printf(TUN_MAGENTA"[TunManager]: "ERROR_RED"Error during epoll_wait\n");
            break;
        }
        for(int i=0;i<nfds;i++) {
            int fd = events[i].data.fd;
            if(events[i].events & (EPOLLERR | EPOLLHUP)) {
                printf(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"File Description %d error or hang up\n"RESET, fd);
                if(fd == pipefd[0]) {
                    printf(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Pipe from MAIN error or hang up, Cannot update clientlist\n");
                } else {
                    printf("[TunManager]: "ERROR_RED"Critical Error, Mqueue or tunfd failure\n"RESET);
                    goto clear;
                }
                continue;
            }
            if(fd == pipefd[0]) {
                MANAGER_recv_mainpipe(fd);
            } else if(fd == tunfd) {
                MANAGER_recv_tunfd(fd);
            } else if(fd == mqfd) {
                MANAGER_recv_mqfd(fd);
            }
        }
    }
clear:
    close(epoll_fd);
    close(mqfd);
    close(tunfd);
    close(pipefd[0]);
    exit(0);
}

int PUB_add_to_epoll(char *colortag, char *processname, int epoll_fd, int fd, uint32_t events, const char *desc) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        printf("%s%s: "ERROR_RED"Failed to add %s (fd=%d) to epoll\n"RESET,colortag, processname, desc, fd);
        return -1;
    }
    printf("%s%s: Added %s (fd=%d) to epoll\n"RESET, colortag, processname, desc, fd);
    return 0;
}

void MANAGER_recv_mainpipe(int pipereadfd) {
    uint8_t buffer[BUFFERSIZE];
    long bytes;
    bytes = read(pipereadfd, buffer, BUFFERSIZE);
    if(bytes < 0) {
        printf(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Failed to read from main pipe\n");
        return;
    }
    struct clientinfo getinfo;
    memcpy(&getinfo, buffer, sizeof(getinfo));
    for(uint32_t i=1;i<maxclients;i++) {
        if(clientlist[i].ip == getinfo.ip) {
            clientlist[i].pid = getinfo.pid;
            if(getinfo.pid == -1) {
                close(clientlist[i].fifo_write);
            } else {
                char fifofilename[32];
                sprintf(fifofilename, "./fifodir/fifo%u", i);
                clientlist[i].fifo_write = open(fifofilename, O_WRONLY);
                if(clientlist[i].fifo_write == -1) {
                    perror(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Failed to open fifo"RESET);
                    clientlist[i].pid = -1;
                    return;
                }
            }
            printf(TUN_MAGENTA"[TunManager]: Get client data (pid=%d, assign hostid=%u)\n"RESET, getinfo.pid, i);
            break;
        }
    }
}

void MANAGER_recv_tunfd(int tunfd) {
    uint8_t buffer[BUFFERSIZE];
    long bytes;
    bytes = read(tunfd, buffer, BUFFERSIZE);
    if(bytes < 0) {
        printf(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Failed to read from tun\n");
        return;
    }
    if((buffer[0]&0xf0)!=0x40) {
        printf(TUN_MAGENTA"[TunManager]: Got a Non IPv4 packet from TUN, pass it\n");
        return;
    }
    uint32_t dstip;
    *((uint8_t *)&dstip+3) = buffer[16];
    *((uint8_t *)&dstip+2) = buffer[17];
    *((uint8_t *)&dstip+1) = buffer[18];
    *((uint8_t *)&dstip) = buffer[19];
    for(uint32_t i=1;i<maxclients;i++) {
        if(clientlist[i].pid>0 && clientlist[i].ip==dstip) {
            long wrt = write(clientlist[i].fifo_write, buffer, bytes);
            if(wrt < 0) {
                char errmsg[100];
                sprintf(errmsg, TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Failed to Write to Client fifo (assign hostid=%u)"RESET, i);
                perror(errmsg);
                return;
            }
            printf(TUN_MAGENTA"[TunManager]: Transmitted packet(%hhu.%hhu.%hhu.%hhu --> %hhu.%hhu.%hhu.%hhu) tunfd --> fifo%u: %ld Bytes\n"RESET, 
                buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19], i, wrt);
            return;
        }
    }
    printf(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"No Such client, pass it\n"RESET);
}

void MANAGER_recv_mqfd(int mqfd) {
    uint8_t buffer[BUFFERSIZE];
    long bytes;
    bytes = mq_receive(mqfd, buffer, BUFFERSIZE, NULL);
    if(bytes < 0) {
        printf(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Failed to read from msg queue\n"RESET);
        return;
    }
    if((buffer[0]&0xf0) != 0x40) {
        printf(TUN_MAGENTA"[TunManager]: Got a Non IPv4 packet from msg queue, pass it\n"RESET);
        return;
    }
    uint32_t dstip;
    *((uint8_t *)&dstip+3) = buffer[16];
    *((uint8_t *)&dstip+2) = buffer[17];
    *((uint8_t *)&dstip+1) = buffer[18];
    *((uint8_t *)&dstip) = buffer[19];
    uint32_t intraip, intranetid, intrahostid, intramask, intramaxclients;
    PUB_netstrparse(intranet, &intraip, &intranetid, &intrahostid, &intramask, &intramaxclients);
    if((dstip&intramask)==intranetid || (dstip&tunmask)==tunnetid) {
        long wrt = write(tunfd, buffer, bytes);
        if(wrt < 0) {
            perror(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Failed to write to tunfd"RESET);
            return;
        }
        printf(TUN_MAGENTA"[TunManager]: Transmitted packet(%hhu.%hhu.%hhu.%hhu --> %hhu.%hhu.%hhu.%hhu) mqueue --> tunfd: %ld Bytes\n"RESET, 
            buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19], wrt);
    } else {
        printf(TUN_MAGENTA"[TunManager]: "WARN_YELLOW"Its dst ip is not in consideration, pass it\n"RESET);
    }
}

SSL_CTX *MAIN_create_sslctx() {
    SSL_library_init();             // 初始化SSL库
    SSL_load_error_strings();       // 加载错误信息
    OpenSSL_add_all_algorithms();   // 加载所有算法
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if(!ctx) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to create ssl ctx\n"RESET);
        return NULL;
    }
    if (SSL_CTX_use_certificate_file(ctx, MYCERT, SSL_FILETYPE_PEM) <= 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to set server cert file\n"RESET);
        SSL_CTX_free(ctx);
        return NULL;
    }
    // 设置客户端私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, MYKEY, SSL_FILETYPE_PEM) <= 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to set server private key file\n"RESET);
        SSL_CTX_free(ctx);
        return NULL;
    }
    // 验证私钥是否与证书匹配
    if (!SSL_CTX_check_private_key(ctx)) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Server's private key not peer with cert\n"RESET);
        SSL_CTX_free(ctx);
        return NULL;
    }
    // 设置CA证书用于验证服务器证书
    if (SSL_CTX_load_verify_locations(ctx, CACERT, NULL) != 1) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to load CA cert file\n"RESET);
        SSL_CTX_free(ctx);
        return NULL;
    }
    // 设置验证模式：验证服务器证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, SESSION_verify_callback);
    // 设置验证深度
    SSL_CTX_set_verify_depth(ctx, 4);
    return ctx;
}

int MAIN_setupsocket(uint16_t port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if(socket < 0) {
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to create stream socket\n"RESET);
        return -1;
    }
    int opt = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sockfd);
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to setsockopt\n"RESET);
        return -1;
    }
    struct sockaddr_in srvaddr;
    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr.s_addr = INADDR_ANY;
    srvaddr.sin_port = htons(port);
    if(bind(sockfd, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) < 0) {
        close(sockfd);
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to bind\n"RESET);
        return -1;
    }
    if(listen(sockfd, 20) < 0) {
        close(sockfd);
        printf(MAIN_GREEN"[MAIN]: "ERROR_RED"Failed to listen\n"RESET);
        return -1;
    }
    return sockfd;
}

void HandleSession(SSL_CTX *ctx, uint32_t assign_hostid, int client_sockfd) {
    char fifofilename[32];
    sprintf(fifofilename, "./fifodir/fifo%u", assign_hostid);
    int fifo_read = open(fifofilename, O_RDONLY);
    if(fifo_read == -1) {
        perror(SESSION_CYAN"[Session]: "ERROR_RED"Failed to open fifo read"RESET);
        close(client_sockfd);
        exit(0);
    }
    int mqfd = mq_open(MSGQUE, O_WRONLY, 0644, NULL);
    if(mqfd == -1) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Failed to open msg queue\n"RESET, assign_hostid);
        close(fifo_read);
        close(client_sockfd);
        exit(0);
    }
    int epoll_fd = epoll_create1(0);
    if(epoll_fd == -1) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Failed to create epoll fd\n"RESET, assign_hostid);
        close(mqfd);
        close(fifo_read);
        close(client_sockfd);
        exit(0);
    }
    printf(SESSION_CYAN"[Session:%2u]: Opened fifo read (fd=%d), opened mqueue (fd=%d), created epoll (fd=%d)\n"RESET, assign_hostid, fifo_read, mqfd, epoll_fd);
    char procname[24];
    sprintf(procname, "[Session:%2u]", assign_hostid);
    PUB_add_to_epoll(SESSION_CYAN, procname, epoll_fd, fifo_read, EPOLLIN, "FIFO_READ_TunManager");
    PUB_add_to_epoll(SESSION_CYAN, procname, epoll_fd, client_sockfd, EPOLLIN, "Client_Sockfd");

    uint8_t buffer[BUFFERSIZE];
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sockfd);
    if(SSL_accept(ssl) <= 0) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"SSL shaking failed\n"RESET, assign_hostid);
        goto clear;
    }
    printf(SESSION_CYAN"[Session:%2u]: SSL shaking successfully\n"RESET, assign_hostid);
    char user[128], pass[128];
    if(SSL_read(ssl, buffer, BUFFERSIZE)<0) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Get username failed\n"RESET, assign_hostid);
        goto clear;
    }
    strcpy(user, buffer);
    if(SSL_read(ssl, buffer, BUFFERSIZE)<0) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Get passwd failed\n"RESET, assign_hostid);
        goto clear;
    }
     strcpy(pass, buffer);
    uint8_t hashpass[65] = {0};
    SESSION_sha256(pass, strlen(pass), hashpass);
    printf(SESSION_CYAN"[Session:%2u]: Got request from user: %s, password: %s\n"RESET, assign_hostid, user, pass);
    char realhashpass[65];
    if(SESSION_sql_search(user, realhashpass) < 0) {
        SSL_write(ssl, "BAD", 4);
        goto clear;
    }
    if(strcmp(realhashpass, hashpass)) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Client's password is wrong\n"RESET, assign_hostid);
        SSL_write(ssl, "BAD", 4);
        goto clear;
    }
    SSL_write(ssl, "OK", 3);
    printf(SESSION_CYAN"[Session:%2u]: Client verify finished\n"RESET, assign_hostid);
    uint32_t alloc_ip = tunnetid+assign_hostid;
    SSL_write(ssl, &alloc_ip, sizeof(alloc_ip));
    SSL_write(ssl, &tunmask, sizeof(tunmask));
    SSL_write(ssl, intranet, strlen(intranet)+1);
    printf(SESSION_CYAN"[Session:%2u]: Sent configurations to Client:\n"RESET, assign_hostid);
    printf(SESSION_CYAN"    Client TUN IP    : %hhu.%hhu.%hhu.%hhu\n"RESET, *((uint8_t *)&alloc_ip+3), *((uint8_t *)&alloc_ip+2), *((uint8_t *)&alloc_ip+1), *((uint8_t *)&alloc_ip));
    printf(SESSION_CYAN"    Client TUN MASK  : %hhu.%hhu.%hhu.%hhu\n"RESET, *((uint8_t *)&tunmask+3), *((uint8_t *)&tunmask+2), *((uint8_t *)&tunmask+1), *((uint8_t *)&tunmask));
    printf(SESSION_CYAN"    Server INNER NET : %s\n\n"RESET, intranet);

    int nfds;
    struct epoll_event events[MAXEVENTS];
    while(1) {
        nfds = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
        if(nfds == -1) {
            if(errno == EINTR) {
                printf(SESSION_CYAN"[Session:%2u]: "WARN_YELLOW"Interpreted by Signal\n"RESET, assign_hostid);
                continue;
            }
            printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Error during epoll_wait\n"RESET, assign_hostid);
            break;
        }
        for(int i=0;i<nfds;i++) {
            int fd = events[i].data.fd;
            if(events[i].events & (EPOLLERR | EPOLLHUP)) {
                printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"File Descriptor %d error or hang up\n"RESET, assign_hostid, fd);
                goto clear;
            }
            if(events[i].events & EPOLLIN) {
                if(fd == fifo_read) {
                    if(SESSION_recv_managerfifo(fd, ssl, assign_hostid)<0) {
                        goto clear;
                    }
                } else if(fd == client_sockfd) {
                    if(SESSION_recv_client(ssl, mqfd, assign_hostid)<0) {
                        goto clear;
                    }
                }
            }
        }
    }
clear:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sockfd);
    close(fifo_read);
    close(mqfd);
    close(epoll_fd);
    exit(0);
}

int SESSION_sha256(const uint8_t *data, size_t data_len, uint8_t *hashstr) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    uint8_t hashbytes[32];
    if (EVP_DigestFinal_ex(ctx, hashbytes, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    char bytestr[3];
    for(int i=0;i<32;i++) {
        sprintf(bytestr, "%02hhx", hashbytes[i]);
        strcat(hashstr, bytestr);
    }
    EVP_MD_CTX_free(ctx);
    return 0;
}

int SESSION_recv_managerfifo(int fd, SSL *ssl, uint32_t assign_hostid) {
    uint8_t buffer[BUFFERSIZE];
    long fiford = read(fd, buffer, BUFFERSIZE);
    if(fiford < 0) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Failed to read from fifo\n", assign_hostid);
        return -1;
    }
    int sslwrt = SSL_write(ssl, buffer, fiford);
    if(sslwrt < 0) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Failed to write to ssl\n"RESET, assign_hostid);
        return -1;
    }
    printf(SESSION_CYAN"[Session:%2u]: Transmitted packet(%hhu.%hhu.%hhu.%hhu --> %hhu.%hhu.%hhu.%hhu) fifo --> socket: %d Bytes\n"RESET,
        assign_hostid, buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19], sslwrt);
    return 0;
}

int SESSION_recv_client(SSL *ssl, int mqfd, uint32_t assign_hostid) {
    uint8_t buffer[BUFFERSIZE];
    int sslrd = SSL_read(ssl, buffer, BUFFERSIZE);
    if(sslrd < 0) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Failed to read from socket\n"RESET, assign_hostid);
        return -1;
    }
    int mqwrt = mq_send(mqfd, buffer, sslrd, 0);
    if(mqwrt < 0) {
        printf(SESSION_CYAN"[Session:%2u]: "ERROR_RED"Failed to write to msg queue\n"RESET, assign_hostid);
        return -1;
    }
    printf(SESSION_CYAN"[Session:%2u]: Transmitted packet(%hhu.%hhu.%hhu.%hhu --> %hhu.%hhu.%hhu.%hhu) socket --> mqueue: %d Bytes\n"RESET,
        assign_hostid, buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19], sslrd);
    return 0;
}

int SESSION_sql_search(char *user, char *sqlhash) {
    sqlite3 *db;
    int rc = sqlite3_open(SQLFILE, &db);
    if(rc != SQLITE_OK) {
        printf(ERROR_RED"[SqlSearch]: Failed to open database: %s\n"RESET, sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    char sql[256] = "select passhash from vpnclient where username='";
    strcat(sql, user);
    strcat(sql, "';");
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if(rc != SQLITE_OK) {
        printf(ERROR_RED"[SqlSearch]: Failed to prepare query language: %s\n"RESET, sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    if(sqlite3_step(stmt) != SQLITE_ROW) {
        printf(ERROR_RED"[SqlSearch]: The user %s not found\n"RESET, user);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    strcpy(sqlhash, sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int SESSION_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    if(depth == 0) {
        X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        printf(SESSION_CYAN"Client Cert Subject: %s\n"RESET, subject);
        char issuer[256];
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        printf(SESSION_CYAN"Client Cert Issuer: %s\n"RESET, issuer);
    }
    return preverify_ok;
}

void MAIN_sigchld_handler(int sig) {
    pid_t curpid = getpid();
    switch(sig) {
    case SIGINT:
        if(curpid != mainpid) {
            printf(SIG_BLUE"[SIGNAL]: Sub process got SIGINT: %d\n"RESET, curpid);
            exit(0);
        } else {
            printf(SIG_BLUE"[SIGNAL]: MAIN Got SIGINT\n"RESET);
            close(pipefd[1]);
            mq_unlink(MSGQUE);
            printf(SIG_BLUE"[SIGNAL]: Unlinked: %s\n"RESET, MSGQUE);
            char fifofilename[32];
            for(uint32_t i=1;i<maxclients;i++) {
                if(i!=tunhostid && clientlist[i].pid>0) {
                    sprintf(fifofilename, "./fifodir/fifo%u", i);
                    unlink(fifofilename);
                    printf(SIG_BLUE"[SIGNAL]: Unlinked: %s\n"RESET, fifofilename);
                }
            }
            exit(0);
        }
        break;
    case SIGCHLD:
        printf(SIG_BLUE"[SIGNAL]: MAIN Got SIGCHLD\n"RESET);
        int saved_errno = errno;
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            if (WIFEXITED(status)) {
                printf(SIG_BLUE"[SIGNAL]: Process %d exited with code: %d\n"RESET, pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf(SIG_BLUE"[SIGNAL]: Process %d terminated by signal: %d\n"RESET, pid, WTERMSIG(status));
            }
            if(pid == managerpid) {
                printf(SIG_BLUE"[SIGNAL]: It is TUNMANAGER EXITED, All process down\n"RESET);
                mq_unlink(MSGQUE);
                close(pipefd[1]);
                printf(SIG_BLUE"[SIGNAL]: Unlinked: %s\n"RESET, MSGQUE);
                char fifofilename[32];
                for(uint32_t i=0;i<maxclients;i++) {
                    if(i!=tunhostid && clientlist[i].pid>0) {
                        sprintf(fifofilename, "./fifodir/fifo%u", i);
                        unlink(fifofilename);
                        printf(SIG_BLUE"[SIGNAL]: Unlinked: %s\n"RESET, fifofilename);
                    }
                }
                exit(0);
            }
            char fifofilename[32];
            for(uint32_t i=1;i<maxclients;i++) {
                if(clientlist[i].pid==pid) {
                    clientlist[i].pid = -1;
                    write(pipefd[1], &clientlist[i], sizeof(struct clientinfo));
                    sprintf(fifofilename, "./fifodir/fifo%u", i);
                    unlink(fifofilename);
                    printf(SIG_BLUE"[SIGNAL]: Unlinked: %s\n"RESET, fifofilename);
                }
            }
        }
        errno = saved_errno;
        break;
    }
}

