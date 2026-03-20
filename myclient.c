#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <openssl/ssl.h>

#define CACERT "./keys/ca.crt"
#define MYCERT "./keys/client.crt"
#define MYKEY  "./keys/client.key"
#define BUFSIZE 2048
#define DEFAULT_SRVNAME "cp.com"
#define DEFAULT_SRVPORT 8888
#define DEFAULT_USER "hosta"
#define DEFAULT_PASS "hosta"
int is_set_name = 0;
struct termios old_term, new_term;

void disableEcho() {    // 关闭回显
    tcgetattr(STDIN_FILENO, &old_term);  // 保存原设置
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO | ICANON); // 关闭回显和规范模式
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
}
void restoreTerminal() {    // 恢复回显
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
}

void init_openssl();                    // 初始化SSL库
SSL_CTX *create_context();              // 创建SSL上下文环境
void configure_context(SSL_CTX *ctx);   // 配置上下文
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);    // 身份验证回调
int connect_to_server(const char *hostname, unsigned short port);    // 根据服务器主机名连接服务器并返回套接字
int tun_device_create(char *dev, char *ip, char *netmask);   // 创建配置tun
int tunselected(int tunfd, SSL *ssl);      // 将tun数据发到ssl
int socketselected(int tunfd, SSL *ssl);   // 将ssl数据发到tun
int addroute(char *dev, char *net);     // 添加路由

int main(int argc, char *argv[])
{
    char srvname[128];
    unsigned short port;
    if(argc == 1) {
        printf("INFO: DEFAULT CONNECT TO %s:%hu:\n", DEFAULT_SRVNAME, DEFAULT_SRVPORT);
        strcpy(srvname, DEFAULT_SRVNAME);
        port = DEFAULT_SRVPORT;
    } else if(argc==2 && strcmp(argv[1], "--help")==0) {
        printf("USAGE1: %s\n", argv[0]);
        printf("USAGE2: %s <SERVER NAME/IP> <PORT>", argv[0]);
        printf("DEFAULT ARGUMENTS: %s %s %hu\n", argv[0], DEFAULT_SRVNAME, DEFAULT_SRVPORT);
        return 1;
    } else if(argc == 3) {
        strcpy(srvname, argv[1]);
        sscanf(argv[2], "%hu", &port);
    } else {
        printf("INVALID ARGUMENTS\n");
        printf("Using --help for more information\n");
        return 1;
    }
    init_openssl();                     // 初始化ssl库
    SSL_CTX *ctx = create_context();    // 创建上下文环境
    configure_context(ctx);             // 配置上下文
    SSL *ssl = SSL_new(ctx);            // 创建ssl
    int sockfd = connect_to_server(srvname, port);    // 根据主机名连接服务器
    SSL_set_fd(ssl, sockfd);            // 绑定ssl和套接字
    if(is_set_name) {
        SSL_set1_host(ssl, srvname);        // 设置主机名
    }
    int ssl_err = SSL_connect(ssl);     // tls握手连接
    if(ssl_err<=0) {
        printf("ERROR: TLS shaking failed\n");
        exit(EXIT_FAILURE);
    }
    printf("INFO: TLS shaking finished successfully\n");
    
    unsigned char buffer[BUFSIZE];
    int bytes;
    
    // 客户端身份验证
    printf("INFO: Begin certify my account\n");
    char user[128], pass[128];
    printf("Username(Enter return to use default): ");
    fgets(user, 128, stdin);
    if(strlen(user)<127) user[strlen(user)-1] = 0;  // 吃掉换行
    printf("Password(Enter return to use default): ");
    disableEcho();
    fgets(pass, 128, stdin);
    restoreTerminal();
    if(strlen(pass)<127) pass[strlen(pass)-1] = 0;  // 吃掉换行
    if(strlen(user)==0) {
        printf("Using default username %s\n", DEFAULT_USER);
        strcpy(user, DEFAULT_USER);
    }
    if(strlen(pass)==0) {
        printf("Using default password: %s\n", DEFAULT_PASS);
        strcpy(pass, DEFAULT_PASS);
    }
    SSL_write(ssl, user, strlen(user)+1);
    SSL_write(ssl, pass, strlen(pass)+1);
    SSL_read(ssl, buffer, BUFSIZE);
    if(strcmp(buffer, "OK")) {
        printf("ERROR: Username or Password invalid\n");
        printf("    Connection refused by server\n");
        goto clean;
    }

    // 获取ip和掩码设置tun和目的网段
    char tunip[16], tunmask[16], tunnet[20];
    uint32_t ip, mask;
    SSL_read(ssl, buffer, BUFSIZE);
    memcpy(&ip, buffer, 4);
    SSL_read(ssl, buffer, BUFSIZE);
    memcpy(&mask, buffer, 4);
    SSL_read(ssl, buffer, BUFSIZE);
    strcpy(tunnet, buffer);
    sprintf(tunip, "%hhu.%hhu.%hhu.%hhu", *((uint8_t *)&ip+3), *((uint8_t *)&ip+2),*((uint8_t *)&ip+1), *((uint8_t *)&ip));
    sprintf(tunmask, "%hhu.%hhu.%hhu.%hhu", *((uint8_t *)&mask+3), *((uint8_t *)&mask+2),*((uint8_t *)&mask+1), *((uint8_t *)&mask));
    char tundevname[16];
    int tunfd = tun_device_create(tundevname, tunip, tunmask);
    if(tunfd < 0) {
        printf("ERROR: Failed to create TUN device\n");
        goto clean;
    }
    printf("INFO: Successfully create TUN device: %s\n", tundevname);
    if(addroute(tundevname, tunnet)) {
        printf("ERROR: Failed to add iproute via tun\n");
        goto clean;
    }
    printf("INFO: Successfully add route: %s via %s\n", tunnet, tundevname);

    // 设置监听的文件描述符集合
    fd_set readFDSet;
    while(1) {
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if(FD_ISSET(tunfd, &readFDSet)) {
            if(tunselected(tunfd, ssl) < 0) {
                printf("INFO: Server has exited\n");
                break;
            }
        }
        if(FD_ISSET(sockfd, &readFDSet)) {
            if(socketselected(tunfd, ssl) < 0) {
                printf("INFO: Server has exited\n");
                break;
            }
        }
    }
clean:
    SSL_shutdown(ssl);  // 关闭ssl连接
    SSL_free(ssl);      // 释放ssl资源
    SSL_CTX_free(ctx);  // 释放上下文
    OPENSSL_cleanup();  // 清理ssl资源
    close(sockfd);      // 关闭套接字
    printf("INFO: Client exit\n");
    return 0;
}

void init_openssl() {
    SSL_library_init();             // 初始化SSL库
    SSL_load_error_strings();       // 加载错误信息
    OpenSSL_add_all_algorithms();   // 加载所有算法
}

SSL_CTX *create_context() {
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(TLS_client_method()); // 使用客户端方法创建上下文
    if (!ctx) {
        printf("ERROR: Failed to create ssl ctx\n");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // 设置客户端证书
    if (SSL_CTX_use_certificate_file(ctx, MYCERT, SSL_FILETYPE_PEM) <= 0) {
        printf("ERROR: Failed to set client cert file\n");
        exit(EXIT_FAILURE);
    }
    // 设置客户端私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, MYKEY, SSL_FILETYPE_PEM) <= 0) {
        printf("ERROR: Failed to set client private key file\n");
        exit(EXIT_FAILURE);
    }
    // 验证私钥是否与证书匹配
    if (!SSL_CTX_check_private_key(ctx)) {
        printf("ERROR: Client's private key not peer with cert\n");
        exit(EXIT_FAILURE);
    }
    // 设置CA证书用于验证服务器证书
    if (SSL_CTX_load_verify_locations(ctx, CACERT, NULL) != 1) {
        printf("ERROR: Failed to load CA cert file\n");
        exit(EXIT_FAILURE);
    }
    // 设置验证模式：验证服务器证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    
    // 设置验证深度
    SSL_CTX_set_verify_depth(ctx, 4);
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    if(depth == 0) {
        X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
        char subject[256];
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        printf("Server Cert Subject: %s\n", subject);
        char issuer[256];
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        printf("Server Cert Issuer: %s\n", issuer);
    }
    if(!preverify_ok) {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        switch(err) {
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_CERT_HAS_EXPIRED:
            printf("ERROR: Server's cert is out of time\n");
            break;
        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        case X509_V_ERR_CERT_REVOKED:
            printf("ERROR: Failed to certify server's belonging\n");
            break;
        case X509_V_ERR_HOSTNAME_MISMATCH:
            printf("ERROR: Server's hostname is not right\n");
            break;
        }
        return 0;
    }
    return preverify_ok;
}

int connect_to_server(const char *hostname, unsigned short port) {
    char portstr[6] = {0};
    snprintf(portstr, 6, "%hu", port);
    // 设置地址解析提示
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;          // IPv4
    hints.ai_socktype = SOCK_STREAM;    // TCP套接字

    // 解析主机名和服务
    struct addrinfo *result;
    int ret = getaddrinfo(hostname, portstr, &hints, &result);
    if (ret != 0) {
        printf("ERROR: Failed to get addr info about %s\n", hostname);
        exit(EXIT_FAILURE);
    }
    // 连接返回结果中的第一个地址
    int sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (connect(sockfd, result->ai_addr, result->ai_addrlen) == -1) {
        printf("ERROR: Cannot connect to %s:%hu\n", hostname, port);
        exit(EXIT_FAILURE);
    }
    char ipstr[16] = {0};
    inet_ntop(AF_INET, &((struct sockaddr_in *)result->ai_addr)->sin_addr, ipstr, 16);
    if(strcmp(ipstr, hostname)!=0) {
        is_set_name = 1;
    }
    printf("INFO: Successfully connect to %s %s:%hu\n", hostname, ipstr, port);
    freeaddrinfo(result);
    return sockfd;
}

int tun_device_create(char *dev, char *ip, char *netmask) {
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";
    
    // 打开TUN设备文件
    if ((fd = open(clonedev, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN设备，无协议信息头
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }
    
    // 创建socket用于ioctl调用
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        return -1;
    }
    // 设置ip
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr.sin_addr);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR)");
        close(sockfd);
        return -1;
    }
    // 设置网络掩码
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, netmask, &addr.sin_addr);
    memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK)");
        close(sockfd);
        return -1;
    }
    // 激活接口
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        close(sockfd);
        return -1;
    }
    close(sockfd);
    // 复制实际的设备名称
    strcpy(dev, ifr.ifr_name);
    return fd;
}

int tunselected(int tunfd, SSL *ssl) {
    unsigned char buffer[BUFSIZE];
    memset(buffer, 0, BUFSIZE);
    long len = read(tunfd, buffer, BUFSIZE);
    if(len < 0) {
        printf("Failed to read from TUN\n");
        return -1;
    }
    if((buffer[0]&0xf0) != 0x40) {
        printf("Not IPv4, pass it\n");
        return 0;
    }
    int sslwrt = SSL_write(ssl, buffer, len);
    if(sslwrt <= 0) {
        printf("Write Failed to SSL; Maybe the Client has exited\n");
        return -1;
    }
    printf("Transmitted packet(%hhu.%hhu.%hhu.%hhu --> %hhu.%hhu.%hhu.%hhu) TUN --> Socket: %d Bytes\n",
        buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19], sslwrt);
    return 0;
}

int socketselected(int tunfd, SSL *ssl) {
    char buffer[BUFSIZE];
    memset(buffer, 0, BUFSIZE);
    int sslrd = SSL_read(ssl, buffer, BUFSIZE);
    if(sslrd <= 0) {
        printf("Read Failed from SSL; Maybe the Client has exited\n");
        return -1;
    }
    if((buffer[0]&0xf0) != 0x40) {
        printf("Not IPv4, pass it\n");
        return 0;
    }
    long len = write(tunfd, buffer, sslrd);
    if(len <= 0) {
        printf("Write Failed to TUN\n");
        return -1;
    }
    printf("Transmitted packet(%hhu.%hhu.%hhu.%hhu --> %hhu.%hhu.%hhu.%hhu) Socket --> TUN: %ld Bytes\n",
        buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19], len);
    return 0;
}

int addroute(char *dev, char *net) {
    char cmd[100] = "ip route add ";
    strcat(cmd, net);
    strcat(cmd, " dev ");
    strcat(cmd, dev);
    int ret = system(cmd);
    printf("system ret= %d\n", ret);
    return ret;
}

