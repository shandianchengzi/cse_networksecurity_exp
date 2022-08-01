#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <shadow.h>
#include <crypt.h> //client verify
#include <memory.h>
#include <pthread.h>

#define PORT_NUMBER 4433
#define BUFF_SIZE 2000

/* define HOME to be dir for key and cert files... */
#define HOME "./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF   HOME"server.crt"
#define KEYF    HOME"server.key"
#define CACERT  HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_RET(err,s)	if ((err)!=0) { perror(s); exit(3); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

struct sockaddr_in peerAddr;
pthread_mutex_t mutex_tun;
SSL_CTX* ctx;


// TLS协商的准备工作
SSL_CTX* initTLS() {
    SSL_METHOD *meth;
    SSL_CTX *ctx;

    // 第一步：初始化OpenSSL库
	// This step is no longer needed as of version 1.1.0.
    SSL_library_init();             //使用OpenSSL前的协议初始化工作 
    SSL_load_error_strings();       //加载错误处理机制，打印出一些方便阅读的调试信息
    SSLeay_add_ssl_algorithms();    // 添加SSL的加密/HASH算法

    // 第二步：SSL上下文初始化
    meth = (SSL_METHOD *)SSLv23_server_method(); //选择会话协议
    //创建会话协议
    ctx = SSL_CTX_new(meth);
    //CHK_RET(ctx,stderr);
     if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    //制定证书验证方式
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

    // 第三步：设置服务器证书和私钥
    // 为SSL会话加载用户证书
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    // 为SSL会话加载用户私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    // 验证私钥和证书是否相符
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    } else {
        printf("Private key match the certificate public key\n");
    }
    
	return ctx;
}

// 初始化TCP服务端
int initTCPServer()
{
	struct sockaddr_in sa_server;
	int listen_sock;

	// 创建监听套接字
	listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(listen_sock, "socket");
	// 设置套接字信息，包括协议、地址、端口
	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(PORT_NUMBER);
	// 绑定套接字和套接字信息
	int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));
	CHK_ERR(err, "bind");
	//监听套接字，设置等待连接队列的最大长度为5
	err = listen(listen_sock, 5);
	CHK_ERR(err, "listen");
	
	return listen_sock;
}

// 用户登录函数
int userLogin(char *user, char *passwd) {
	//shadow文件的结构体 
	struct spwd *pw = getspnam(user);    //从shadow文件中获取给定用户的帐户信息
	if (pw == NULL) return -1;	// 没有该用户则返回-1

	printf("Login name: %s\n", user); //用户登录名
	
	// 将输入加密，与shadow文件的密码对比验证密码
	char *epasswd = crypt(passwd, pw->sp_pwdp);
	if (strcmp(epasswd, pw->sp_pwdp)) {
		return -1;
	}
	return 1;
}

// 创建虚拟网卡设备/dev/net/tun，并将虚拟IP用参数传回去
int createTunDevice(int sockfd, int* virtualIP)
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	// IFF_TUN:表示创建一个TUN设备；IFF_NO_PI:表示不包含包头信息
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	// 系统会自动找tun设备号，为避免客户端打开同一个设备，加互斥锁
	pthread_mutex_lock(&mutex_tun);
	tunfd = open("/dev/net/tun", O_RDWR);
	pthread_mutex_unlock(&mutex_tun);
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	
	// 设置设备的结构
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	// 获得当前虚拟设备编号
	int tunId = atoi(ifr.ifr_name+3); // 取设备名的tunxx的xx，转换成数字
	if(tunId == 127){
    printf("[Error] VPN客户端数量已经超过了最大值，本服务端无法承受更多的客户端。");
    return -1;
	}
	
	char cmd[60];
	// 自动为服务器的虚拟网卡设备分配虚拟IP
	sprintf(cmd, "sudo ifconfig tun%d 192.168.53.%d/24 up", tunId, tunId+1);
	system(cmd);
	// 给客户端TUN接口分配虚拟IP号
	*virtualIP = tunId + 127;  
	// 自动为服务器创建路由
	sprintf(cmd, "sudo route add -host 192.168.53.%d tun%d", tunId+127, tunId);
	system(cmd);
	
	printf("[tunfd %3d] Setup tun%d interface for sockfd %d\n", tunfd, tunId, sockfd);
	return tunfd;
}

// 向TLS隧道发送数据
void tunSelected(int tunfd, SSL* ssl)
{
	int len;
	char buff[BUFF_SIZE];

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	buff[len] = '\0';
	
	printf("[tunfd %3d] len %4d, Got a packet from TUN\n", tunfd, len);
	
	// 将数据写入套接字中
	SSL_write(ssl, buff, len);
}

// 从TLS隧道接收数据，注意长度为0时隧道关闭，要停止线程
int socketSelected(int tunfd, SSL* ssl)
{
	int len;
	char buff[BUFF_SIZE];

	bzero(buff, BUFF_SIZE);
	// 从套接字中读取数据
	len = SSL_read(ssl, buff, BUFF_SIZE - 1);
	
	printf("[tunfd %3d] len %4d, Got a packet from the tunnel\n", tunfd, len);
	if(len == 0) {    // 监测隧道关闭
    return 1;
  }
  buff[len] = '\0';
	
	//将数据写入TUN设备
	write(tunfd, buff, len);
	return 0;
}

//客户端验证
int verifyClient(SSL *ssl) {
    //获取用户名和密码
	char iptNameMsg[]="Please input username: ";
    SSL_write(ssl, iptNameMsg, strlen(iptNameMsg)+1);
    char username[BUFF_SIZE];
    int len = SSL_read(ssl, username, BUFF_SIZE);

    char iptPasswdMsg[]="Please input password: ";
    SSL_write(ssl, iptPasswdMsg, strlen(iptPasswdMsg)+1);
    char passwd[BUFF_SIZE];
    len = SSL_read(ssl, passwd, BUFF_SIZE);

    int r = userLogin(username, passwd);
    if(r != 1){
        char no[] = "Client verify failed";
		printf("%s\n",no);
        SSL_write(ssl, no, strlen(no)+1);
		return -1; 
	}
    char yes[] = "Client verify succeed";
    printf("%s\n",yes);
    SSL_write(ssl, yes, strlen(yes)+1);
    return 1;
}


// 客户端线程处理函数
void *threadClient(void *sockfdArg){
	int tunfd, sockfd, virtualIP;

	sockfd = (int)sockfdArg; // 传入的参数是Server新建的TCP Socket

	/*----------------TLS 协商---------------------*/
    SSL* ssl = SSL_new(ctx);    // 新建SSL套接字
    SSL_set_fd(ssl, sockfd);    // 令TCP套接字与SSL套接字绑定
    int err = SSL_accept(ssl);  // 使用SSL_accept完成连接握手
    if(err <= 0) {
        printf("[Error] SSL_accept 运行失败!\n");
        close(sockfd);
        return NULL;
    }

    printf("SSL connection established!\n");
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    /*-----要求客户端认证-----*/
    if (verifyClient(ssl) != 1) {
        //验证失败时关闭ssl连接
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        return NULL;   //子进程返回
    }

  /* -----创建TUN设备，并分配虚拟IP号----- */
	tunfd = createTunDevice(sockfd, &virtualIP);
	if(tunfd == -1) exit(-1);
	
	/* -----向客户端发送虚IP号----- */
	char buf[10];
	sprintf(buf,"%d",virtualIP);
	SSL_write(ssl,buf,strlen(buf)+1);

  /* -----使用select进行 IO多路复用 监听套接字和虚拟设备----- */
	while (1) {
		fd_set readFDSet;           // 读文件描述符集

		FD_ZERO(&readFDSet);        // 将文件描述符集清空
		FD_SET(sockfd, &readFDSet); // 将套接字句柄加入集合
		FD_SET(tunfd, &readFDSet);  // 将设备句柄加入集合
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		// 监听到Tun设备就绪时，向VPN隧道发送数据
		if (FD_ISSET(tunfd, &readFDSet))
			tunSelected(tunfd, ssl);
		// 监听到套接字设备就绪时，从VPN隧道接收数据
		if (FD_ISSET(sockfd, &readFDSet)){
      if(socketSelected(tunfd, ssl)==1){
        printf("[tunfd %3d] VPN Client Closed\n", tunfd);
        return NULL;
      }
		}
	}
	
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sockfd);
	return NULL;
}

int main(int argc, char *argv[])
{
	
	/*-----TLS 初始化-----*/
	ctx = initTLS(); 

	/*-----初始化TCP服务端套接字-----*/
	int listenSock = initTCPServer();
	
	while (1) {
    /* -----等待收到客户端的TCP连接----- */
    struct sockaddr_in clientAddr;
    size_t clientAddrLen = sizeof(struct sockaddr_in);
    int sockfd = accept(listenSock, (struct sockaddr *)&clientAddr, &clientAddrLen);
    CHK_ERR(sockfd, "accept");
    
    printf("Connection from IP:%s port:%d, sockfd: %d\n",
    inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port, sockfd);
    
    /* -----启动客户端线程----- */
    pthread_t tid;
    int ret = pthread_create(&tid, NULL, threadClient, (void*)sockfd);
	if (ret != 0) {close(sockfd);}
	CHK_RET(ret, "pthread 启动失败");
  }
	
}
