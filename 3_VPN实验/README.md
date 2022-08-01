写在最前：本README并不全面，更详细的内容请直接查看“我的报告.docx”。

注意：我修改了代码、报告中涉及的域名的名字，但没有修改编译后的可执行程序文件。证书我已经删掉了，按照错误的域名重新生成的证书用不了。**必须重新编译代码并生成自己的证书**。

[TOC]

# 计算机网络安全实验三

【一些经验教训】

注意，在docker的`root@xxx`中，**加或者不加`sudo`是有很大区别的**，别看是root就不加`sudo`。

举例：运行`vpnclient`之后，在docker中希望用`kill`终止掉，不加`sudo`不行。如下图。

![](https://img2022.cnblogs.com/blog/2208802/202208/2208802-20220816135327216-245873214.png)

## VPN实验

虚拟专用网络（VPN）用于创建计算机通信的专用的通信域，或为专用网络 到不安全的网络（如 Internet）的安全扩展。VPN 是一种被广泛使用的安全技术。 在 IPSec 或 TLS/SSL（传输层安全性/安全套接字层）上构建 VPN 是两种根本不 同的方法。本实验中，我们重点关注基于 TLS/SSL 的 VPN。这种类型的 VPN 通 常被称为 TLS/SSL VPN。

实验要求：实现简单的 TLS/SSL VPN。

本次实验，学生需要为 Linux 操作系统实现一个简单的 VPN。我们将其称为 miniVPN。

### 配置环境

本实验在docker上完成，相当于建两个子网，然后使两个子网之间能够通过`TLS/SSL VPN`相互通信。

其中VPN服务器网关是虚拟机VM@seed。

配置完成后的拓扑图：

![](https://img2022.cnblogs.com/blog/2208802/202208/2208802-20220816135321858-1855504508.png)

配置过程：

```bash
# 外网的配置：
sudo docker network create --subnet=10.0.2.0/24 --gateway=10.0.2.8 --opt "com.docker.network.bridge.name"="docker1" extranet # 网卡名为docker1
sudo docker run -it --name=HostU0 --hostname=HostU0 --net=extranet --ip=10.0.2.4 --privileged "seedubuntu" /bin/bash
sudo docker run -it --name=HostU1 --hostname=HostU1 --net=extranet --ip=10.0.2.5 --privileged "seedubuntu" /bin/bash
sudo docker run -it --name=HostU2 --hostname=HostU2 --net=extranet --ip=10.0.2.6 --privileged "seedubuntu" /bin/bash
# 内网的配置：
sudo docker network create --subnet=192.168.60.0/24 --gateway=192.168.60.1 --opt "com.docker.network.bridge.name"="docker2" intranet # 网卡名为docker2
sudo docker run -it --name=HostV --hostname=HostV --net=intranet --ip=192.168.60.101 --privileged "seedubuntu" /bin/bash
# 开启ip转发、关闭防火墙：
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo iptables -F
# 删除所有docker（Host*）中的默认路由：
route del default
```

1. 创建网络extranet（外网）：

   ```bash
   sudo docker network create --subnet=10.0.2.0/24 --gateway=10.0.2.8 --opt "com.docker.network.bridge.name"="docker1" extranet # 网卡名为docker1
   ```

2. 创建网络intranet（内网）：

   ```bash
   sudo docker network create --subnet=192.168.60.0/24 --gateway=192.168.60.1 --opt "com.docker.network.bridge.name"="docker2" intranet # 网卡名为docker2
   ```

3. 创建并运行容器 HostU（外网主机，运行着VPN客户端）：

   ```bash
   sudo docker run -it --name=HostU --hostname=HostU --net=extranet --ip=10.0.2.7 --privileged "seedubuntu" /bin/bash
   ```

4. 新开一个终端。

5. 创建并运行容器 HostV（内网主机）：

   ```bash
   sudo docker run -it --name=HostV --hostname=HostV --net=intranet --ip=192.168.60.101 --privileged "seedubuntu" /bin/bash
   ```

6. 还需要在root@VM（注意是root）中开启ip转发的功能，开启后HostU和HostV可以相互ping通：

   ```bash
   echo 1 > /proc/sys/net/ipv4/ip_forward
   ```
   
7. 在容器 HostU 和 HostV 内，分别删掉默认路由（默认路由就是，无条件转发给网关的那条路由）：

   ```bash
   route -n # 查看当前路由
   root@HostU:/# route del default
   root@HostV:/# route del default
   ```

   删除默认路由之后，HostU和HostV将无法相互ping通。就可以用来做VPN实验了。

#### docker常用指令

打开或停止HostM：

```bash
sudo docker start/stop HostM
```

把HostM映射到bash中：

```bash
sudo docker exec -it HostM /bin/bash
```

查看当前docker有哪些：

```bash
sudo docker ps -a
```

关闭防火墙：

```bash
sudo iptables -F
```

主机和容器之间拷贝数据：

```bash
sudo docker cp 容器名称:路径 主机路径
sudo docker cp 主机路径 容器名称:路径
```

需要往docker中拷贝的内容（包括vpnclient可执行程序、cert_server/ca.crt），先全部放到client目录下：

```bash
mkdir -p client/cert_server/
cp vpnclient client/
cp cert_server/ca.crt client/cert_server/ca.crt
sudo docker start HostU0
sudo docker start HostU1
sudo docker start HostU2
sudo docker cp client/ HostU0:/
sudo docker cp client/ HostU1:/
sudo docker cp client/ HostU2:/
# 然后切换到docker中
sudo docker exec -it HostU0 /bin/bash
route del default
echo "10.0.2.8        chengziServer.com" >> /etc/hosts
sudo docker exec -it HostU1 /bin/bash
route del default
echo "10.0.2.8        chengziServer.com" >> /etc/hosts
sudo docker exec -it HostU2 /bin/bash
route del default
echo "10.0.2.8        chengziServer.com" >> /etc/hosts
# HostV必须要打开telnet服务，不然是不可能telnet成功的
sudo docker exec -it HostV /bin/bash
service openbsd-inetd start
```

修改Wireshark配置时，需要将Wireshark全屏，然后将鼠标在顶端悬浮，才能看到Edit按钮。

用openssl检查证书：

```bash
openssl x509 -noout -text -in cert_server/ca.crt
```

### 创建隧道

利用`TUN/TAP `技术，可以创建虚拟网络接口，TAP模拟以太网设备，TUN模拟网络层设备。

用户程序可以使用标准的read()和write()系统调用来接收或发送数据包到虚拟接口(如/dev/net/tun或/dev/net/tap)。

通过设备驱动，可以保证这些虚拟接口能够把报文上传给网关、从网关接收并发回内网机器。

#### 运行一下服务端和客户端程序

给出的程序在docker里不能编译，所以要编译好之后移进去。拷贝指令：

```bash
sudo docker cp vpnclient HostU:/vpnclient
```

在网关(seed@VM)里运行`vpnserver`：

> VPN服务器程序`vpnserver.c`：程序的`daemon(1,1)`意思是让程序后台运行，所以运行时bash不会卡在while死循环里，而是直接显示`Setup TUN interface success!`。
>
> 主要功能：打开/tun设备结点，创建了一个套接字，然后读取buff数据，发送给这个套接字。

```bash
sudo ./vpnserver
```

可以用netstat或者ps查看刚刚运行的进程的信息：

```bash
netstat -anp | grep vpn # 只能在root@VM中运行
ps -aux | grep vpn # 可以在seed@VM下运行
```

> 这里额外指出查看的指令，是因为该程序运行在后台。倘若对程序有所修改，需要先`kill 进程号` 终止之前运行的程序。
>
> 当然，也可以运行`killall vpnclient`这种指令来终止所有同名的运行程序。

为了避免麻烦，接下来我们在网关运行时，一律在root@VM而不是seed@VM。

网关添加接口：

```bash
ifconfig tun0 192.168.53.1/24 up
```

HostU运行客户端程序：

```bash
./vpnclient 10.0.2.8
```

客户端添加接口：

```bash
ifconfig tun0 192.168.53.5/24 up
```

到这一步时，网关那边显示的如下图所示：

![](https://img2022.cnblogs.com/blog/2208802/202208/2208802-20220816135321506-2045151917.png)

进入下一阶段。

#### 配置路由

HostU添加路由：

```bash
root@HostU:/# route add -net 192.168.60.0/24 tun0
```

> 意思；所有发给192.168.60.0/24的报文，都直接发给tun0虚拟接口。

添加后，尝试ping HostV，现象会发生变化，如下图所示：

![](https://img2022.cnblogs.com/blog/2208802/202208/2208802-20220816135321053-1674708268.png)

每次ping时，wireshark上能够截到UDP包。

可以将tcpdump用如下指令链接到HostV中，这样在HostV中查看报文会方便很多：

```bash
root@HostV:/# mv /usr/sbin/tcpdump /usr/bin/tcpdump
root@HostV:/# ln -s /usr/bin/tcpdump /usr/sbin/tcpdump
```

ping的时候，在HostV中的tcpdump能看到如下图所示的报文信息：

![](https://img2022.cnblogs.com/blog/2208802/202208/2208802-20220816135320445-1921882170.png)

所以可以推测出我们需要在HostV上建立的路由是`route add -net 192.168.53.0/24 gw 192.168.60.1 `，这个路由以192.168.60.1为网关。

> 意思；所有发给192.168.53.0/24的报文，都直接发给网关192.168.60.1（也就是docker2的网关）。这样，HostV这类报文就可以正常地接上外网了。
>
> 我觉得之前就不该删掉HostV的默认路由……

添加后，HostU ping HostV能ping通了。

#### tls

打开老师发的tls文件夹并解压，make编译。

`tlsserver`主要功能：

前期准备：初始化ssl，创建ssl的上下文，指定ssl的方法（如SSLv23是兼容的模式，server_method是服务器端的方法），设置一些本机的证书、私钥、认证的一些参数。

> SSL_CTX_new是通过方法创建一个上下文。然后就是设置认证的模式，SSL_VERIFY_PEER是对对端校验的，verify_callback是对校验过程中出现的错误之类的处理，SSL_VERIFY_NONE是不对对端校验。load_verify是直接load一个证书，就是用来设置一些本机的证书。

创建会话：通过SSL_new创建一个会话句柄。ssl是基于tcp套接字通信的，所以要创建套接字。服务器收到连接请求的时候就建立一个套接字。

建立套接字后，先用SSL_connect和SSL_accept做一些SSL的协商，比如加密套件的协商、证书的传递和校验等等。

`tlsclient`基本功能：

就是连接，然后到加密管道里读写数据，其他的和server挺像的。

传输文件：

```bash
tar czvfp tls.tgz tls # 打包
sudo docker cp tls.tgz HostU:/tls.tgz # 拷贝
```

解压：

```bash
tar xzvfp tls.tgz
```

服务器端运行：

```bash
./tlsserver & # &是强制后台运行 
```

默认在4433端口，可用`netcat -antp | grep tls`查看。

HostU运行：

```bash
./tlsclient 10.0.2.8 4433
# 输入密码123456
```

交互如下：

![](https://img2022.cnblogs.com/blog/2208802/202208/2208802-20220816135319958-613697380.png)



**自己做的程序不应该让用户手动设置tun接口。**

**之后密码要修改成自己的。**



要求整合vpn和tls程序，合成一个有加密的vpn程序。

证书有效期的检查，在客户端可以调用load_verify_location指定CA证书和路径。

SSL_CTX_set_verify 指定证书验证方式，打开的话就需要验证对才可以访问。

对客户端认证不是ssl中必须的。

客户端对服务端的认证是必须的。**客户端认证，一般是以用户口令的方式，在指导书5.4节**。



vpn系统。

应该支持多客户端。服务器需要多进程或多线程，支持并发登录。数据包的虚拟IP用来区分客户端，是看不到用户名之类的。

多客户端的系统，虚拟IP怎么用来关联用户和套接字，这需要设计一些机制，比如建立一些结构数组(指导手册有提示)。



最后检查的程序只有一个客户端、一个服务端。



注意保存截包数据(之后做系统再截吧)。

