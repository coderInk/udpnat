  
 
 # **udpnat 用UDP实现NAT穿透,p2p聊天系统**
  
  &ensp;&ensp;用UDP实现的NAT穿透，一个简单的p2p聊天系统, 理论上来说, 只要不是Port Restricted Cone NAT与Symmetric NAT , Symmetric NAT与Symmetric NAT. 这两种类型组合之间打洞,都可以使用．这两种类型参考其他方案．
(默认只有一个网卡，一个ip的情况)

## 原理
### NAT分类
#### **Full Cone NAT**:  
&ensp;&ensp;&ensp;&ensp;内网主机建立一个UDP socket(LocalIP:LocalPort) 第一次使用这个socket给外部主机发送数据时NAT会给其分配一个公网(PublicIP,PublicPort),以后用这个socket向外面**任何主机**发送数据都将使用这对(PublicIP,PublicPort)。此外**任何外部主机**只要知道这个(PublicIP,PublicPort)就可以发送数据给(PublicIP,PublicPort)，内网的主机就能收到这个数据包

#### **Restricted Cone NAT**: 
&ensp;&ensp;&ensp;&ensp;内网主机建立一个UDP socket(LocalIP,LocalPort) 第一次使用这个socket给外部主机发送数据时NAT会给其分配一个公网(PublicIP,PublicPort),以后用这个socket向外面**任何主机**发送数据都将使用这对(PublicIP,PublicPort)。此外，如果任何外部主机想要发送数据给这个内网主机，只要知道这个(PublicIP,PublicPort)并且内网主机之前用这个**socket曾向这个外部主机IP发送过数据**。只要满足这两个条件，这个外部主机就可以用自己的(**IP,任何端口**)发送数据给(PublicIP,PublicPort)，内网的主机就能收到这个数据包 

#### **Port Restricted Cone NAT**:

&ensp;&ensp;&ensp;&ensp;内网主机建立一个UDP socket(LocalIP,LocalPort) 第一次使用这个socket给外部主机发送数据时NAT会给其分配一个公网(PublicIP,PublicPort),以后用这个socket向外面**任何主机**发送数据都将使用这对(PublicIP,PublicPort)。此外，如果任何外部主机想要发送数据给这个内网主机，只要知道这个(PublicIP,PublicPort)并且内网主机之前用这个**socket曾向这个外部主机(IP,Port)发送过数据**。只要满足这两个条件，这个外部主机就可以用自己的(**IP,Port**)发送数据给(PublicIP,PublicPort)，内网的主机就能收到这个数据包 

#### **Symmetric NAT**: 
&ensp;&ensp;&ensp;&ensp;内网主机建立一个UDP socket(LocalIP,LocalPort),当用这个socket第一次发数据给外部主机1时,NAT为其映射一个(PublicIP-1,Port-1),以后内网主机发送给外部主机1的所有数据都是用这个(PublicIP-1,Port-1)，如果内网主机同时用这个socket给外部主机2发送数据，第一次发送时，NAT会为其分配一个(PublicIP-2,Port-2), 以后内网主机发送给外部主机2的所有数据都是用这个(PublicIP-2,Port-2).如果NAT有多于一个公网IP，则PublicIP-1和PublicIP-2可能不同，如果NAT只有一个公网IP,则Port-1和Port-2肯定不同，也就是说一定不能是PublicIP-1等于 PublicIP-2且Port-1等于Port-2。此外，如果任何外部主机想要发送数据给这个内网主机，那么它首先应该收到内网主机发给他的数据，然后才能往回发送，否则即使他知道内网主机的一个(PublicIP,Port)也不能发送数据给内网主机，这种NAT实现UDP-P2P通信比较困难，可以通过先给对端发送消息，再给发服务器发送消息，猜测端口。


### 思路

&ensp;&ensp;&ensp;&ensp;既然已经知道了各种NAT类型的特点了, 也就可以知道,那三个cone类型的NAT, 同一个socket向外部的任何主机通信, NAT都会为它映射同一个端口,在外部主机看来, 就好像有固定的IP和端口一样.

&ensp;&ensp;&ensp;&ensp;即然对外面所有主机来说, 它的IP和端口一样, 那么我们做NAT穿透是不是就差最后一步了, 如何知道对方的IP和端口.

&ensp;&ensp;&ensp;&ensp;答案就是辅助服务器. 搭建一个服务器, 它有固定的外网IP和端口. 可以让所有的客户端都能连接它. 这样, 这个服务器就能知道所有连入它的客户端的外网IP和端口号了.

&ensp;&ensp;&ensp;&ensp;到这里思路就清楚了:

&ensp;&ensp;&ensp;&ensp;所有客户端都去连接辅助服务器,服务器就知道了所有客户端的外网ip和端口, 客户端再向服务器请求要穿透的目标客户端, 服务器就可以返回其目标的外网IP和端口, 同时通知目标客户端要被P2P连接并发送要连接它的另一个客户端的IP和端口. 这时双方都知道对方IP和端口,P2P就能顺利进行了.


&ensp;&ensp;&ensp;&ensp;, 需要唯一标识符表明需要哪个客户端的IP和端口. 这里就可以有很多设计方案了, 比如事先两个客户端之间就协定好了这个标识符, 比如一个友好的唯一用户名.


### 代码实现流程

![image](https://github.com/coderInk/udpnat/blob/master/udpHole.png)

 1. 加入p2p系统的节点向服务器发送注册消息，服务器记录加入节点的用户名与经过NAT设备后的ip与port.
 2. Client A向用户名B发送消息，则先找到用户名B的经过NAT后的ip和port，判断与对端是否已经打洞．
 3. 如果没打洞则发送握手消息给Client B，如果在一个局域网则B收到握手消息后回复ACK;如果不在同一个局域网则等待ACK超时，发送握手消息给服务器，服务器转发消息给Client B.
 4. Client B收到握手消息后回复ACK给Client A,由于CLIent A先给Client B发送握手消息，则Client A的NAT设备记录了Client B的信息，当Client使用相同的端口回复消息时，能透过NAT A到达A．
 5. 由于Client　B给Client A发送了消息，则Client B的NAT设备也记录下了Client A的经过NAT　A后的ip和port，则Client A也可以给Client B发送消息．


### 聊天系统使用
**服务端**

./server --ip serverIp --port serverPort  

//ip后带服务器ip,port后带服务器监听端口，默认ip为0.0.0.0,端口为8848

**客户端**

 ./client  --sip serverIp --sport serverPort --cip clientIp --cport clientPort
 
 //sip后带服务器ip地址，sport后带服务器监听端口，cip为本客户端ip地址，--cport本客户端监听端口，默认服务器ip:port为(0.0.0.0:8848),默认客户端ip:port(0.0.0.0:8900)


 
