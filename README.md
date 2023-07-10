# lfrp
Lfrp is light fast reverse proxy that allows you to expose a local server located behind a NAT or firewall to the Internet. 

It's just a backup of frp, when Win10/Win11 intercept frp (so I can't connect to my work virtual machine without administrator privileges during meetings).

Otherwise， this is so simple that it's easy to use for students to learn.

Roadmap：
  1. Add AES， because some company will scan network stream；
  2. Build for Linux， because most people may want use linux TunSvr.

学习说明：
  1. 使用lfrp.sln可以直接编译出lfrpCli、lfrpTun、lfrpSvr、EchoServer、EchoClient，Debug模式可以全部在本地运行，前四个启动没有顺序要求，最后再启动EchoClient即可调试。
  2. 具体调试代码，可以在每个子项目下打开分别打开5个sln，按第一步要求启动调试。

具体网络结构如下面图所示：

![Image text](https://github.com/frankfengfl/lfrp/blob/main/lfrp.png)
