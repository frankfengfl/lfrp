# What is lfrp?
Lfrp is light fast reverse proxy that allows you to expose a local server located behind a NAT or firewall to the Internet. All data stream bytes on the Internet are encrypted, even without any clear text header or fixed byte header.

# Goal
1. It's just a backup of frp, and only used when windows defender intercepts frp (I can't connect to my non-administrative office virtual machine while I'm in a boring meeting).
2. It is very simple and can be used to help students learn network data flow.

# Roadmap
   1. epoll & iocp? The select model is enough for individual users, but for learning purposes, this can be added later.
   2. performance optimization: memory pool, switch AES library...

# Manual
1. lfrpTun -p ListenPort -k AESKey
2. lfrpSvr -th lfrpTun_ip -tp lfrpTun_port -sh BusinessServer_ip -sp BusinessServer_port -k AESKey
3. lfrpCli -th lfrpTun_ip -tp lfrpTun_port -sp LocalListen_port -k AESKey

# Example Usage
Compare the architecture diagram below，when: 
1. EchoServer is 10.0.0.168:3389 on the company network,
2. lfrpSvr is 10.0.0.100 on the company network,
3. lfrpTun is 111.111.111.111 on the Internet,
4. lfrpCli is 192.168.68.100 on home LAN,
5. EchoClient is 192.168.68.101 on home LAN.

The startup commands of all programs are as follows：
1. lfrpSvr -th 111.111.111.111 -tp 12300 -sh 10.0.0.168 -sp 3389
2. lfrpTun -p 12300
3. lfrpCli -th 111.111.111.111 -tp 12300 -sp 12345
4. the EchoClient connect 192.168.68.100:12345 to use the service such as remote desktop.

# Architecture:

![Image text](https://github.com/frankfengfl/lfrp/blob/main/lfrp.png)

# 学习说明：
## Windows调试: 
1. 使用lfrp.sln可以直接编译出lfrpCli、lfrpTun、lfrpSvr、EchoServer、EchoClient；
2. Debug模式build后，可以直接在./x64/Debug目录下双击5个exe程序启动（无需参数），前四个没有启动顺序要求，只要最后启动EchoClient即可；
3. 需要具体调试代码，可以在每个子项目下分别打开5个sln，或者只打开自己需要调试的子项目，直接Debug运行即可（无需参数）。
4. 如果没有安装VS2022，低版本VS修改project属性里的平台工具集即可，比如VS2019改成v142.

## Linux调试: 
1. cd到目录下make；
2. 直接运行./bin目录下的5个执行程序（无需参数），前四个没有启动顺序要求，只要最后启动EchoClient即可；
3. 具体调试代码，建议使用windows调试。
