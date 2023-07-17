// EchoServer.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#else
#include <sys/types.h>      
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

typedef int SOCKET;
typedef unsigned int DWORD;
typedef unsigned char BYTE;
#define FALSE 0 
#define SOCKET_ERROR (-1) 
#define INVALID_SOCKET (SOCKET)(~0)
#define NO_ERROR    0

int geterror() { return errno; }
#define WSAGetLastError() geterror()
#define closesocket close
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#define IP "127.0.0.1"
#define DEFAULT_PORT 10001
#define Print_ErrCode(e) fprintf(stderr,"\n[Server]%s 执行失败: %d\n",e,WSAGetLastError())
#define DEFAULT_BACKLOG 5
#define MAX_IO_PEND 10

int curr_size = 0; //当前的句柄数
#define OP_READ 0x10
#define OP_WRITE 0x20//定义结构体用于储存通信信息

#define MAX_SEND_SIZE   512
#define BUFFER_SIZE     MAX_SEND_SIZE+1

#ifdef _WIN32
#define LFRP_SEND_FLAGS     0
#else
#define LFRP_SEND_FLAGS     MSG_NOSIGNAL
#endif

int nPort = DEFAULT_PORT;
typedef struct _socklist
{
    SOCKET sock;
    DWORD Op;
    char name[100];
    char Buffer[BUFFER_SIZE];
    int  bufLen;
} Socklist; 

int main(int argc, char** argv)
{
    int i = 0;
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0 && i + 1 <= argc)
        {
            i++;
            nPort = atoi(argv[i]);
        }
    }

    int nStartup = 0;
    struct sockaddr_in clientService;
    SOCKET sockListen = INVALID_SOCKET;
    int nRet = 0;
#ifdef _WIN32
    WSADATA wsaData;
    if (0 != (nStartup = WSAStartup(MAKEWORD(2, 2), &wsaData)))
    {
        WSASetLastError(nStartup); //WSAStartup不会自动设置错误代码
        Print_ErrCode("WSAStartup()");
        return 1;
    }
#endif

    clientService.sin_family = AF_INET;
    //clientService.sin_addr.s_addr = inet_addr(IP);
    clientService.sin_addr.s_addr = htonl(INADDR_ANY);
    clientService.sin_port = htons(nPort);
    if (INVALID_SOCKET ==
        (sockListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))
        )
    {
        Print_ErrCode("socket()");
        return 1;
    }
#ifdef _WIN32
    u_long type = 1;
    ioctlsocket(sockListen, FIONBIO, &type);    
#else
    fcntl(sockListen, F_SETFL, O_NONBLOCK);
#endif
    if (SOCKET_ERROR == bind(sockListen,
        (sockaddr*)&clientService,
        sizeof(clientService)
    ))
    {
        Print_ErrCode("bind()");
        closesocket(sockListen);
        return 1;
    }    
    if (SOCKET_ERROR == listen(sockListen, DEFAULT_BACKLOG))
    {
        Print_ErrCode("listen()");
        closesocket(sockListen);
    }
    printf("[Server]监听 %s:%d\n", IP, nPort);    //存放所有的socket，包括用于accept的socket。
    Socklist sockList[10];
    Socklist sClientV[10];  // 访问服务的client
    //将监听socket设为socklist第一个元素
    curr_size = 0;    // 一个大循环，不断的接收客户端请求
    while (true)
    {
        //循环判断是否有请求需要处理
        fd_set fdRead, fdWrite;
        while (true)
        {
            FD_ZERO(&fdRead);
            FD_ZERO(&fdWrite);
            FD_SET(sockListen, &fdRead);
            SOCKET maxSock = sockListen;
            for (int i = 0; i < curr_size; i++)
            {
                //对需要send的客户端连接select
                if (sockList[i].Op == OP_WRITE)
                {
                    FD_SET(sockList[i].sock, &fdWrite);
                }
                //对所有的客户端连接select
                FD_SET(sockList[i].sock, &fdRead);
                maxSock = max(maxSock, sockList[i].sock);
            }
            //这个操作会被阻塞
#ifdef _WIN32
            nRet = select(0, &fdRead, &fdWrite, NULL, NULL);
#else
            nRet = select(maxSock + 1, &fdRead, &fdWrite, NULL, NULL);
#endif
            if (FD_ISSET(sockListen, &fdRead))
            {
                SOCKET sockNewClient = accept(sockListen, NULL, NULL);
                sockList[curr_size].sock = sockNewClient;
                sockList[curr_size++].Op = OP_READ;
                printf("[Server]accept sockeID:%d\n", sockNewClient);
                break;
            }
            //其他socket可用了，判断哪些能读，哪些能写
#ifdef _WIN32
            if (fdRead.fd_count > 0)
#endif
            {
                for (int i = 0; i < curr_size; i++)
                {
                    if (FD_ISSET(sockList[i].sock, &fdRead))
                    {
                        //开始recv
                        nRet = recv(sockList[i].sock, sockList[i].Buffer, MAX_SEND_SIZE, 0);
                        if (nRet == SOCKET_ERROR || nRet == 0)
                        {
                            closesocket(sockList[i].sock);
                            //移除sockList
                            for (int j = i; j < curr_size - 1; j++)
                            {
                                sockList[i].sock = sockList[i + 1].sock;
                            }
                            curr_size--;
                        }
                        else
                        {
                            sockList[i].Buffer[nRet] = '\0';
                            sockList[i].bufLen = nRet;
                            sockList[i].Op = OP_WRITE;
                            printf("[Server]接收到:%s\n", sockList[i].Buffer);
                        }
                    }
                }
            }
#ifdef _WIN32
            if (fdWrite.fd_count > 0)
#endif
            {
                for (int i = 0; i < curr_size; i++)
                {
                    if (FD_ISSET(sockList[i].sock, &fdWrite))
                    {
                        if (sockList[i].Op == OP_WRITE)
                        {
                            //开始send
                            nRet = send(sockList[i].sock, sockList[i].Buffer, sockList[i].bufLen, LFRP_SEND_FLAGS);
                            //事实上，这里可能会有nRet小于bufLen的情况
                            if (nRet == SOCKET_ERROR)
                            {
                                closesocket(sockList[i].sock);
                                //移除sockList
                                for (int j = i; j < curr_size - 1; j++)
                                {
                                    sockList[i].sock = sockList[i + 1].sock;
                                }
                                curr_size--;
                            }
                            else
                            {
                                sockList[i].Op = OP_READ;
                                printf("[Server]已发送:%d\n", nRet);
                            }
                        }
                    }
                }
            }
        }
    }
}