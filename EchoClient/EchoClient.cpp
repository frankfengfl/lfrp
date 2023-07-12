// EchoClient.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <string>

#pragma comment(lib, "ws2_32")

std::string ip = "127.0.0.1";
int nPort = 12345;

static SOCKET sClient;
#define CLENT_NUM 1
static SOCKET sSever, sSever_c[CLENT_NUM];
struct sockaddr_in sSever_c_sd[CLENT_NUM];

#define MAX_SEND_SIZE   512
#define BUFFER_SIZE     MAX_SEND_SIZE+1

#define USER_ERROR -1

int tcp_client_init(const char* ip, int iPort)
{
    struct sockaddr_in ser; //服务器端地址
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("Failed to load Winsock.\n"); //Winsock 初始化错误
        return -1;
    }
    ser.sin_family = AF_INET;                        //初始化服务器地址信息
    ser.sin_port = htons(iPort);                     //端口转换为网络字节序
    ser.sin_addr.s_addr = inet_addr(ip); //IP 地址转换为网络字节序
    sClient = socket(AF_INET, SOCK_STREAM, 0);       //创建客户端流式套接字
    if (sClient == INVALID_SOCKET)
    {
        printf("socket() Failed: %d\n", WSAGetLastError());
        return -1;
    }
    //请求与服务器端建立 TCP 连接
    if (connect(sClient, (struct sockaddr*)&ser, sizeof(ser)) == INVALID_SOCKET)
    {
        printf("connect() Failed: %d\n", WSAGetLastError());
        return -1;
    }
    printf("connect ok\n");

    return 0;
}

int tcp_client_send(unsigned char* buff, int len)
{
    int nRet = send(sClient, (const char*)buff, len, 0);
    if (nRet <= 0)
    {
        printf("send Failed: %d\n", WSAGetLastError());
    }
    return 0;
}

int tcp_client_rcv(unsigned char* buff, int* len)
{
    int iLen; //从服务器端接收的数据长度

    iLen = recv(sClient, (char*)buff, MAX_SEND_SIZE, 0); //从服务器端接收数据
    if (iLen == 0)
        return -1;
    else if (iLen == SOCKET_ERROR)
    {
        printf("recv() Failed: %d\n", WSAGetLastError());
        return -1;
    }
    //else
    //    printf("recv() data from server: %s\n", buff); // 输出接收数据
    *len = iLen;

    return iLen;
}

int close_tcp_client()
{
    closesocket(sClient); //关闭 socket
    WSACleanup();
    return 0;
}


int tcp_client_test()
{
    unsigned char buff[BUFFER_SIZE] = { 0 };
    int rcv_len;

    tcp_client_init(ip.c_str(), nPort);
    int nCount = 10;
    srand((unsigned int)time(0));
    while (nCount > 0)
    {
        std::string str = "test";
        int nSize = rand() % MAX_SEND_SIZE;
        for (size_t i = 0; i < nSize; i++)
        {
            //char c = (rand() % 26) + 'a';
            char c = (i % 26) + 'a';
            str += c;
        }
        
        printf("send:%s\n", str.c_str());
        tcp_client_send((unsigned char*)str.c_str(), str.length());
        memset(buff, 0, BUFFER_SIZE);
        rcv_len = tcp_client_rcv(buff, &rcv_len);
        if (rcv_len > 0)
        {
            if (str.compare((char*)buff) != 0)
            {
                printf("find error\n\n");
            }
            printf("rcv:%s\n", buff);
        }
            

        Sleep(1);
        nCount--;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    int i = 0;
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 && i + 1 <= argc)
        {
            i++;
            ip = argv[i];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 <= argc)
        {
            i++;
            nPort = atoi(argv[i]);
        }
    }

    tcp_client_test();
    return 0;
}
