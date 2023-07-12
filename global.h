﻿#ifndef __GLOBAL_H
#define __GLOBAL_H

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include <winsock2.h>

/*******************************************************
* 1.本程序为专用AES，只用一个全局key加密
* 2.本程序一律采用fill模式，解包时自动按填充的折算
* 3.本程序跟lfrpTun相关的数据流完全加密，不留数据头，避免被检测头
********************************************************/
#define USE_AES

#define LOCAL_IP "127.0.0.1"
#define DEFAULT_BACKLOG 5
#define MAX_IO_PEND 10
#define OP_READ 0x10
#define OP_WRITE 0x20//定义结构体用于储存通信信息
#define MAGIC_NUMBER 0xFEEFFEEF
#define SEQ_CLIENT_BEG  10000
#define SEQ_SERVER_BEG  1000000

#define Print_ErrCode(e) fprintf(stderr,"\n[Server]%s 执行失败: %d\n",e,WSAGetLastError())
#define PRINT_ERROR printf
#ifdef _DEBUG
#define PRINT_INFO  printf
#else
#define PRINT_INFO 
#endif

enum SeqEnum
{
    SEQ_CLIENT = 0,
    SEQ_SERVER
};

enum PackTypeEnum
{
    PACK_TYPE_AUTH_SERVER = 1,  // 服务登录
    PACK_TYPE_AUTH_VISTOR,      // 访问者登录
    PACK_TYPE_DATA_BEG = 100,   // 数据包类型开始，区间包格式:MaginNum,type,len,SocketID
    PACK_TYPE_DATA,             // 数据包
    PACK_TYPE_DATA_END = 999,   // 数据包类型结束，用于分段结束，也用于业务结束
    PACK_TYPE_TUN_BEG = 1000,   // 通道之间的消息，不涉及业务
    PACK_TYPE_TUN_END = 1999,   // 通道之间的消息，不涉及业务；用于分段结束，也用于业务结束
    PACK_TYPE_UNKNOW = 10000,
};


#define ELEM_BUFFER_SIZE    1024*1024   // 增大内容避免不停new内存
#define RECV_BUFFER_SIZE    10*1024        // socket接受一次大小
#define BUFFER_SIZE 1024
#define PACK_SIZE_HEADER 12
#define PACK_SIZE_AUTH  20
#define PACK_SIZE_DATA_BEG  20
#define PACK_SIZE_DATA  20
#define PACK_SIZE_HEADER_MAX 20


struct CBuffer
{
    int nLen;
    char* pBuffer;
};
typedef std::vector<CBuffer> CVecBuffer;

class CLfrpSocket
{
public:
    CLfrpSocket()
    {
        InitMember();
    }

    ~CLfrpSocket()
    {
        ClearBuffer();
    }

    void InitMember()
    {
        sock = INVALID_SOCKET;
        Op = 0;
        nMagicNum = MAGIC_NUMBER;
        nType = PACK_TYPE_UNKNOW;
        nBufLen = 0;
        pBuffer = nullptr;
        nBufAlloc = 0;
        nPackLen = 0;
        nServerNumber = -1;
        nSocketID = INVALID_SOCKET;
        nPackSeq = 0;
        memset(Buffer, 0, ELEM_BUFFER_SIZE);
    }

    void ClearBuffer()
    {
        if (pBuffer)
        {
            delete[] pBuffer;
            pBuffer = nullptr;
            nBufAlloc = 0;
        }

#ifdef USE_AES
        if (pEncBuffer)
        {
            delete[] pEncBuffer;
            pEncBuffer = nullptr;
            nEncBufAlloc = 0;
        }
        nEncBufLen = 0;
        memset(EncBuffer, 0, ELEM_BUFFER_SIZE);
#endif

        Op = 0;
        nType = PACK_TYPE_UNKNOW;
        nBufLen = 0;
        nPackLen = 0;
        nServerNumber = -1;
        nSocketID = INVALID_SOCKET;
        nPackSeq = 0;
        memset(Buffer, 0, ELEM_BUFFER_SIZE);
    }

public:
    SOCKET sock;
    DWORD Op;
    int nMagicNum;
    int nServerNumber;          // 服务提供编号，用于区分Business侧提供的服务，认证包带
    int nSocketID;              // 业务客户端建立的SocketID，PACK_TYPE_DATA_BEG包带，通道Elem是临时存下
    int nPackSeq;               // 为每个SocketID连接

    // 接收数据相关
    int nBufLen;
    int nType;                  // 收到的包类型
    int nPackLen;               // 包含头部8个字节
    char Buffer[ELEM_BUFFER_SIZE]; //前12个字节放MagicNum、Type和nPackLen，可跟多个包
    char* pBuffer;            // 超过BUFFER_SIZE只用这个存
    int nBufAlloc;              // 分配的pBuffer大小

    //发送队列
    CVecBuffer vecSendBuf;

#ifdef USE_AES
    char EncBuffer[ELEM_BUFFER_SIZE];
    char* pEncBuffer;           // 收到的原始加密流
    int nEncBufLen;
    int nEncBufAlloc;
#endif
};

class CSocketPair
{
public:
    CSocketPair()
        :pServer(nullptr), pVistor(nullptr)
    {}
    CLfrpSocket* pServer;
    CLfrpSocket* pVistor;
};
typedef std::map<int, CSocketPair> CSocketPairMap;       // LfrpTun服务根据nServerNumber管理socket对
typedef CSocketPairMap::iterator iterSockets;
typedef std::vector<CLfrpSocket*> CSocketVec;
typedef std::map<int, CLfrpSocket*> CSocketMap;         // 业务端点根据soketID管理多连接
typedef std::map<int, int>  CSeqMap;                    // socketID->NextSeq


void LfrpSetFD(CLfrpSocket* pSocket, fd_set& fdRead, fd_set& fdWrite);
char* GetSocketBuffer(CLfrpSocket* pSocket);

// 解析包里的头信息
int ParsePackHeader(CLfrpSocket* pSocket);

// 添加nRet的pData数据到Buffer
bool AddDataToSocketBuffer(char Buffer[], char*& pBuffer, int& nBufLen, int& nBufAlloc, char* pData, int nRet);

// 从Buffer里移nPackLen的包数据到pBuf
bool RemoveDataFromSocketBuffer(char Buffer[], char*& pBuffer, int& nBufLen, int& nBufAlloc, char* pBuf, int& nPackLen);

// recv封装，用于加入aes以及内存管理
int LfrpRecv(CLfrpSocket* pSocket);                          // 数据流接收封装，返回值小于0错误，等于0断开，大于0正常

// 三个服务都是socket对，之间流转数据包
int MoveSendPack(CLfrpSocket* pSrcSocket, CLfrpSocket* pDesSocket);

void CopyOnePack(CLfrpSocket* pSocket, char* pBuf);

// 丢弃一个数据包
void DropOnePack(CLfrpSocket* pSocket);

// User侧或Bussiness侧异常，组装通知另一侧断开的消息
void MakeDataEndPack(CBuffer& buf, int nSocketID, int nSeq);    

// LfrpTun服务根据一侧通道异常，组装通知Client或Server断开业务的消息
void MakeTunEndPack(CBuffer& buf);        

// close socket封装，带上清理内存
void CloseLfrpSocket(CLfrpSocket* pSocket);

// Seq是User侧或Bussiness侧各自发起包带的，用于调试数据包在链路流转的问题
int GetNextSeq(SeqEnum nType, int nSocketID);     
void RemoveSeqKey(int nSocketID);

// 获取buffer中的socket信息
void GetInfoFromBuf(CBuffer& buf, int& nType, int& nLen, int& nSocketID, int& nSeq);

// 获取最后一个包信息，注意这个函数要求最后的包头至少包含包大小字段
void GetLastPackLenInfo(CLfrpSocket* pSocket, int& nBufLen, int& nPackLen);

// 连接socket封装
int ConnectSocket(SOCKET* pSocket, const char* pIPAddress, int nPort);

// 准备给日志使用
std::string GetCurTimeStr();    
#endif
