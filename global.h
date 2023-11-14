#ifndef __GLOBAL_H
#define __GLOBAL_H

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/types.h>      
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>

typedef int SOCKET;
typedef unsigned int DWORD;
typedef unsigned char BYTE;
#define FALSE 0 
#define SOCKET_ERROR (-1) 
#define INVALID_SOCKET (SOCKET)(~0)
#define NO_ERROR    0

extern int geterror();
#define WSAGetLastError() geterror()
#define Sleep   sleep
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define nullptr     0
#endif

/*******************************************************
* 1.本程序为专用AES，只用一个全局key加密
* 2.本程序一律采用fill模式，解包时自动按填充的折算
* 3.本程序跟lfrpTun相关的数据流完全加密，不留数据头，避免被检测头
********************************************************/
#define USE_AES

#define LOCAL_IP "127.0.0.1"
#define DEFAULT_BACKLOG 10240   //128     // backlog太小会导致队列满而使得一些请求被丢弃
#define MAX_IO_PEND 10
#define OP_READ 0x10
#define OP_WRITE 0x20//定义结构体用于储存通信信息，注意EPOLL复用了这个标志位做trans
#define MAGIC_NUMBER 0xFEEFFEEF
#define SEQ_CLIENT_BEG  10000
#define SEQ_SERVER_BEG  1000000

#define Print_ErrCode(e) fprintf(stderr,"\n[Server]%s 执行失败: %d\n",e,WSAGetLastError())

//#define RECORD_SOCKET_DATA  // 是否记录socket收发的数据
#define LOG_TO_FILE
#ifdef LOG_TO_FILE
    #define PRINT_ERROR PrintToFile
    #define PRINT_INFO //PrintToFile
#else // LOG_TO_FILE
    #define PRINT_ERROR printf
    #ifdef _DEBUG
        #define PRINT_INFO  printf
    #else
        #define PRINT_INFO 
    #endif // _DEBUG
#endif // LOG_TO_FILE

enum SeqEnum
{
    SEQ_CLIENT = 0,
    SEQ_SERVER
};

enum PackTypeEnum
{
    PACK_TYPE_AUTH_SERVER = 1,  // 服务登录
    PACK_TYPE_AUTH_VISTOR,      // 访问者登录
    PACK_TYPE_HEART_BEAT,       // 心跳
    PACK_TYPE_DATA_BEG = 100,   // 数据包类型开始，区间包格式:MaginNum,type,len,SocketID
    PACK_TYPE_DATA,             // 数据包
    PACK_TYPE_DATA_END = 999,   // 数据包类型结束，用于分段结束，也用于业务结束
    PACK_TYPE_TUN_BEG = 1000,   // 通道之间的消息，不涉及业务
    PACK_TYPE_TUN_END = 1999,   // 通道之间的消息，不涉及业务；用于分段结束，也用于业务结束
    PACK_TYPE_UNKNOW = 10000,
};

// 记录
enum RecordTypeEnum
{
    RECORD_TYPE_UNKNOW = 0,     // 未知类型，不需要记录，比如lfrpTun收到新建连接
    RECORD_TYPE_TUN_RECV = 1,   // lfrpCli和lfrpSvr跟通道的接受
    RECORD_TYPE_TUN_SEND,       // lfrpCli和lfrpSvr跟通道的发送
    RECORD_TYPE_BUS_RECV,       // lfrpCli和lfrpSvr跟非通道的接受
    RECORD_TYPE_BUS_SEND,       // lfrpCli和lfrpSvr跟非通道的发送
    RECORD_TYPE_STUN_RECV,      // lfrpTun跟业务服务侧连接的接受
    RECORD_TYPE_STUN_SEND,      // lfrpTun跟业务服务侧连接的发送
    RECORD_TYPE_CTUN_RECV,      // lfrpTun跟客户侧连接的接受
    RECORD_TYPE_CTUN_SEND,      // lfrpTun跟客户侧连接的发送
};


#ifdef _WIN32
#define ELEM_BUFFER_SIZE    1024*1024   // 增大内容避免不停new内存
#else
#define ELEM_BUFFER_SIZE    16*1024   // 增大内容避免不停new内存
#endif
#define RECV_BUFFER_SIZE    10*1024        // socket接受一次大小
#define BUFFER_SIZE 1024
#define PACK_SIZE_HEADER 12
#define PACK_SIZE_AUTH  16
#define PACK_SIZE_DATA_BEG  20
#define PACK_SIZE_DATA  20
#define PACK_SIZE_HEADER_MAX 20

#ifdef _WIN32
#define LFRP_SEND_FLAGS     0
#else
#define LFRP_SEND_FLAGS     MSG_NOSIGNAL
#endif


struct CBuffer
{
    int nLen;
    char* pBuffer;
    uint64_t uCreateTime;
};
typedef std::vector<CBuffer> CVecBuffer;

class CLfrpSocket
{
public:
    CLfrpSocket();
    ~CLfrpSocket();

    void InitMember();
    void ClearBuffer();

public:
    SOCKET sock;
    DWORD Op;                   // 注意EPOLL复用了这个标志位做trans
    int nMagicNum;
    int nServiceNumber;          // 服务提供编号，用于区分Business侧提供的服务，认证包带
    int nSocketID;              // Select: Cli socketID; 业务客户端建立的SocketID，PACK_TYPE_DATA_BEG包带，通道Elem是临时存下
                                // Epoll: Cli Virtual Increamental ID，避免socket复用导致问题；用于链路传输Cli侧唯一标识（全链路是SN + VID唯一标识）

    int nPackSeq;               // 为每个SocketID连接

    // 接收数据相关
    int nType;                  // 收到的包类型
    int nPackLen;               // 包含头部8个字节
    // 接受数据buffer
    int nBufLen;
    char Buffer[ELEM_BUFFER_SIZE]; //前12个字节放MagicNum、Type和nPackLen，可跟多个包
    char* pBuffer;            // 超过BUFFER_SIZE只用这个存
    int nBufAlloc;              // 分配的pBuffer大小

    //发送队列
    CVecBuffer vecSendBuf;      // lfrpTun里存AES加密数据，避免重复加解密；其他存原始数据

    unsigned int nAcceptSec;    // Accept的时间
    unsigned int nLastRecvSec;  // 最后一次接收数据的时间，有心跳包，防止假连

    uint64_t uCreateTime;

#if 1//def USE_AES
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
char* GetSocketEncBuffer(CLfrpSocket* pSocket);

// 解析包里的头信息
int ParsePackHeader(CLfrpSocket* pSocket);
int ParsePackHeader(char* pBuffer, int nBufLen, int& nType, int& nPackLen);

// 添加nRet的pData数据到Buffer
bool AddDataToSocketBuffer(char Buffer[], char*& pBuffer, int& nBufLen, int& nBufAlloc, char* pData, int nRet);

// 从Buffer里移nPackLen的包数据到pBuf
bool RemoveDataFromSocketBuffer(char Buffer[], char*& pBuffer, int& nBufLen, int& nBufAlloc, char* pBuf, int& nPackLen);

// recv封装，用于加入aes以及内存管理
int LfrpRecv(CLfrpSocket* pSocket, RecordTypeEnum nType);                          // 数据流接收封装，返回值小于0错误，等于0断开，大于0正常
int LfrpTunAESRecv(CLfrpSocket* pSocket, RecordTypeEnum nType);
int AddAESRecvData(CLfrpSocket* pSocket, char* Buffer, int nRet);       // 通用获取数据，全解密
int AddTunAESRecvData(CLfrpSocket* pSocket, char* Buffer, int nRet);    // 通道获取数据，只用解出包头

// 三个服务都是socket对，之间流转数据包
bool MoveSendPack(CLfrpSocket* pSrcSocket, CLfrpSocket* pDesSocket);
bool MoveSendAESPack(CLfrpSocket* pSrcSocket, CLfrpSocket* pDesSocket);

// 取一个数据包
void FetchOnePack(CLfrpSocket* pSocket, char* pBuf);

// 丢弃一个数据包
void DropOnePack(CLfrpSocket* pSocket);

// 心跳包
void MakeHeartBeatPack(CBuffer& buf);

// User侧或Bussiness侧异常，组装通知另一侧断开的消息
void MakeDataEndPack(CBuffer& buf, int nSocketID, int nSeq);    

// LfrpTun服务根据一侧通道异常，组装通知Client或Server断开业务的消息
void MakeTunEndPack(CBuffer& buf);        

// 加密数据块
void EncryptBuffer(CBuffer& buf);

// close socket封装，带上清理内存
void CloseLfrpSocket(CLfrpSocket* pSocket);

// Seq是User侧或Bussiness侧各自发起包带的，用于调试数据包在链路流转的问题
int GetNextSeq(SeqEnum nType, int nSocketID);     
void RemoveSeqKey(int nSocketID);

// 获取buffer中的socket信息
void GetInfoFromBuf(CBuffer& buf, int& nType, int& nLen, int& nSocketID, int& nSeq);

// 获取最后一个包信息，注意这个函数要求最后的包头至少包含包大小字段
int GetLastPackLenInfo(CLfrpSocket* pSocket, int& nBufLen, int& nPackLen);

// 初始化socket
int InitSocket();

// 连接socket封装
int PreConnectSocket(SOCKET& sockCon, const char* pIPAddress, int nPort);
int ProcssConnectSocket(SOCKET& sockCon, const char* pIPAddress, int nPort);
int ConnectSocket(SOCKET& sockCon, const char* pIPAddress, int nPort);
int CheckConnected(SOCKET& sockCon);

// 监听socket
int ListenSocket(SOCKET& sockListen, const char* pIPAddress, int nPort);

// 判断是否需要等一下再发送，比如缓冲区堵住
bool IsReSendSocketError(int nError);

void DeleteBufItems(CVecBuffer& vecBuf, int nIndex);

uint64_t GetCurMilliSecond();
unsigned int GetCurSecond();
const char* GetCurTimeStr();    // 单线程使用，todo 多线程可能乱码但不至于崩溃
void InitLog(const char* file);
void PrintToFile(const char* format, ...);

void InitSection(const char* section);
void RecordSocketData(RecordTypeEnum nType, int nSocket, char* pData, int nLen);

std::vector<std::string> stringSplit(const std::string& str, char delim);
std::vector<int> TransStrToInt(std::vector<std::string>& vecStr);

#endif // __GLOBAL_H
