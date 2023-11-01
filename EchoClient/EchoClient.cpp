// EchoClient.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#elif 1/*defined(USE_EPOLL)*/
#include "../global.h"
#include "../globalEpoll.h"
#undef BUFFER_SIZE
#else
#include <sys/types.h>      
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

typedef int SOCKET;
typedef unsigned int DWORD;
typedef unsigned char BYTE;
#define FALSE 0 
#define SOCKET_ERROR (-1) 
#define INVALID_SOCKET (SOCKET)(~0)
#define NO_ERROR    0

static int geterror() { return errno; }
#define WSAGetLastError() geterror()
#define Sleep   sleep
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define nullptr     0
#endif

std::string ip = "127.0.0.1";
int nPort = 12345;

static SOCKET sClient;
#define CLENT_NUM 1
static SOCKET sSever, sSever_c[CLENT_NUM];
struct sockaddr_in sSever_c_sd[CLENT_NUM];

#define MAX_SEND_SIZE   512
#define BUFFER_SIZE     MAX_SEND_SIZE+1

#define USER_ERROR -1

#ifdef _WIN32
#define LFRP_SEND_FLAGS     0
#else
#define LFRP_SEND_FLAGS     MSG_NOSIGNAL
#endif

int tcp_client_init(const char* ip, int iPort)
{
    struct sockaddr_in ser; //服务器端地址
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("Failed to load Winsock.\n"); //Winsock 初始化错误
        return -1;
    }
#endif
    ser.sin_family = AF_INET;                        //初始化服务器地址信息
    ser.sin_port = htons(iPort);                     //端口转换为网络字节序
    ser.sin_addr.s_addr = inet_addr(ip); //IP 地址转换为网络字节序
    sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);       //创建客户端流式套接字
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
    int nRet = send(sClient, (const char*)buff, len, LFRP_SEND_FLAGS);
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
#ifdef _WIN32
    closesocket(sClient); //关闭 socket
    WSACleanup();
#else
    close(sClient); //关闭 socket
#endif
    
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

#ifdef USE_EPOLL
#include<sys/time.h>
#include <atomic>

#define TEST_LOOP_COUNT  500
std::thread** pEchoCliThreadAry = nullptr;
typedef std::map<int, std::string> CSocketDataMap;
CSocketDataMap* pSockDataMapAry = nullptr;
std::atomic<int> nCorrectCount(0);
std::atomic<int> nConnectCount(0);
std::atomic<int> nCloseCount(0);
struct timeval tmStart;

// 全局sock对实例的映射字典
std::shared_mutex mtxEchoSockToInstance;
std::map<int, CLfrpSocket*> mapEchoSockToClass;
void EchoAddSockToInstanceMap(int sock, CLfrpSocket* pSocket)
{
    CWriteLock lock(mtxEchoSockToInstance);
    std::map<int, CLfrpSocket*>::iterator iter = mapEchoSockToClass.find(sock);
    if (iter != mapEchoSockToClass.end())
    {
        mapEchoSockToClass.erase(iter);;
    }
    mapEchoSockToClass.insert(std::make_pair(sock, pSocket));
}

void EchoRemoveSockFromInstanceMap(int sock)
{
    CWriteLock lock(mtxEchoSockToInstance);
    std::map<int, CLfrpSocket*>::iterator iter = mapEchoSockToClass.find(sock);
    if (iter != mapEchoSockToClass.end())
    {
        mapEchoSockToClass.erase(iter);;
    }
}

void ExitProcess()
{
    ExitWorkerThreads();

    struct timeval tmEnd;
    gettimeofday(&tmEnd, NULL);
    int nDiffTime = 1000* (tmEnd.tv_sec - tmStart.tv_sec) + (tmEnd.tv_usec - tmStart.tv_usec) / 1000;

    int nCoCnt = nCorrectCount;
    int nClCnt = nCloseCount;
    double nCountPerSec = nThreadCount * TEST_LOOP_COUNT / ((double)nDiffTime / 1000);
    PRINT_ERROR("%s %s,%d: test finish take %dms with %d correct in %d test count, TPC %f\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nDiffTime, nCoCnt, nClCnt, nCountPerSec);
#ifdef LOG_TO_FILE
    printf("%s %s,%d: test finish take %dms with %d correct in %d test count, TPC %f\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nDiffTime, nCoCnt, nClCnt, nCountPerSec);
#endif

    // 打印失败内容：比如单机测试EchoServer抢不到资源，来不及accept；
    for (size_t i = 0; i < nThreadCount; i++)
    {
        for (CSocketDataMap::iterator iter = pSockDataMapAry[i].begin(); iter != pSockDataMapAry[i].end(); iter++)
        {
            //if (iter->second.length() == 0)
            {
                PRINT_ERROR("%s %s,%d: SocketID %d with data size %d didn't recv data\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->first, iter->second.length());
            }
        }
    }

    for (std::map<int, CLfrpSocket*>::iterator iter = mapEchoSockToClass.begin(); iter != mapEchoSockToClass.end(); iter++)
    {
        PRINT_ERROR("%s %s,%d: SocketID %d didn't close\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->first);
    }

    // todo，完整清理并退出
    exit(0);
}

int EchoCliTrans(int nIndex, int sock, CLfrpSocket* pSocket)
{
    return 0;
}

int EchoCliClose(int nIndex, int sock)
{
    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (!pSocket)
    { // 已经关闭不再尝试发送
        return 0;
    }

    PRINT_INFO("%s %s,%d: thread %d SocketID %d close\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex, sock);
    //close(sock);
    //AddDelayClose(sock);
    CloseSocketInstance(nIndex, sock);
    EchoRemoveSockFromInstanceMap(sock);

    nCloseCount++;

    if (nCloseCount == TEST_LOOP_COUNT * nThreadCount)
    {
        ExitProcess();
    }

    return 0;
}

int EchoCliRead(int nIndex, int sock, char* pBuffer, int nCount)
{
    CSocketDataMap::iterator iter = pSockDataMapAry[nIndex].find(sock);
    if (iter != pSockDataMapAry[nIndex].end())
    {
        std::string& str = iter->second;
        std::string strRecv(pBuffer, nCount);
        if (str.length() > nCount)
        {
            PRINT_ERROR("%s %s,%d: SocketID %d recv part pack\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        }
        else if (str.compare(strRecv) != 0)
        {
            PRINT_ERROR("%s %s,%d: SocketID %d with %d:%s recv error data %d:%s\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, str.length(), str.c_str(), strRecv.length(), strRecv.c_str());
        }
        else
        {
            nCorrectCount++;
            PRINT_INFO("%s %s,%d: OK: SocketID %d recv: %d:%s\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, str.length(), str.c_str());
            //str.clear();
        }
        pSockDataMapAry[nIndex].erase(iter);
    }
    else
    {
        PRINT_ERROR("%s %s,%d: cant find SocketID %d \n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
    }

    // 比较完关闭socket
    //FireCloseEvent(sock);
    EchoCliClose(nIndex, sock);     // Fire关闭会导致事件中间再Write数据

    return 0;
}

int EchoCliWrite(int nIndex, int sock)
{
    if (pSockDataMapAry[nIndex].find(sock) != pSockDataMapAry[nIndex].end())
    { // 发送过，不再发
        return 0;
    }

    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (!pSocket)
    { // 已经关闭不再尝试发送
        return 0;
    }
    
    char cBuf[100] = { '0' };
    sprintf(cBuf, "%d,%d:", nIndex, sock);
    std::string str = cBuf; // "test";
    int nSize = rand() % MAX_SEND_SIZE;
    for (size_t i = 0; i < nSize; i++)
    {
        //char c = (rand() % 26) + 'a';
        char c = (i % 26) + 'a';
        str += c;
    }
    pSockDataMapAry[nIndex].insert(std::make_pair(sock, str));
    int nRet = send(sock, str.c_str(), str.length(), LFRP_SEND_FLAGS);
    if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
    { // 堵住就等下一个EPOLLOUT事件，清掉已经发送的数据
        PRINT_ERROR("%s %s,%d: send to Tun err size %d wsaerr %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, str.length(), WSAGetLastError());
        //FireWriteEvent(sock);
    }
    else if (nRet == SOCKET_ERROR || nRet == 0)
    {
        PRINT_ERROR("%s %s,%d: SocketID %d disconnect because send err %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nRet);
    }
    else
    {
        PRINT_INFO("%s %s,%d: SocketID %d send data size %d:%s err %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, str.length(), str.c_str(), nRet);
    }
    return 0;
}

void EchoConnectWorker(int nIndex, const char* pIPAddr, int nPort)
{
    for (size_t i = 0; i < TEST_LOOP_COUNT; i++)
    {
        if (bExitPorcess)
        {
            return;
        }

        // 等待连接太多需要等一下
        if (nConnectCount - nCloseCount > 100)
        {
            usleep(1 * 1000);
        }

        int sock = INVALID_SOCKET;
        //EpollConnectSocket(epollfd, sock, pIPAddr, nPort);
        //FireTransEvent(sock);
        nConnectCount++;
        CLfrpSocket* pSocket = new CLfrpSocket;
        if (pSocket)
        {
            if (PreConnectSocket(pSocket->sock, pIPAddr, nPort) != 0)
            {
                pSocket->sock = INVALID_SOCKET;
                PRINT_ERROR("%s connect() Tun Failed: %d\n", GetCurTimeStr(), WSAGetLastError());
            }
            else
            {
                PRINT_INFO("%s %s,%d: EchoConnectWorker connect SocketID %d \n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock);
                // 先把sock放到全局环境
                sock = pSocket->sock;
                AddSockToInstanceMap(sock, pSocket);    // 添加实例，用于判断sock是否可用
                EchoAddSockToInstanceMap(sock, pSocket);

                // 实际连接
                int nRet = ProcssConnectSocket(pSocket->sock, pIPAddr, nPort);
                nRet = EpollPostConnectSocket(epollfd, pSocket->sock, pIPAddr, nPort, nRet);
                if (nRet < 0)
                {
                    PRINT_ERROR("%s %s,%d: EpollPostConnectSocket error: %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet);
                    CloseLfrpSocket(pSocket);
                    delete pSocket;
                    sock = INVALID_SOCKET;
                }
                else
                {
                    //FireTransEvent(sock);                   // 等待可写后，避免可写先完成，这里发个事件
                }
            }
        }
        else
        {
            PRINT_ERROR("%s %s,%d: thread %d index %d new CLfrpSocket error\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex, i);
        }
    }
}

int EchoCliTimer()
{
    CommTimer();

    static bool bExit = false;
    if (!bExit && !bExitPorcess)
    {
        struct timeval tmEnd;
        gettimeofday(&tmEnd, NULL);
        int nDiffTime = 1000 * (tmEnd.tv_sec - tmStart.tv_sec) + (tmEnd.tv_usec - tmStart.tv_usec) / 1000;
        int nEndTime = nThreadCount * TEST_LOOP_COUNT * 1000 / 2 / 4;
        nEndTime = nEndTime > 5 ? nEndTime / 2 : nEndTime;
        if (nDiffTime > 30 * 1000/*nEndTime*/)  // todo, 超过时间根据机器情况设置
        {
            bExit = true;
            ExitProcess();
        }
    }
    return 0;
}

int mainEchoEpoll()
{
    // 初始化socket
    InitSocket();

    InitLog("./EchoCli.txt");

    // 初始化epooll工作线程相关
    SetBusWorkerCallBack(EchoCliRead, EchoCliWrite, EchoCliClose, EchoCliTrans, nullptr, EchoCliTimer);
    InitWorkerThreads();
    pSockDataMapAry = new CSocketDataMap[nThreadCount];
    pEchoCliThreadAry = new std::thread * [nThreadCount];

    gettimeofday(&tmStart, NULL);

    for (int i = 0; i < nThreadCount; i++)
    {
        pEchoCliThreadAry[i] = new std::thread(EchoConnectWorker, i, ip.c_str(), nPort);
    }

    SOCKET sockListen = INVALID_SOCKET;
    mainEpoll(epollfd, sockListen);
    bExitPorcess = true;

    return 0;
}
#endif

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
    
#ifdef USE_EPOLL
    mainEchoEpoll();
#else
    tcp_client_test();
#endif
    return 0;
}
