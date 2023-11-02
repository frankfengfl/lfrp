#ifndef __GLOBAL_EPOLL_H
#define __GLOBAL_EPOLL_H

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
#endif

#ifndef _WIN32
#define USE_EPOLL

// 配置断开事件EPOLLRDHUP，配置EPOLLONESHOT避免多触发
#define DEFAULT_EPOLL_STAT  (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLRDHUP | EPOLLET /*| EPOLLONESHOT*/)
#define LISTEN_EPOLL_STAT (EPOLLIN /*| EPOLLOUT | EPOLLERR | EPOLLRDHUP | EPOLLET | EPOLLONESHOT*/)     // Listen入股边缘触发，一次有多条就一个事件accept会丢失剩余
// EPOLLIN 1, EPOLLOUT 4, EPOLLPRI 2, EPOLLERR 8, EPOLLRDHUP 2000, EPOLLET 80000000, EPOLLONESHOT 40000000
#define EPOLL_CUSTOM_TRANS_EVENT    (EPOLLERR << 2)     // 仅用于自定义中转到工作线程使用
#define EPOLL_CUSTOM_HEART_BEAT_EVENT (EPOLLERR << 4)   // 仅用于自定义中转到工作线程使用
#define MAX_FILE_NUMBER     100*1024  // 进程最大文件数
#define MAX_EPOLL_EVENT     20000  // EPOLL事件数

#define OP_TRANS 0x80	//定义结构体用于储存通信信息

#define DELAY_CLOSE_SECOND      5   // 延迟关闭socket避免快速复用影响业务
#endif

#ifdef USE_EPOLL
extern int epollfd;
extern int nThreadCount;
extern bool bExitPorcess;
extern int pipefd[2];
typedef std::shared_lock<std::shared_mutex> CReadLock; // 读锁
typedef std::lock_guard<std::shared_mutex> CWriteLock; // 写锁

typedef int (*fnRead)(int nIndex, int sock, char* pBuffer, int nCount);
typedef int (*fnClose)(int nIndex, int sock);
typedef int (*fnEpollRead)(int sock);
typedef int (*fnEpollWrite)(int sock);
typedef int (*fnEpollClose)(int sock);
void WorkerWait(std::condition_variable& cvWait, std::mutex& mtxWait, int& nFlag);
void WorkerNotify(std::condition_variable& cvWait, std::mutex& mtxWait, int& nFlags, int nAddFlag);
void EpollReadET(int nThreadIndex, int sockfd, fnRead cbRead, fnClose cbClose);
void EpollAddEvent(int epollfd, int fd, int state);
void EpollDeleteEvent(int epollfd, int fd, int state);
void EpollInit();
int EpollConnectSocket(SOCKET epollfd, SOCKET& sockCon, const char* pIPAddress, int nPort);
int EpollPostConnectSocket(SOCKET epollfd, SOCKET& sockCon, const char* pIPAddress, int nPort, int nRet);
int EpollListenSocket(SOCKET epollfd, SOCKET& sockListen, const char* pIPAddress, int nPort);
void EpollRunET(int epollfd, epoll_event* events, int nEventNumber, SOCKET& listenfd, fnEpollRead cbRead, fnEpollWrite cbWrite, fnEpollClose cbClose);

void AddSockToInstanceMap(int sock, CLfrpSocket* pSocket);
void RemoveSockFromInstanceMap(int sock);
CLfrpSocket* GetSockFromInstanceMap(int sock);


typedef int (*fnBusRead)(int nIndex, int sock, char* pBuffer, int nCount);
typedef int (*fnBusWrite)(int nIndex, int sock);
typedef int (*fnBusClose)(int nIndex, int sock);
typedef int (*fnBusTrans)(int nIndex, int sock, CLfrpSocket* pSocket);
typedef int (*fnBusPostAccept)(CLfrpSocket* pSocket);
typedef int (*fnBusTimer)();
int GetFirstSocket(std::vector<int>& vecSock, std::mutex& mtx);
void MoveSocketVec(std::vector<int>& vecDstSock, std::vector<int>& vecSrcSock, std::mutex& mtx);
int GetThreadIndexByNum(int nNum);
int GetThreadIndex(int sock);
int GetServiceNum(int sock);
void SetServiceNum(int sock, int nServiceNum);
int GetSockBySN(int nServiceNum);				// Cli和Svr的ServiceNumber分别对应一个sock
void SetSockBySN(int nServiceNum, int sock);	// Cli和Svr的ServiceNumber分别对应一个sock
std::vector<int> GetActiveSNSock();             // 获取所有SN的Sock，用于比如发送心跳
int FireReadEvent(int sock);					// 读事件
int FireWriteEvent(int sock);					// 写事件
int FireCloseEvent(int sock);					// 异常关闭事件
int FireTransEvent(int sock);					// 转换事件，都是socket刚连接好后，或者刚收到第一组包时需要转到对应线程处理
int FireHeartBeatEvent(int sock);                    // 发送心跳事件
int CloseSocketInstance(int nIndex, int sock);
int AddDelayClose(int sock);                    // 延迟几秒关闭，避免socket快速复用，而部分内存没及时清掉
int FireDelayClose();
void SetBusWorkerCallBack(fnBusRead fnRead, fnBusWrite fnWrite, fnBusClose fnClose, fnBusTrans fnTrans, fnBusPostAccept fnPostAccept, fnBusTimer fnTimer);
void InitWorkerThreads();
void ExitWorkerThreads();
void EpollWorker(int nIndex);
int mainEpoll(int epollfd, SOCKET& sockListen);

bool EpollMoveSendPack(CLfrpSocket* pSrcSocket, CLfrpSocket* pDesSocket);
int GetNextSeq(int nIndex, SeqEnum nType, int nSocketID);
void RemoveSeqKey(int nIndex, int nSocketID);

/*
*  connect相关，指的是Cli和Svr连接Tun部分的connect管理
*/
#define MAKE_SOCKET_MAP_KEY(x,y) (((int64_t)x << 32) + y)
extern std::vector<int> vecServieNumber;
void ConnectWorker(const char* pIPAddr, int nPort);
int FireConnectEvent(int nServiceNum);
int AddDelayReConnect(int nServiceNum);         // 添加延迟连接
int FireDelayReConnect();                       // 发送延迟连接

// 定时器相关
void InitTimer(int epollfd);
int CommTimer();                // 处理延迟重连、sock句柄延迟关闭

int SendSNHeartBeat(int sock);

// pipe相关
#define PIPE_OP_ADD_EPOLL   1
#define PIPE_OP_DEL_EPOLL   2
struct CPipeData
{
    int op;
    int fd;
};
#endif // USE_EPOLL

#endif // __GLOBAL_EPOLL_H
