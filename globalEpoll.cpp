// global.cpp 
//

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include "global.h"
#include "globalEpoll.h"
#include "aes.h"

#ifdef USE_EPOLL
#include <sys/timerfd.h>

int epollfd = 0;
int nThreadCount = 1;

// 管道用于同步epoll的add和del到主线程
int pipefd[2] = {-1};

// 定时器描述符
int timerfd = -1;

// 全局sock对实例的映射字典
std::shared_mutex mtxSockToInstance;
std::map<int, CLfrpSocket*> mapSockToClass;

// 工作线程同步事件相关
bool bExitPorcess = false;
std::condition_variable* pCvAry = nullptr;
std::mutex* pMutexAry = nullptr;
std::thread** pThreadAry = nullptr;
int* pFlagAry = nullptr;
std::vector<int>* pRecvSockAry = nullptr;
std::vector<int>* pSendSockAry = nullptr;
std::vector<int>* pCloseSockAry = nullptr;
std::vector<int>* pTransSockAry = nullptr;
std::vector<int>* pHeartBeatSockAry = nullptr;
CSeqMap* pSeqMapAry = nullptr;

// 业务回调
fnBusRead fnBusReadCallback = nullptr;
fnBusWrite fnBusWriteCallback = nullptr;
fnBusClose fnBusCloseCallback = nullptr;
fnBusTrans fnBusTransCallback = nullptr;
fnBusPostAccept fnBusPostAcceptCallback = nullptr;
fnBusTimer fnBusTimerCallback = nullptr;

// sock到serverNumber的字典
std::shared_mutex mtxSockToSvrNum;
std::map<int, int> mapSockToServiceNum;

// 重连相关
std::mutex mtxReConnect;
std::map<int, unsigned int>  mapServiceNumToTime;        // 发送重连时间，收到新的会更新时间
// 关闭相关
std::mutex mtxDelayClose;
std::map<int, unsigned int>  mapCloseSockToTime;        // 发送重连时间，收到新的会更新时间

void AddSockToInstanceMap(int sock, CLfrpSocket* pSocket)
{
    CWriteLock lock(mtxSockToInstance);
    std::map<int, CLfrpSocket*>::iterator iter = mapSockToClass.find(sock);
    if (iter != mapSockToClass.end())
    {
        mapSockToClass.erase(iter);;
    }
    mapSockToClass.insert(std::make_pair(sock, pSocket));
}

void RemoveSockFromInstanceMap(int sock)
{
    CWriteLock lock(mtxSockToInstance);
    std::map<int, CLfrpSocket*>::iterator iter = mapSockToClass.find(sock);
    if (iter != mapSockToClass.end())
    {
        mapSockToClass.erase(iter);;
    }
}

CLfrpSocket* GetSockFromInstanceMap(int sock)
{
    CReadLock lock(mtxSockToInstance);
    std::map<int, CLfrpSocket*>::iterator iter = mapSockToClass.find(sock);
    if (iter != mapSockToClass.end())
    {
        return iter->second;
    }
    return nullptr;
}

void WorkerWait(std::condition_variable& cvWait, std::mutex& mtxWait, int& nFlag)
{
    std::unique_lock<std::mutex> lock(mtxWait);
    if (nFlag)
    {
        return;
    }
    cvWait.wait(lock, [&nFlag]
        {
            return nFlag != 0;
        });
}

void WorkerNotify(std::condition_variable& cvWait, std::mutex& mtxWait, int& nFlags, int nAddFlag)
{
    std::unique_lock<std::mutex> lock(mtxWait);
    nFlags |= nAddFlag;
    lock.unlock();
    cvWait.notify_one();
}

void EpollAddEvent(int epollfd, int fd, int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    int nRet = epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
    if (nRet != 0)
    {
        PRINT_ERROR("%s %s,%d: EpollAddEvent socketID %d error %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, fd, nRet);
    }
}

void EpollDeleteEvent(int epollfd, int fd, int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    int nRet = epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
    if (nRet != 0)
    {
        PRINT_ERROR("%s %s,%d: EpollDeleteEvent socketID %d error %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, fd, nRet);
    }
}

void EpollInit()
{
    /* 设置每个进程允许打开的最大文件数 */
    struct rlimit rt;
    rt.rlim_max = rt.rlim_cur = MAX_FILE_NUMBER;
    if (setrlimit(RLIMIT_NOFILE, &rt) == -1) {
        PRINT_ERROR("setrlimit error");
        exit(1);
    }
}

// 先connect再添加epoll监听，不确定在快速连接时是否会错过事件，推荐使用PreConnectSocket、ProcssConnectSocket、EpollPostConnectSocket组合
int EpollConnectSocket(SOCKET epollfd, SOCKET& sockCon, const char* pIPAddress, int nPort)
{
    int nRet = ConnectSocket(sockCon, pIPAddress, nPort);
    if (nRet < 0 && errno != EINPROGRESS)
    {
        close(sockCon);
        PRINT_ERROR("%s %s,%d: connect socket %s:%d error %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pIPAddress, nPort, errno);
        return -1;
    }

    EpollAddEvent(epollfd, sockCon, DEFAULT_EPOLL_STAT);
    return 0;
}

int EpollPostConnectSocket(SOCKET epollfd, SOCKET& sockCon, const char* pIPAddress, int nPort, int nRet)
{
    if (nRet < 0 && errno != EINPROGRESS)
    {
        close(sockCon);
        PRINT_ERROR("%s %s,%d: connect socket %s:%d error %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pIPAddress, nPort, errno);
        return -1;
    }

    EpollAddEvent(epollfd, sockCon, DEFAULT_EPOLL_STAT);
    return 0;
}

int EpollListenSocket(SOCKET epollfd, SOCKET& sockListen, const char* pIPAddress, int nPort)
{
    int nRet = ListenSocket(sockListen, pIPAddress, nPort);
    if (nRet != 0)
    {
        return 1;
    };
    EpollAddEvent(epollfd, sockListen, LISTEN_EPOLL_STAT);
    return 0;
}

int PipeRead(int nIndex, int sock, char* pBuffer, int nCount)
{
    //PRINT_INFO("%s %s,%d: PipeRead fd %d size %d \n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nCount);
    char* pData = pBuffer;
    while (nCount >= sizeof(CPipeData))
    {
        CPipeData* pPipeData = (CPipeData*)pData;
        int fd = pPipeData->fd;
        if (pPipeData->op == PIPE_OP_ADD_EPOLL)
        {
            struct epoll_event ev;
            ev.events = DEFAULT_EPOLL_STAT;
            ev.data.fd = fd;
            int nRet = epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
            if (nRet != 0)
            {
                PRINT_ERROR("%s %s,%d: PipeRead addEpoll socketID %d error %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, fd, nRet);
            }
        }
        else if (pPipeData->op == PIPE_OP_DEL_EPOLL)
        {
            struct epoll_event ev;
            ev.events = DEFAULT_EPOLL_STAT;
            ev.data.fd = fd;
            int nRet = epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL/*&ev*/);
            if (nRet != 0)
            {
                PRINT_ERROR("%s %s,%d: PipeRead delEpoll socketID %d error %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, fd, nRet);
            }
        }
        pData += sizeof(CPipeData);
        nCount -= sizeof(CPipeData);
    }
    return 0;
}

int PipeClose(int nIndex, int sock)
{
    PRINT_ERROR("%s %s,%d: PipeClose socketID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
    return 0;
}

void EpollReadETPipe(int nIndex, int sockfd, fnRead cbRead, fnClose cbClose)
{
    PRINT_INFO("%s %s,%d: EpollReadETPipe thread %d begin\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex);
    char buf[RECV_BUFFER_SIZE];
    while (1)
    { // et模式一直读到EAGAIN
        memset(buf, '\0', RECV_BUFFER_SIZE);
        int ret = read(sockfd, buf, RECV_BUFFER_SIZE);
        PRINT_INFO("%s %s,%d: EpollReadETPipe thread %d recv ret %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex, ret);
        if (ret < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                break;
            }
            if (cbClose)
            {
                cbClose(nIndex, sockfd);
            }
            break;
        }
        else if (ret == 0)
        {
            if (cbClose)
            {
                cbClose(nIndex, sockfd);
            }
        }
        else
        {
            if (cbRead)
            {
                cbRead(nIndex, sockfd, buf, ret);
            }
        }
    }
    PRINT_INFO("%s %s,%d: EpollReadETPipe thread %d end\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex);
}

void EpollReadET(int nIndex, int sockfd, fnRead cbRead, fnClose cbClose)
{
    PRINT_INFO("%s %s,%d: EpollReadET thread %d begin\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex);
    char buf[RECV_BUFFER_SIZE];
    while (1)
    { // et模式一直读到EAGAIN
        memset(buf, '\0', RECV_BUFFER_SIZE);
        int ret = recv(sockfd, buf, RECV_BUFFER_SIZE, 0);
        PRINT_INFO("%s %s,%d: EpollReadET thread %d recv ret %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex, ret);
        if (ret < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                break;
            }
            if (cbClose)
            {
                cbClose(nIndex, sockfd);
            }
            break;
        }
        else if (ret == 0)
        {
            if (cbClose)
            {
                cbClose(nIndex, sockfd);
            }
            break;
        }
        else
        {
            if (cbRead)
            {
                cbRead(nIndex, sockfd, buf, ret);
            }
        }
    }
    PRINT_INFO("%s %s,%d: EpollReadET thread %d end\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex);
}

//ET工作模式
void EpollRunET(int epollfd, epoll_event* events, int nEventNumber, SOCKET& listenfd, fnEpollRead cbRead, fnEpollWrite cbWrite, fnEpollClose cbClose)
{
    PRINT_INFO("%s %s,%d: EpollRunET has trigger %d events\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nEventNumber);
    for (int i = 0; i < nEventNumber; i++)
    {
        int sockfd = events[i].data.fd;
        PRINT_INFO("%s %s,%d: EpollRunET the %d event is socket %d with event 0x%x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, i, sockfd, events[i].events);
        if (sockfd == listenfd)
        {
            //struct sockaddr_in client_address;
            //socklen_t client_addrlength = sizeof(client_address);
            //int connfd = accept(listenfd, (struct sockaddr*)&client_address, &client_addrlength);
            int connfd = accept(listenfd, NULL, NULL);
            if (connfd != INVALID_SOCKET)
            {
                int enable = 1;
                if (setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, (char*)&enable, sizeof(enable)) == SOCKET_ERROR)
                {
                    PRINT_ERROR("%s Tun %s,%d: accept socket setopt TCP_NODELAY error\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                }

                /* 非阻塞式连接 */
                int flags;
                flags = fcntl(connfd, F_GETFL, NULL);
                int iRet = fcntl(connfd, F_SETFL, flags | O_NONBLOCK);

                PRINT_INFO("%s Tun %s,%d: accept new socketID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, connfd);
                // todo, 新socket实例放主线程这里会影响速度，Tun改到放到read里，但是要管理新连接不发请求的关掉，避免攻击；Cli的Accept需要注意，改的时候也要处理
                CLfrpSocket* pSocket = new CLfrpSocket;
                pSocket->sock = connfd;
                AddSockToInstanceMap(connfd, pSocket);
                if (fnBusPostAcceptCallback)
                {
                    fnBusPostAcceptCallback(pSocket);
                }
                EpollAddEvent(epollfd, connfd, DEFAULT_EPOLL_STAT);
            }
            else
            {
                PRINT_ERROR("%s Tun %s,%d: accept error socketID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, connfd);
            }
        }
        else if (sockfd == pipefd[0])
        { // 收到pipe
            if (events[i].events & EPOLLIN)
            {
                EpollReadETPipe(0, sockfd, PipeRead, PipeClose);
            }
        }
        else if (sockfd == timerfd)
        {
            // 1秒定时器触发
            if (fnBusTimerCallback)
            {
                fnBusTimerCallback();
            }
        }
        else
        {
            if (events[i].events & EPOLLIN)
            {
                if (cbRead(sockfd) < 0)
                    cbClose(sockfd);
            }
            /*else */if (events[i].events & EPOLLOUT)
            {
                if (cbWrite(sockfd) < 0)
                    cbClose(sockfd);
            }
            //else //  EPOLLRDHUP | EPOLLERR 等都认为关闭
            if ((events[i].events & EPOLLRDHUP) || (events[i].events & EPOLLERR))
            { // todo，综合关闭的状态去释放
                cbClose(sockfd);
            }
        }
    }
}

int GetFirstSocket(std::vector<int>& vecSock, std::mutex& mtx)
{
    int sock = INVALID_SOCKET;
    std::unique_lock<std::mutex> lock(mtx);
    if (vecSock.size() > 0)
    {
        sock = vecSock[0];
        vecSock.erase(vecSock.begin());
    }
    lock.unlock();
    return sock;
}

void MoveSocketVec(std::vector<int>& vecDstSock, std::vector<int>& vecSrcSock, std::mutex& mtx)
{
    std::unique_lock<std::mutex> lock(mtx);
    vecDstSock.insert(vecDstSock.end(), vecSrcSock.begin(), vecSrcSock.end());
    vecSrcSock.clear();
    lock.unlock();
}

int GetThreadIndexByNum(int nNum)
{
    return nNum % nThreadCount;
}

int GetThreadIndex(int sock)
{
    int nThreadIndex = GetThreadIndexByNum(sock); // 新请求按模确定工作线程
    CReadLock lockSock(mtxSockToSvrNum);
    std::map<int, int>::iterator iter = mapSockToServiceNum.find(sock);
    if (iter != mapSockToServiceNum.end())
    {
        nThreadIndex = GetThreadIndexByNum(iter->second); // 有服务号的，按照服务号配对，这样成对操作无需加锁
    }
    lockSock.unlock();
    return nThreadIndex;
}

int GetServiceNum(int sock)
{
    int nServiceNum = -1;
    CReadLock lockSock(mtxSockToSvrNum);
    std::map<int, int>::iterator iter = mapSockToServiceNum.find(sock);
    if (iter != mapSockToServiceNum.end())
    {
        nServiceNum = iter->second; // 有服务号的，按照服务号配对，这样成对操作无需加锁
    }
    lockSock.unlock();
    return nServiceNum;
}

void SetServiceNum(int sock, int nServiceNum)
{
    CWriteLock lockSock(mtxSockToSvrNum);
    if (nServiceNum == -1)
    {
        std::map<int, int>::iterator iter = mapSockToServiceNum.find(sock);
        if (iter != mapSockToServiceNum.end())
        {
            mapSockToServiceNum.erase(iter);
        }
        return;
    }
    std::map<int, int>::iterator iter = mapSockToServiceNum.find(sock);
    if (iter != mapSockToServiceNum.end())
    {
        iter->second = nServiceNum;
    }
    else
    {
        mapSockToServiceNum.insert(std::make_pair(sock, nServiceNum));
    }
}

// sock到serverNumber的字典
std::shared_mutex mtxSvrNumToSock;
std::map<int, int> mapSvrNumToSock;
int GetSockBySN(int nServiceNum)
{
    int sock = -1;
    CReadLock lockSock(mtxSvrNumToSock);
    std::map<int, int>::iterator iter = mapSvrNumToSock.find(nServiceNum);
    if (iter != mapSvrNumToSock.end())
    {
        sock = iter->second; // 有服务号的，按照服务号配对，这样成对操作无需加锁
    }
    lockSock.unlock();
    return sock;
}
void SetSockBySN(int nServiceNum, int sock)
{
    CWriteLock lockSock(mtxSvrNumToSock);
    if (sock == INVALID_SOCKET)
    {
        std::map<int, int>::iterator iter = mapSvrNumToSock.find(nServiceNum);
        if (iter != mapSvrNumToSock.end())
        {
            mapSvrNumToSock.erase(iter);
        }
        return;
    }

    std::map<int, int>::iterator iter = mapSvrNumToSock.find(nServiceNum);
    if (iter != mapSvrNumToSock.end())
    {
        iter->second = sock;
    }
    else
    {
        mapSvrNumToSock.insert(std::make_pair(nServiceNum, sock));
    }
}
std::vector<int> GetActiveSNSock()
{
    std::vector<int> vecSock;
    int sock = -1;
    CReadLock lockSock(mtxSvrNumToSock);
    for (std::map<int, int>::iterator iter = mapSvrNumToSock.begin(); iter != mapSvrNumToSock.end(); iter++)
    {
        if (iter->second != INVALID_SOCKET)
        {
            vecSock.push_back(iter->second);
        }
    }
    lockSock.unlock();
    return vecSock;
}

// 运行于主线程，分配socket到对应线程处理
int FireReadEvent(int sock)
{
    int nThreadIndex = GetThreadIndex(sock);
    PRINT_INFO("%s Tun %s,%d: FireReadEvent socketID %d ThreadID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nThreadIndex);
    std::unique_lock<std::mutex> lock(pMutexAry[nThreadIndex]);
    pRecvSockAry[nThreadIndex].push_back(sock);
    lock.unlock();
    WorkerNotify(pCvAry[nThreadIndex], pMutexAry[nThreadIndex], pFlagAry[nThreadIndex], EPOLLIN);
    return 0;
}

// 运行于主线程，是水平触发；运行于工作线程，是有数据要发送了
int FireWriteEvent(int sock)
{
    int nThreadIndex = GetThreadIndex(sock);
    PRINT_INFO("%s Tun %s,%d: FireWriteEvent socketID %d ThreadID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nThreadIndex);
    std::unique_lock<std::mutex> lock(pMutexAry[nThreadIndex]);
    pSendSockAry[nThreadIndex].push_back(sock);
    lock.unlock();
    WorkerNotify(pCvAry[nThreadIndex], pMutexAry[nThreadIndex], pFlagAry[nThreadIndex], EPOLLOUT);
    return 0;
}

int FireCloseEvent(int sock)
{
    int nThreadIndex = GetThreadIndex(sock);
    PRINT_INFO("%s Tun %s,%d: FireCloseEvent socketID %d ThreadID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nThreadIndex);
    std::unique_lock<std::mutex> lock(pMutexAry[nThreadIndex]);
    pCloseSockAry[nThreadIndex].push_back(sock);
    lock.unlock();
    WorkerNotify(pCvAry[nThreadIndex], pMutexAry[nThreadIndex], pFlagAry[nThreadIndex], EPOLLERR);
    return 0;
}

// 用于新socket线程不对应时，在工作线程转线程时使用
int FireTransEvent(int sock)
{
    int nThreadIndex = GetThreadIndex(sock);
    PRINT_INFO("%s Tun %s,%d: FireTransEvent socketID %d ThreadID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nThreadIndex);
    std::unique_lock<std::mutex> lock(pMutexAry[nThreadIndex]);
    pTransSockAry[nThreadIndex].push_back(sock);
    lock.unlock();
    WorkerNotify(pCvAry[nThreadIndex], pMutexAry[nThreadIndex], pFlagAry[nThreadIndex], EPOLL_CUSTOM_TRANS_EVENT);
    return 0;
}

int FireHeartBeatEvent(int sock)
{
    int nThreadIndex = GetThreadIndex(sock);
    PRINT_INFO("%s Tun %s,%d: FireHeartBeatEvent socketID %d ThreadID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nThreadIndex);
    std::unique_lock<std::mutex> lock(pMutexAry[nThreadIndex]);
    pHeartBeatSockAry[nThreadIndex].push_back(sock);
    lock.unlock();
    WorkerNotify(pCvAry[nThreadIndex], pMutexAry[nThreadIndex], pFlagAry[nThreadIndex], EPOLL_CUSTOM_HEART_BEAT_EVENT);
    return 0;
}

void SetBusWorkerCallBack(fnBusRead fnRead, fnBusWrite fnWrite, fnBusClose fnClose, fnBusTrans fnTrans, fnBusPostAccept fnPostAccept, fnBusTimer fnTimer)
{
    fnBusReadCallback = fnRead;
    fnBusWriteCallback = fnWrite;
    fnBusCloseCallback = fnClose;
    fnBusTransCallback = fnTrans;
    fnBusPostAcceptCallback = fnPostAccept;
    fnBusTimerCallback = fnTimer;
}

int CloseSocketInstance(int nIndex, int sock)
{
    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (pSocket)
    {
        CloseLfrpSocket(pSocket);
        delete pSocket;
    }
    else
    {
        //close(sock);
        AddDelayClose(sock);   // 延迟关闭，避免太早复用事件错乱
    }
    return 0;
}

void InitWorkerThreads()
{
    // 初始化epooll工作线程相关
    unsigned int concurentThreadsSupported = std::thread::hardware_concurrency();
    nThreadCount = concurentThreadsSupported;
    //nThreadCount *= 2;      // 2倍CPU核数的线程
    nThreadCount = nThreadCount > 8 ? nThreadCount / 2 : nThreadCount;  // todo, 测试时所有程序在一台机器上，减少线程数

    pFlagAry = new int[nThreadCount];
    memset(pFlagAry, 0, sizeof(int) * nThreadCount);
    pRecvSockAry = new std::vector<int>[nThreadCount];
    pSendSockAry = new std::vector<int>[nThreadCount];
    pCloseSockAry = new std::vector<int>[nThreadCount];
    pTransSockAry = new std::vector<int>[nThreadCount];
    pHeartBeatSockAry = new std::vector<int>[nThreadCount];
    pSeqMapAry = new CSeqMap[nThreadCount];
    pThreadAry = new std::thread * [nThreadCount];
    pMutexAry = new std::mutex[nThreadCount];
    pCvAry = new std::condition_variable[nThreadCount];
    for (size_t i = 0; i < nThreadCount; i++)
    {
        pThreadAry[i] = new std::thread(EpollWorker, i);
    }

    epollfd = epoll_create(5);

    // 创建管道
    int ret;
    if ((ret = pipe(pipefd)) < 0)
    {
        PRINT_ERROR("%s Tun %s,%d: create pipe fail: ret %d errno %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, ret, errno);
        return;
    }
    
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = pipefd[0];
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, pipefd[0], &ev) < 0) {
        PRINT_ERROR("%s Tun %s,%d: add pipe to epoll error\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
        return;
    }

    InitTimer(epollfd);
}

void ExitWorkerThreads()
{
    EpollDeleteEvent(epollfd, timerfd, DEFAULT_EPOLL_STAT);
    EpollDeleteEvent(epollfd, pipefd[0], DEFAULT_EPOLL_STAT);
    bExitPorcess = true;

    // todo,通过FireHeartBeatEvent和FireConnectEvent来关闭所有工作线程
}

void EpollWorker(int nIndex)
{
    while (true)
    {
        WorkerWait(pCvAry[nIndex], pMutexAry[nIndex], pFlagAry[nIndex]);
        if (bExitPorcess)
        {
            return;
        }
        PRINT_INFO("%s %s,%d: EpollWorker worker thread %d with flag 0x%x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nIndex, pFlagAry[nIndex]);

        // 针对Cli在accept后FireTrans，在AddEpoll后FireRead，有顺序要求，如果不拷贝出来，在前一个EPOLLIN处理中会循环取了Read先做，再下一个循环做trans不对
        // 所以当此循环只处理已收到的内容，且跟循环处理倒序拷贝，避免拷贝完trans队列后read队列前，同时写入一个trans和read，致使read被先执行了
        // Close具有优先权，所有也比读写晚拷贝，跟trans优先一样
        std::vector<int> vecTrans;
        std::vector<int> vecRead;
        std::vector<int> vecWrite;
        std::vector<int> vecClose;
        std::vector<int> vecHB;
        std::unique_lock<std::mutex> lock(pMutexAry[nIndex]);
        vecHB.insert(vecHB.end(), pHeartBeatSockAry[nIndex].begin(), pHeartBeatSockAry[nIndex].end());
        vecWrite.insert(vecWrite.end(), pSendSockAry[nIndex].begin(), pSendSockAry[nIndex].end());
        vecRead.insert(vecRead.end(), pRecvSockAry[nIndex].begin(), pRecvSockAry[nIndex].end());
        vecClose.insert(vecClose.end(), pCloseSockAry[nIndex].begin(), pCloseSockAry[nIndex].end());
        vecTrans.insert(vecTrans.end(), pTransSockAry[nIndex].begin(), pTransSockAry[nIndex].end());
        pHeartBeatSockAry[nIndex].clear();
        pSendSockAry[nIndex].clear();
        pRecvSockAry[nIndex].clear();
        pCloseSockAry[nIndex].clear();
        pTransSockAry[nIndex].clear();
        int nFlag = pFlagAry[nIndex];
        pFlagAry[nIndex] = 0;
        lock.unlock();

        // 收了第一组包后转过来，需要把第一组包处理完，可能包含数据包，在后续循环再处理EPOLLIN读新数据
        if (nFlag & EPOLL_CUSTOM_TRANS_EVENT)
        {
            for (size_t i = 0; i < vecTrans.size(); i++)
            {
                int sock = vecTrans[i];
                if (fnBusTransCallback)
                {
                    fnBusTransCallback(nIndex, sock, nullptr);
                }
            }
        }

        // 收到读消息
        if (nFlag & EPOLLIN) // 这里可以不用锁判断，因为只有这个条件里面才会清除标志
        {
            for (size_t i = 0; i < vecRead.size(); i++)
            {
                int sock = vecRead[i];
                // 新连接正在转对应线程处理，但一开始按照socketID对应的线程还收到触发了，不要收数据，直接转到对应线程
                // 因为只会在socketID线程分配好，再次进入时不收数据，就不会影响ServiceNumber工作线程的接收顺序，即第一批包只在socketID线程收完，后续都换SN线程收
                if (GetThreadIndex(sock) != nIndex)
                { // 直接中转读触发状态到SN对应线程，未读数据
                    FireReadEvent(sock);
                }
                else
                {
                    EpollReadET(nIndex, sock, fnBusReadCallback, fnBusCloseCallback);
                }
            }
        }
        /*else */if (nFlag & EPOLLOUT)
        {
            for (size_t i = 0; i < vecWrite.size(); i++)
            {
                int sock = vecWrite[i];
                if (fnBusWriteCallback)
                {
                    fnBusWriteCallback(nIndex, sock);
                }
            }
        }
        /*else */if (nFlag & EPOLLERR)
        {
            for (size_t i = 0; i < vecClose.size(); i++)
            {
                int sock = vecClose[i];
                if (fnBusCloseCallback)
                {
                    fnBusCloseCallback(nIndex, sock);
                }
            }
        }

        // 收到心跳事件
        if (nFlag & EPOLL_CUSTOM_HEART_BEAT_EVENT)
        {
            for (size_t i = 0; i < vecHB.size(); i++)
            {
                int sock = vecHB[i];
                SendSNHeartBeat(sock);
            }
        }
    }
}

int mainEpoll(int epollfd, SOCKET& sockListen)
{
    /*
    EPOLLIN ：表示对应的文件描述符可以读（包括对端SOCKET正常关闭）；
    EPOLLOUT：表示对应的文件描述符可以写；
    EPOLLPRI：表示对应的文件描述符有紧急的数据可读（这里应该表示有带外数据到来）；
    EPOLLERR：表示对应的文件描述符发生错误；
    EPOLLHUP：表示对应的文件描述符被挂断；很多系统检测不到，使用EPOLLIN，read返回0，删除掉事件，关闭close(fd);
    EPOLLET： 将EPOLL设为边缘触发(Edge Triggered)模式，这是相对于水平触发(Level Triggered)来说的。
    EPOLLONESHOT：只监听一次事件，当监听完这次事件之后，如果还需要继续监听这个socket的话，需要再次把这个socket加入到EPOLL队列里
    */
    /*PRINT_ERROR("%s EPOLLIN %x, EPOLLOUT %x, EPOLLPRI %x, EPOLLERR %x, EPOLLRDHUP %x, EPOLLET %x, EPOLLONESHOT %x\n", \
        GetCurTimeStr(), EPOLLIN, EPOLLOUT, EPOLLPRI, EPOLLERR, EPOLLRDHUP, EPOLLET, EPOLLONESHOT);*/

    int nRet = 0;
    epoll_event events[MAX_EPOLL_EVENT];
    while (true)
    {
        int ret = epoll_wait(epollfd, events, MAX_EPOLL_EVENT, -1);
        if (ret < 0)
        {
            PRINT_ERROR("epoll_wait failure ret %d error %d\n", ret, errno);
            nRet = -1;
            break;
        }
        EpollRunET(epollfd, events, ret, sockListen, FireReadEvent, FireWriteEvent, FireCloseEvent);
    }
    return nRet;
}

bool EpollMoveSendPack(CLfrpSocket* pSrcSocket, CLfrpSocket* pDesSocket)
{
    bool bDestSend = false;
    if (pSrcSocket->nBufLen >= pSrcSocket->nPackLen && pSrcSocket->nPackLen > 0)
    {
        if (pDesSocket)
        {
            CBuffer buf;
            buf.nLen = pSrcSocket->nPackLen;
            buf.pBuffer = new char[pSrcSocket->nPackLen];
            FetchOnePack(pSrcSocket, buf.pBuffer);
            pDesSocket->vecSendBuf.push_back(buf);
            //pair.pVistor->Op = OP_WRITE;
            bDestSend = true;

            int nType, nPakLen, nSocketID, nSeq;
            GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
            PRINT_INFO("%s %s,%d: socketID %d trans pack from sockID %d to sockID %d type %d size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, \
                nSocketID, pSrcSocket->sock, pDesSocket->sock, nType, nPakLen, nSeq);

            // 如果源有多个数据包，一次转过去
            ParsePackHeader(pSrcSocket);
            if (pSrcSocket->nType >= PACK_TYPE_DATA_BEG && pSrcSocket->nType <= PACK_TYPE_DATA_END)
            {
                //MoveSendPack(pSrcSocket, pDesSocket); // nop
            }
            else if (pSrcSocket->nType >= PACK_TYPE_TUN_BEG && pSrcSocket->nType <= PACK_TYPE_TUN_END)
            {
                //MoveSendPack(pSrcSocket, pDesSocket); // nop
            }
            else if (pSrcSocket->nType == PACK_TYPE_HEART_BEAT)
            { // 中间如果有心跳包，取掉包进下一个循环
                DropOnePack(pSrcSocket);
                ParsePackHeader(pSrcSocket);
                //MoveSendPack(pSrcSocket, pDesSocket); // nop
            }
        }
    }
    return bDestSend;
}

int GetNextSeq(int nIndex, SeqEnum nType, int nSocketID)
{
    // 无效连接或者刚开始连接Seq都为0
    if (nSocketID == INVALID_SOCKET)
    {
        return 0;
    }

    int nRetSeq = 0;
    CSeqMap::iterator iter = pSeqMapAry[nIndex].find(nSocketID);
    if (iter == pSeqMapAry[nIndex].end())
    {
        int nSeqBeg = 0;
        if (nType == SEQ_CLIENT)
        {
            nSeqBeg = SEQ_CLIENT_BEG;
        }
        else
        {
            nSeqBeg = SEQ_SERVER_BEG;
        }
        nRetSeq = nSeqBeg;
        pSeqMapAry[nIndex].insert(std::make_pair(nSocketID, nSeqBeg + 1));
    }
    else
    {
        nRetSeq = iter->second;
        iter->second++;
    }
    return nRetSeq;
}

void RemoveSeqKey(int nIndex, int nSocketID)
{
    CSeqMap::iterator iter = pSeqMapAry[nIndex].find(nSocketID);
    if (iter != pSeqMapAry[nIndex].end())
    {
        pSeqMapAry[nIndex].erase(iter);
    }
}


/*
*  connect相关，指的是Cli和Svr连接Tun部分的connect管理
*/
std::vector<int> vecServieNumber;
std::vector<int> vecConnectSN;
std::condition_variable cvConnect;
std::mutex mtxConnect;
int nFlagConnect = 0;
void ConnectWorker(const char* pIPAddr, int nPort)
{
    vecConnectSN = vecServieNumber;
    while (true)
    {
        WorkerWait(cvConnect, mtxConnect, nFlagConnect);
        if (bExitPorcess)
        {
            return;
        }
        PRINT_INFO("%s %s,%d: ConnectWorker thread process %d connect count\n", GetCurTimeStr(), __FUNCTION__, __LINE__, vecConnectSN.size());
        nFlagConnect = 0;

        std::unique_lock<std::mutex> lock(mtxConnect);
        std::vector<int> vecTmpConnect = vecConnectSN;
        vecConnectSN.clear();
        lock.unlock();

        for (size_t i = 0; i < vecTmpConnect.size(); i++)
        {
            int nServiceNum = vecTmpConnect[i];
            struct sockaddr_in clientService;
            int nRet = 0;
            int sock = INVALID_SOCKET;
            CLfrpSocket* pSocket = new CLfrpSocket;
            if (pSocket)
            {
                pSocket->nServiceNumber = nServiceNum;
                if (PreConnectSocket(pSocket->sock, pIPAddr, nPort) != 0)
                {
                    pSocket->sock = INVALID_SOCKET;
                    PRINT_ERROR("%s connect() Tun Failed: %d\n", GetCurTimeStr(), WSAGetLastError());
                }
                else
                {
                    PRINT_INFO("%s %s,%d: ConnectWorker connect SocketID %d ServiceNumber %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, pSocket->nServiceNumber);
                    // 先把sock放到全局环境
                    sock = pSocket->sock;
                    AddSockToInstanceMap(sock, pSocket);    // 添加到实例，这里务必比SvrWrite先完成
                    SetServiceNum(sock, nServiceNum);
                    SetSockBySN(nServiceNum, sock);         // 设置SN到sock用于管理重连，这里务必比SvrWrite先完成

                    // 实际连接
                    int nRet = ProcssConnectSocket(pSocket->sock, pIPAddr, nPort);
                    nRet = EpollPostConnectSocket(epollfd, pSocket->sock, pIPAddr, nPort, nRet);
                    if (nRet < 0)
                    {
                        PRINT_ERROR("%s %s,%d: EpollPostConnectSocket error: %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet);
                        SetSockBySN(nServiceNum, INVALID_SOCKET);
                        CloseLfrpSocket(pSocket);
                        delete pSocket;
                        sock = INVALID_SOCKET;
                    }
                    else
                    {
                        FireTransEvent(sock);                   // 等待可写后，避免可写先完成，这里发个事件
                    }
                }
            }
            
            if (sock == INVALID_SOCKET)
            {
                //FireConnectEvent(nServiceNum);
                AddDelayReConnect(nServiceNum);
            }
        }
    }
}
int FireConnectEvent(int nServiceNum)
{
    if (nServiceNum != -1)
    {
        std::unique_lock<std::mutex> lock(mtxConnect);
        vecConnectSN.push_back(nServiceNum);
        lock.unlock();
    }
    WorkerNotify(cvConnect, mtxConnect, nFlagConnect, 1);

    return 0;
}

int AddDelayReConnect(int nServiceNum)
{
    unsigned int uSec = GetCurSecond();
    std::unique_lock<std::mutex> lock(mtxReConnect);
    std::map<int, unsigned int>::iterator iter = mapServiceNumToTime.find(nServiceNum);
    if (iter != mapServiceNumToTime.end())
    {
        iter->second = uSec;
    }
    else
    {
        mapServiceNumToTime.insert(std::make_pair(nServiceNum, uSec));
    }
    return 0;
}

int FireDelayReConnect()
{
    unsigned int uSec = GetCurSecond();
    // 找出超过5秒的重连
    std::unique_lock<std::mutex> lock(mtxReConnect);
    std::map<int, unsigned int> mapTmp = mapServiceNumToTime;
    for (std::map<int, unsigned int>::iterator iter = mapServiceNumToTime.begin(); iter != mapServiceNumToTime.end(); iter++)
    {
        if (uSec - iter->second >= 5)
        {
            mapTmp.insert(std::make_pair(iter->first, iter->second));
        }
    }
    
    for (std::map<int, unsigned int>::iterator iter = mapTmp.begin(); iter != mapTmp.end(); iter++)
    {
        std::map<int, unsigned int>::iterator iterTmp = mapServiceNumToTime.find(iter->first);
        if (iterTmp != mapServiceNumToTime.end())
        {
            mapServiceNumToTime.erase(iterTmp);
        }
    }
    lock.unlock();

    for (std::map<int, unsigned int>::iterator iter = mapTmp.begin(); iter != mapTmp.end(); iter++)
    {
        FireConnectEvent(iter->first);
    }

    return 0;
}

int AddDelayClose(int sock)
{
    unsigned int uSec = GetCurSecond();
    PRINT_INFO("%s %s,%d: add delay close socketID %d at second %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, uSec);
    std::unique_lock<std::mutex> lock(mtxDelayClose);
    std::map<int, unsigned int>::iterator iter = mapCloseSockToTime.find(sock);
    if (iter != mapCloseSockToTime.end())
    {
        iter->second = uSec;
    }
    else
    {
        mapCloseSockToTime.insert(std::make_pair(sock, uSec));
    }
    return 0;
}

int FireDelayClose()
{
    unsigned int uSec = GetCurSecond();
    // 找出超过3秒的关闭sock句柄
    std::vector<int> vecSock;
    std::unique_lock<std::mutex> lock(mtxDelayClose);
    for (std::map<int, unsigned int>::iterator iter = mapCloseSockToTime.begin(); iter != mapCloseSockToTime.end(); iter++)
    {
        // 延迟3秒即可，太长影响socket复用
        if (uSec - iter->second >= 3)  // todo，延迟3秒
        {
            vecSock.push_back(iter->first);
        }
    }

    for (std::vector<int>::iterator iter = vecSock.begin(); iter != vecSock.end(); iter++)
    {
        std::map<int, unsigned int>::iterator iterMap = mapCloseSockToTime.find(*iter);
        if (iterMap != mapCloseSockToTime.end())
        {
            mapCloseSockToTime.erase(iterMap);
        }
    }
    lock.unlock();

    // 先主线程直接关闭，后续再考虑性能优化
    for (std::vector<int>::iterator iter = vecSock.begin(); iter != vecSock.end(); iter++)
    {
        PRINT_INFO("%s %s,%d: add delay close socketID %d at second %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, *iter, uSec);
        close(*iter);
    }

    return 0;
}

void InitTimer(int epollfd)
{
    // 创建一个定时器文件描述符
    //timerfd = timerfd_create(CLOCK_REALTIME, 0);
    timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (timerfd < 0) {
        perror("timerfd_create error");
        exit(1);
    }

    // 设置定时器的超时时间
    struct itimerspec ts;
    ts.it_value.tv_sec = 1;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = 1; //时间间隔
    ts.it_interval.tv_nsec = 0;
    timerfd_settime(timerfd, 0, &ts, NULL);

    // 将定时器文件描述符加入到epoll监听列表中
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = timerfd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &ev);
}

int CommTimer()
{
    uint64_t exp = 0;
    int ret = read(timerfd, &exp, sizeof(uint64_t));
    if (ret != sizeof(uint64_t))
    {
        PRINT_ERROR("%s %s,%d: CommTimer error\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
    }
    else
    {
        PRINT_INFO("%s %s,%d: CommTimer %lu\n", GetCurTimeStr(), __FUNCTION__, __LINE__, exp);
    }

    FireDelayReConnect();
    FireDelayClose();
    return 0;
}

int SendSNHeartBeat(int sock)
{
    int nServiceNum = GetServiceNum(sock);
    int nSNSock = GetSockBySN(nServiceNum);
    if (nSNSock == sock)
    { // 处理通道心跳
        CLfrpSocket* pSock = GetSockFromInstanceMap(sock);
        if (pSock)
        {
            CBuffer buf;
            MakeHeartBeatPack(buf);
            pSock->vecSendBuf.push_back(buf);
            FireWriteEvent(sock);
        } 
    }

    return 0;
}

#endif // USE_EPOLL