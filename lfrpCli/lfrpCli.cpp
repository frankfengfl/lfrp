// lfrpCli.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include "../global.h"
#include "../aes.h"
#include "../globalEpoll.h"

#pragma comment(lib,"ws2_32.lib")

// 本地服务信息
std::string strSvr = "127.0.0.1";
int nSvrPort = 12345;
// 通道服务信息
std::string strTun = "127.0.0.1";
int nTunPort = 6868;
// Business服务编号
int nServiceNumber = 1;
// AES key
std::string strAesKey = "asdf1234567890";

// 客户侧连接失败，需要通知服务侧清掉这条连接
void DoBusSocketErr(CLfrpSocket* pSocket, CLfrpSocket* pTunSocket)
{
    CSendBuffer buf;
    int nSeq = GetNextSeq(SEQ_CLIENT, pSocket->sock);
    RemoveSeqKey(pSocket->sock);
    MakeDataEndPack(buf, pSocket->nSocketID, nSeq);
    if (pTunSocket && pTunSocket->sock != INVALID_SOCKET)
    {
        pTunSocket->vecSendBuf.push_back(buf);
        pTunSocket->Op = OP_WRITE;
    }
}

int ProcessRead(CLfrpSocket* pTunSocket, CSocketMap& mapLocalSvr, fd_set& fdRead)
{
    int nFunRet = 0;
    if (FD_ISSET(pTunSocket->sock, &fdRead))
    {
        int nRet = LfrpRecv(pTunSocket, RECORD_TYPE_TUN_RECV);
        if (nRet <= 0)
        {
            PRINT_ERROR("%s Cli %s,%d: Tun SocketID %d disconnect because read err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->sock, nRet, WSAGetLastError());
            CloseLfrpSocket(pTunSocket);
            // 通道关闭，所有客户侧连接清掉
            for (CSocketMap::iterator iter = mapLocalSvr.begin(); iter != mapLocalSvr.end(); iter++)
            {
                if (iter->second->sock != INVALID_SOCKET)
                {
                    PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because tun socket disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                    CloseLfrpSocket(iter->second);
                    delete iter->second;
                }
            }
            mapLocalSvr.clear();
            nFunRet = -1;
        }
        else
        {
            // 包收完全了
            while (pTunSocket->nBufLen >= pTunSocket->nPackLen && pTunSocket->nPackLen > 0)
            {
                PRINT_INFO("%s Cli %s,%d: Tun recv socketID %d pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->nSocketID, nRet, pTunSocket->nPackSeq);
                if (pTunSocket->nType == PACK_TYPE_DATA_END)
                { // 客户端断开
                    CSocketMap::iterator iter = mapLocalSvr.find(pTunSocket->nSocketID);
                    if (iter != mapLocalSvr.end())
                    {
                        PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because Cli send DataEnd\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                        // 服务侧断开，也要同时断开业务侧连接
                        RemoveSeqKey(iter->second->sock);  // 客户端断开，从map中删除
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                        mapLocalSvr.erase(iter);
                    }

                    // 取掉结束包
                    DropOnePack(pTunSocket);
                }
                else if (pTunSocket->nType > PACK_TYPE_DATA_BEG && pTunSocket->nType <= PACK_TYPE_DATA_END)
                {
                    CSocketMap::iterator iter = mapLocalSvr.find(pTunSocket->nSocketID);
                    if (iter != mapLocalSvr.end())
                    {
                        CLfrpSocket* pSocket = iter->second;
                        if (pSocket->sock != INVALID_SOCKET)
                        {
                            PRINT_INFO("%s Cli %s,%d: Tun send pack to Server\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                            if (MoveSendPack(pTunSocket, pSocket))
                            {
                                pSocket->Op = OP_WRITE;
                            }
                        }
                    }
                    else
                    {
                        // 客户侧连接失败，需要通知服务侧清掉这条连接，此时SocketID用包里的，seq为0
                        //DoBusSocketErr(pSocket, pTunSocket);
                        CSendBuffer buf;
                        MakeDataEndPack(buf, pTunSocket->nSocketID, 0);
                        if (pTunSocket && pTunSocket->sock != INVALID_SOCKET)
                        {
                            pTunSocket->vecSendBuf.push_back(buf);
                            pTunSocket->Op = OP_WRITE;
                        }

                        // 没有对应端，取掉包
                        DropOnePack(pTunSocket); 
                    }
                }
                else if (pTunSocket->nType == PACK_TYPE_TUN_END)
                { // 服务端通道整个断开，清掉所有相关业务连接；其实server异常了，也会同步关闭vistor，不会收到这条
                    for (CSocketMap::iterator iter = mapLocalSvr.begin(); iter != mapLocalSvr.end(); iter++)
                    {
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                    }
                    mapLocalSvr.clear();

                    // 取掉结束包
                    DropOnePack(pTunSocket);
                }
                else if (pTunSocket->nType == PACK_TYPE_HEART_BEAT)
                { // 心跳包
                    // 取掉包
                    DropOnePack(pTunSocket);
                }
                else
                { // 不认识的包
                    PRINT_ERROR("%s Svr %s,%d: receive illeage packe type %d size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->nType, pTunSocket->nPackLen);
                    DropOnePack(pTunSocket);
                }
            }
        }
    }

    CSocketVec vecDelSocket;
    for (CSocketMap::iterator iter = mapLocalSvr.begin(); iter != mapLocalSvr.end(); iter++)
    {
        CLfrpSocket* pSocket = iter->second;
        if (pSocket->sock != INVALID_SOCKET)
        {
            if (FD_ISSET(pSocket->sock, &fdRead))
            {
                char Buffer[RECV_BUFFER_SIZE];
                int nRet = recv(pSocket->sock, Buffer, RECV_BUFFER_SIZE, 0);
                if (nRet == SOCKET_ERROR || nRet == 0)
                {
                    int nLastErr = WSAGetLastError();
                    // todo，错误码未测试
                    //if (nRet == SOCKET_ERROR && (nLastErr == EAGAIN || nLastErr == EWOULDBLOCK || nLastErr == WSAEWOULDBLOCK || nLastErr == EINTR))
                    //{ //没有数据
                    //    continue;
                    //}
                    PRINT_ERROR("%s Cli %s,%d: Svr SocketID %d disconnect because read err %x wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet, nLastErr);
                    // 客户侧连接失败，需要通知服务侧清掉这条连接
                    DoBusSocketErr(pSocket, pTunSocket);
                    CloseLfrpSocket(pSocket);
                    vecDelSocket.push_back(pSocket);
                    nFunRet = -1;
                }
                else if (nRet > 0)
                {
                    //RecordSocketData(RECORD_TYPE_BUS_RECV, pSocket->sock, Buffer, nRet);
                    pSocket->nLastRecvSec = GetCurSecond();
                    int nSeq = GetNextSeq(SEQ_CLIENT, pSocket->sock);
                    PRINT_INFO("%s Cli %s,%d: Svr socketID %d recv pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet, nSeq);

                    CSendBuffer buf;
                    buf.pBuffer = new char[PACK_SIZE_DATA + nRet];
                    buf.nLen = PACK_SIZE_DATA + nRet;
                    int* pData = (int*)buf.pBuffer;
                    pData[0] = MAGIC_NUMBER;
                    pData[1] = PACK_TYPE_DATA;
                    pData[2] = buf.nLen;
                    pData[3] = pSocket->sock;
                    pData[4] = nSeq;
                    memcpy(buf.pBuffer + PACK_SIZE_DATA, Buffer, nRet);
                    pTunSocket->vecSendBuf.push_back(buf);
                    pTunSocket->Op = OP_WRITE;
                }
            }
        }
    }

    //删掉无效的连接
    for (int i = 0; i < vecDelSocket.size(); i++)
    {
        if (vecDelSocket[i])
        {
            for (CSocketMap::iterator iter = mapLocalSvr.begin(); iter != mapLocalSvr.end(); iter++)
            {
                if (vecDelSocket[i] == iter->second)
                {
                    mapLocalSvr.erase(iter);
                    break;
                }
            }
            delete vecDelSocket[i];
        }
    }

    return nFunRet;
}

int ProcessWrite(CLfrpSocket* pTunSocket, CSocketMap& mapSvr, fd_set& fdWrite)
{
    int nFunRet = 0;
    int nRet = 0;
    if (pTunSocket->sock != INVALID_SOCKET && FD_ISSET(pTunSocket->sock, &fdWrite))
    {
        if (pTunSocket->Op == OP_WRITE)
        {
            for (int i = 0; i < pTunSocket->vecSendBuf.size(); i++)
            {
                CSendBuffer& buf = pTunSocket->vecSendBuf[i];

                int nType, nPakLen, nSocketID, nSeq;
                GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                PRINT_INFO("%s Cli %s,%d: Tun send socketID %d pack to TunServer size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen, nSeq);

                // 发送前加密
                char* pSendBuffer = buf.pBuffer;
                int nSendLen = buf.nLen;
#ifdef USE_AES
                CAES cAes;
                pSendBuffer = (char*)cAes.Encrypt(buf.pBuffer, buf.nLen, nSendLen, true);
#endif

                //开始send
                //nRet = send(pTunSocket->sock, pSendBuffer, nSendLen, LFRP_SEND_FLAGS);
                int nSendIndex = 0;
                nRet = send(pTunSocket->sock, pSendBuffer + nSendIndex, nSendLen - nSendIndex, LFRP_SEND_FLAGS);
                while ((nRet > 0 && nRet < nSendLen - nSendIndex) || (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError())))
                { // 缓冲区堵塞等一下重发
                    if (nRet > 0 && nRet < nSendLen - nSendIndex)
                    {
                        PRINT_ERROR("%s Cli %s,%d: send to Tun err size %d send %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSendLen, nRet);
                        nSendIndex += nRet;
                    }
                    else if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                    {
                        PRINT_ERROR("%s Cli %s,%d: send to Tun err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSendLen);
                        Sleep(1);
                    }
                    nRet = send(pTunSocket->sock, pSendBuffer + nSendIndex, nSendLen - nSendIndex, LFRP_SEND_FLAGS);
                }
                //RecordSocketData(RECORD_TYPE_TUN_SEND, pTunSocket->sock, pSendBuffer, nSendLen);
#ifdef USE_AES
                delete[] pSendBuffer;
#endif
                delete[] buf.pBuffer;
                buf.pBuffer = nullptr;
                buf.nLen = 0;
                //事实上，这里可能会有nRet小于bufLen的情况
                if (nRet == SOCKET_ERROR || nRet == 0)
                {
                    PRINT_ERROR("%s Cli %s,%d: Tun SocketID %d disconnect because send err %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->sock, nRet);
                    // Server关闭了
                    CloseLfrpSocket(pTunSocket);
                    // 通道关闭，所有客户侧连接清掉
                    for (CSocketMap::iterator iter = mapSvr.begin(); iter != mapSvr.end(); iter++)
                    {
                        if (iter->second->sock != INVALID_SOCKET)
                        {
                            PRINT_ERROR("%s Cli %s,%d: Svr SocketID %d disconnect because tun socket disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                            CloseLfrpSocket(iter->second);
                            delete iter->second;
                        }
                    }
                    mapSvr.clear();
                    nFunRet = -1;
                    break; // socket异常不发剩余数据
                }
            }
            pTunSocket->vecSendBuf.clear();
            pTunSocket->Op = OP_READ;
        }
    }

    CSocketVec vecDelSocket;
    for (CSocketMap::iterator iter = mapSvr.begin(); iter != mapSvr.end(); iter++)
    {
        CLfrpSocket* pSocket = iter->second;
        if (pSocket->sock != INVALID_SOCKET)
        {
            if (pSocket->Op == OP_WRITE)
            {
                for (int i = 0; i < pSocket->vecSendBuf.size(); i++)
                {
                    CSendBuffer& buf = pSocket->vecSendBuf[i];
                    if (buf.nLen > PACK_SIZE_DATA)
                    {
                        int nType, nPakLen, nSocketID, nSeq;
                        GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                        PRINT_INFO("%s Cli %s,%d: Svr send socketID %d pack to User size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen - PACK_SIZE_DATA, nSeq);

                        //开始send
                        //nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA, buf.nLen - PACK_SIZE_DATA, LFRP_SEND_FLAGS);
                        int nSendIndex = 0;
                        nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA + nSendIndex, buf.nLen - PACK_SIZE_DATA - nSendIndex, LFRP_SEND_FLAGS);
                        while ((nRet > 0 && nRet < buf.nLen - PACK_SIZE_DATA - nSendIndex) || (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError())))
                        { // 缓冲区堵塞等一下重发
                            if (nRet > 0 && nRet < buf.nLen - PACK_SIZE_DATA - nSendIndex)
                            {
                                PRINT_ERROR("%s Cli %s,%d: send to User err size %d send %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen - PACK_SIZE_DATA, nRet);
                                nSendIndex += nRet;
                            }
                            else if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                            {
                                PRINT_ERROR("%s Cli %s,%d: send to User err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen - PACK_SIZE_DATA);
                                Sleep(1);
                            }
                            nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA + nSendIndex, buf.nLen - PACK_SIZE_DATA - nSendIndex, LFRP_SEND_FLAGS);
                        }
                        //RecordSocketData(RECORD_TYPE_BUS_SEND, pSocket->sock, buf.pBuffer + PACK_SIZE_DATA, buf.nLen - PACK_SIZE_DATA);
                        //事实上，这里可能会有nRet小于bufLen的情况
                        if (nRet == SOCKET_ERROR || nRet == 0)
                        {
                            PRINT_ERROR("%s Cli %s,%d: Svr SocketID %d disconnect because send err %x wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet, WSAGetLastError());
                            // 客户侧连接失败，需要通知服务侧清掉这条连接
                            DoBusSocketErr(pSocket, pTunSocket);
                            CloseLfrpSocket(pSocket);
                            vecDelSocket.push_back(pSocket);
                            nFunRet = -1;
                            break; // socket异常不发剩余数据
                        }
                    }
                    delete[] buf.pBuffer;
                    buf.pBuffer = nullptr;
                    buf.nLen = 0;
                }
                pSocket->vecSendBuf.clear();
                pSocket->Op = OP_READ;
            }
        }
    }

    //删掉无效的连接
    for (int i = 0; i < vecDelSocket.size(); i++)
    {
        if (vecDelSocket[i])
        {
            for (CSocketMap::iterator iter = mapSvr.begin(); iter != mapSvr.end(); iter++)
            {
                if (vecDelSocket[i] == iter->second)
                {
                    mapSvr.erase(iter);
                    break;
                }
            }
            delete vecDelSocket[i];
        }
    }

    return nFunRet;
}

void SendTunLogin(CLfrpSocket* pTunSocket)
{
    CSendBuffer buf;
    buf.pBuffer = new char[PACK_SIZE_AUTH];
    buf.nLen = PACK_SIZE_AUTH;
    int* pData = (int*)buf.pBuffer;
    pData[0] = MAGIC_NUMBER;
    pData[1] = PACK_TYPE_AUTH_VISTOR;
    pData[2] = PACK_SIZE_AUTH;
#ifdef USE_EPOLL
    pData[3] = pTunSocket->nServiceNumber;
#else
    pData[3] = nServiceNumber;
#endif
    pTunSocket->vecSendBuf.push_back(buf);
    pTunSocket->Op = OP_WRITE;
}

void SendNewClientBegin(CLfrpSocket* pSocket, CLfrpSocket* pTunSocket)
{
    CSendBuffer buf;
    buf.pBuffer = new char[PACK_SIZE_DATA_BEG];
    buf.nLen = PACK_SIZE_DATA_BEG;
    int* pData = (int*)buf.pBuffer;
    pData[0] = MAGIC_NUMBER;
    pData[1] = PACK_TYPE_DATA_BEG;
    pData[2] = PACK_SIZE_DATA_BEG;
    pData[3] = pSocket->sock;
    pData[4] = GetNextSeq(SEQ_CLIENT, pSocket->sock);
    pTunSocket->vecSendBuf.push_back(buf);
    pTunSocket->Op = OP_WRITE;
}

int mainSelect(SOCKET& sockListen)
{
    int nRet = 0;
    CLfrpSocket sockTun;
    CSocketMap mapSvr;    // 业务服务代理连接

    if (ConnectSocket(sockTun.sock, strTun.c_str(), nTunPort) != 0)
    {
        sockTun.sock = INVALID_SOCKET;
        printf("%s connect() Tun Failed: %d\n", GetCurTimeStr(), WSAGetLastError());
    }
    else
    {
        SendTunLogin(&sockTun);
    }

    unsigned int uLastTunSec = GetCurSecond();
    unsigned int uLastHeartBeatSec = GetCurSecond();
    CLfrpSocket sListen;
    sListen.sock = sockListen;
    while (true)
    {
        //循环判断是否有请求需要处理
        fd_set fdRead, fdWrite;
        while (true)
        {
            bool bSetFD = false;
            FD_ZERO(&fdRead);
            FD_ZERO(&fdWrite);
            FD_SET(sListen.sock, &fdRead);
            SOCKET maxSock = sListen.sock;
            if (sockTun.sock != INVALID_SOCKET)
            {
                LfrpSetFD(&sockTun, fdRead, fdWrite);
                maxSock = max(maxSock, sockTun.sock);
                bSetFD = true;
            }
            for (CSocketMap::iterator iter = mapSvr.begin(); iter != mapSvr.end(); iter++)
            {
                CLfrpSocket* pSocket = iter->second;
                if (pSocket && pSocket->sock != INVALID_SOCKET)
                {
                    LfrpSetFD(pSocket, fdRead, fdWrite);
                    maxSock = max(maxSock, pSocket->sock);
                    bSetFD = true;
                }
            }

            if (bSetFD)
            {
                timeval timevalSelect = { 5, 0 };
                //这个操作会被阻塞
#ifdef _WIN32
                nRet = select(0, &fdRead, &fdWrite, NULL, &timevalSelect);
#else
                nRet = select(maxSock + 1, &fdRead, &fdWrite, NULL, &timevalSelect);
#endif
                if (nRet == 0)
                {
                    unsigned int uSec = GetCurSecond();
                    if (sockTun.sock != INVALID_SOCKET && uSec - uLastHeartBeatSec > 10)
                    { // 10秒心跳
                        uLastHeartBeatSec = uSec;
                        CSendBuffer buf;
                        MakeHeartBeatPack(buf);
                        sockTun.vecSendBuf.push_back(buf);
                        sockTun.Op = OP_WRITE;
                    }
                }

                if (FD_ISSET(sockListen, &fdRead))
                {
                    //socket可用了，这时accept一定会立刻返回成功或失败 这里需要处理最大连接数
                    SOCKET sockNewClient = accept(sockListen, NULL, NULL);
                    if (sockNewClient != INVALID_SOCKET)
                    {
                        PRINT_ERROR("%s Cli %s,%d: accept new socketID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sockNewClient);

                        int enable = 1;
                        if (setsockopt(sockNewClient, IPPROTO_TCP, TCP_NODELAY, (char*)&enable, sizeof(enable)) == SOCKET_ERROR)
                        {
                            PRINT_ERROR("%s Cli %s,%d: accept socket setopt TCP_NODELAY error\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                        }

                        CLfrpSocket* pSocket = new CLfrpSocket;
                        pSocket->sock = sockNewClient;
                        pSocket->nSocketID = sockNewClient;
                        mapSvr.insert(std::make_pair(pSocket->nSocketID, pSocket));
                        SendNewClientBegin(pSocket, &sockTun);
                    }
                    //break;
                }

                //其他socket可用了，判断哪些能读，哪些能写
#ifdef _WIN32
                if (fdRead.fd_count > 0)
#endif
                {
                    nRet = ProcessRead(&sockTun, mapSvr, fdRead);
                }
#ifdef _WIN32
                if (fdWrite.fd_count > 0)
#endif
                {
                    nRet |= ProcessWrite(&sockTun, mapSvr, fdWrite);
                }
            }
            else
            {
                nRet = -1;
            }

            //if (nRet == -1)
            {
                // 没有业务，释放CPU
                if (!bSetFD)
                {
                    Sleep(1);
                }

                unsigned int uSec = GetCurSecond();
                // 通道连接失败要重连，但需要有间隔
                if (sockTun.sock == INVALID_SOCKET && uSec - uLastTunSec > 5)
                {
                    PRINT_ERROR("%s Cli %s,%d: ConnectSocket %s:%d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, strTun.c_str(), nTunPort);
                    if (ConnectSocket(sockTun.sock, strTun.c_str(), nTunPort) != 0)
                    {
                        sockTun.sock = INVALID_SOCKET;
                        printf("%s reconnect() Tun Failed: %d\n", GetCurTimeStr(), WSAGetLastError());
                        //return -1;
                    }
                    else
                    {
                        sockTun.ClearBuffer();  //  bind在timewait时会进这里，但实际发不出去，等后面真连成功会有多个认证包
                        SendTunLogin(&sockTun);
                    }
                    uLastTunSec = uSec;
                }
            }
        }
    }

    return 0;
}

#ifdef USE_EPOLL
#include <atomic>
CSocketMap* pSvrMapAry = nullptr;
std::atomic<int> nCliVIDCreator(0);

void SendNewClientBegin(int nIndex, CLfrpSocket* pSocket, CLfrpSocket* pTunSocket)
{
    CSendBuffer buf;
    buf.pBuffer = new char[PACK_SIZE_DATA_BEG];
    buf.nLen = PACK_SIZE_DATA_BEG;
    buf.uCreateTime = GetCurMilliSecond();
    int* pData = (int*)buf.pBuffer;
    pData[0] = MAGIC_NUMBER;
    pData[1] = PACK_TYPE_DATA_BEG;
    pData[2] = PACK_SIZE_DATA_BEG;
    pData[3] = pSocket->nSocketID;
    pData[4] = GetNextSeq(nIndex, SEQ_CLIENT, pSocket->sock);
    pTunSocket->vecSendBuf.push_back(buf);
    pTunSocket->Op = OP_WRITE;
}

void DoBusSocketErr(int nIndex, CLfrpSocket* pSocket, CLfrpSocket* pTunSocket)
{
    CSendBuffer buf;
    buf.uCreateTime = GetCurMilliSecond();
    int nSeq = GetNextSeq(SEQ_CLIENT, pSocket->sock);
    RemoveSeqKey(nIndex, pSocket->sock);
    MakeDataEndPack(buf, pSocket->nSocketID, nSeq);
    if (pTunSocket && pTunSocket->sock != INVALID_SOCKET)
    {
        pTunSocket->vecSendBuf.push_back(buf);
        //pTunSocket->Op = OP_WRITE;
        FireWriteEvent(pTunSocket->sock);
    }
}

int GetCliServiceNum(CLfrpSocket* pSocket)
{
    // 根据sock决定使用那个ServiceNumber，虽然通道使用VID，但这个是工作线程分配，不影响
    return vecServieNumber[abs(pSocket->sock) % vecServieNumber.size()];
}
int GetCliThreadIndex(CLfrpSocket* pSocket)
{
    // 根据ServiceNumber决定ThreadIndex
    return GetCliServiceNum(pSocket) % nThreadCount;
}
// 注意CliPostAccept是主线程调用，尽量简单；另外这个需要比EpollAdd早，可以在所有消息之前处理事件
int CliPostAccept(CLfrpSocket* pSocket)
{
    if (pSocket == nullptr)
        return -1;

    //pSocket->nSocketID = pSocket->sock;             // 设置nSocketID
    pSocket->nSocketID = nCliVIDCreator++;
    if (pSocket->nSocketID == INVALID_SOCKET)
    { // 0是默认值，不使用，循环到了重新分配
        pSocket->nSocketID = nCliVIDCreator++;
    }
    pSocket->nServiceNumber = GetCliServiceNum(pSocket);
    // 因为这个比EpollAdd早，所以socket可用的Fire肯定比这个晚，在Trans里做预处理
    SetServiceNum(pSocket->sock, pSocket->nServiceNumber);
    PRINT_INFO("%s %s,%d: SocketID %d use VID %d ServiceNum %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, pSocket->nSocketID, pSocket->nServiceNumber);
    FireTransEvent(pSocket->sock); 
    return 0;
}

// 转换用于通道登录或客户端Accept后处理(Accept后处理早于所有socket实际事件)
int CliTrans(int nIndex, int sock, CLfrpSocket* pSocket)
{
    if (pSocket == nullptr)
    {
        pSocket = GetSockFromInstanceMap(sock);
    }
    if (pSocket == nullptr)
    {
        PRINT_ERROR("%s %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return 0;
    }

    int nServiceNum = GetServiceNum(sock);
    int nSNSock = GetSockBySN(nServiceNum);
    if (nSNSock == sock)
    { // 处理通道连接
        pSocket->Op |= OP_TRANS;
        if (pSocket->Op | OP_WRITE)
        {
            PRINT_INFO("%s Cli %s,%d: Tun socketID %d prepare to SendTunLogin\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
            SendTunLogin(pSocket);
            pSocket->Op = 0;
            FireWriteEvent(sock);
        }
    }
    else
    { // 处理PostAccept
        pSvrMapAry[nIndex].insert(std::make_pair(pSocket->nSocketID, pSocket));

        int nServiceNum = -1;
        if (pSocket)
        {
            nServiceNum = pSocket->nServiceNumber; //  GetCliServiceNum(pSocket);
        }
        else
        {
            nServiceNum = GetServiceNum(sock);
        }
        PRINT_INFO("%s %s,%d: SocketID %d ServiceNum %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->nSocketID, nServiceNum);
        int nSNSock = GetSockBySN(nServiceNum);
        CLfrpSocket* pSNSocket = GetSockFromInstanceMap(nSNSock);
        if (pSNSocket)
        {
            PRINT_INFO("%s %s,%d: SocketID %d send tun SocketID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->nSocketID, pSNSocket->sock);
            SendNewClientBegin(nIndex, pSocket, pSNSocket);
            FireWriteEvent(pSNSocket->sock);
        }
    }

    return 0;
}

int CliRead(int nIndex, int sock, char* pBuffer, int nCount)
{
    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (pSocket == nullptr)
    {
        PRINT_ERROR("%s Tun %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return 0;
    }

    int nServiceNum = GetServiceNum(sock);
    int nSNSock = GetSockBySN(nServiceNum);
    if (nSNSock == sock)
    { // 处理通道连接
        CLfrpSocket* pTunSocket = pSocket;
        CSocketMap& mapLocalSvr = pSvrMapAry[nIndex];
        PRINT_INFO("%s Cli %s,%d: Tun recv sock %d buf size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nCount);
        RecordSocketData(RECORD_TYPE_TUN_RECV, sock, pBuffer, nCount);
        int nRet = AddAESRecvData(pTunSocket, pBuffer, nCount);
        if (nRet <= 0)
        {
            PRINT_ERROR("%s Cli %s,%d: Tun SocketID %d disconnect because read err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->sock, nRet, WSAGetLastError());
            CloseLfrpSocket(pTunSocket);
            // 通道关闭，所有客户侧连接清掉
            for (CSocketMap::iterator iter = mapLocalSvr.begin(); iter != mapLocalSvr.end(); iter++)
            {
                if (iter->second->sock != INVALID_SOCKET)
                {
                    PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because tun socket disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                    CloseLfrpSocket(iter->second);
                    delete iter->second;
                }
            }
            mapLocalSvr.clear();

            // 发送通道重连通知
            FireConnectEvent(nServiceNum);  // 通道临时问题，需要马上重连，重连失败的才延迟
            //AddDelayReConnect(nServiceNum);
        }
        else
        {
            // 包收完全了
            while (pTunSocket->nBufLen >= pTunSocket->nPackLen && pTunSocket->nPackLen > 0)
            {
                PRINT_INFO("%s Cli %s,%d: Tun recv sock %d socketID %d pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, pTunSocket->nSocketID, nRet, pTunSocket->nPackSeq);
                if (pTunSocket->nType == PACK_TYPE_DATA_END)
                { // 客户端断开
                    CSocketMap::iterator iter = mapLocalSvr.find(pTunSocket->nSocketID);
                    if (iter != mapLocalSvr.end())
                    {
                        PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because Cli send DataEnd\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                        // 服务侧断开，也要同时断开业务侧连接
                        RemoveSeqKey(nIndex, iter->second->sock);  // 客户端断开，从map中删除
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                        mapLocalSvr.erase(iter);
                    }

                    // 取掉结束包
                    DropOnePack(pTunSocket);
                }
                else if (pTunSocket->nType > PACK_TYPE_DATA_BEG && pTunSocket->nType <= PACK_TYPE_DATA_END)
                {
                    CSocketMap::iterator iter = mapLocalSvr.find(pTunSocket->nSocketID);
                    if (iter != mapLocalSvr.end())
                    {
                        CLfrpSocket* pSocket = iter->second;
                        if (pSocket->sock != INVALID_SOCKET)
                        {
                            PRINT_INFO("%s Cli %s,%d: Tun send pack to Server\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                            if (EpollMoveSendPack(pTunSocket, pSocket)) // Epoll复用Tun，收到的每个包pTunSocket->nSocketID可能变
                            {
                                //pSocket->Op = OP_WRITE;
                                FireWriteEvent(pSocket->sock);
                            }
                        }
                    }
                    else
                    {
                        // 客户侧连接失败，需要通知服务侧清掉这条连接，此时SocketID用包里的，seq为0
                        //DoBusSocketErr(nIndex, pSocket, pTunSocket);
                        CSendBuffer buf;
                        buf.uCreateTime = GetCurMilliSecond();
                        MakeDataEndPack(buf, pTunSocket->nSocketID, 0);
                        if (pTunSocket && pTunSocket->sock != INVALID_SOCKET)
                        {
                            pTunSocket->vecSendBuf.push_back(buf);
                            //pTunSocket->Op = OP_WRITE;
                            FireWriteEvent(pTunSocket->sock);
                        }

                        // 没有对应端，取掉包
                        DropOnePack(pTunSocket);
                    }
                }
                else if (pTunSocket->nType == PACK_TYPE_TUN_END)
                { // 服务端通道整个断开，清掉所有相关业务连接；其实server异常了，也会同步关闭vistor，不会收到这条
                    for (CSocketMap::iterator iter = mapLocalSvr.begin(); iter != mapLocalSvr.end(); iter++)
                    {
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                    }
                    mapLocalSvr.clear();

                    // 取掉结束包
                    DropOnePack(pTunSocket);
                }
                else if (pTunSocket->nType == PACK_TYPE_HEART_BEAT)
                { // 心跳包
                    // 取掉包
                    DropOnePack(pTunSocket);
                }
                else
                { // 不认识的包
                    PRINT_ERROR("%s Svr %s,%d: receive illeage packe type %d size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->nType, pTunSocket->nPackLen);
                    DropOnePack(pTunSocket);
                }
            }
        }
    }
    else
    { // 业务连接收到数据
        CLfrpSocket* pTunSocket = GetSockFromInstanceMap(nSNSock);
        if (pTunSocket)
        {
            pSocket->nLastRecvSec = GetCurSecond();
            int nSeq = GetNextSeq(nIndex, SEQ_CLIENT, pSocket->sock);
            //PRINT_INFO("%s Cli %s,%d: Svr socketID %d recv pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nCount, nSeq);
            // todo, 注释掉下面的代码
            //std::string str(pBuffer, nCount);
            //PRINT_INFO("%s Cli %s,%d: Svr socketID %d recv pack size %d:%s seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->nSocketID, nCount, str.c_str(), nSeq);

            CSendBuffer buf;
            buf.pBuffer = new char[PACK_SIZE_DATA + nCount];
            buf.nLen = PACK_SIZE_DATA + nCount;
            buf.uCreateTime = GetCurMilliSecond();
            int* pData = (int*)buf.pBuffer;
            pData[0] = MAGIC_NUMBER;
            pData[1] = PACK_TYPE_DATA;
            pData[2] = buf.nLen;
            pData[3] = pSocket->nSocketID;
            pData[4] = nSeq;
            memcpy(buf.pBuffer + PACK_SIZE_DATA, pBuffer, nCount);
            pTunSocket->vecSendBuf.push_back(buf);
            //pTunSocket->Op = OP_WRITE;

            // todo, 可能连接业务的connect还没完全，发送写事件导致Svr服务异常，需要Svr连接完成后发回到Cli置状态
            FireWriteEvent(pTunSocket->sock);
        }
    }
    return 0;
}

int CliWrite(int nIndex, int sock)
{
    PRINT_INFO("%s Cli %s,%d: socketID %d CliWrite\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);

    int nRet = 0;
    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (pSocket == nullptr)
    {
        PRINT_INFO("%s Tun %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return 0;
    }

    int nServiceNum = GetServiceNum(sock);
    if (nServiceNum == -1)
    {
        int nThreadIndex = GetThreadIndexByNum(nServiceNum);
        if (nThreadIndex != nIndex)
        { // Socket可用会收到可读和可写，可读会trans，但第一个可写会进这里不匹配
            return 0;
        }
    }

    int nSNSock = GetSockBySN(nServiceNum);
    CSocketMap& mapSvr = pSvrMapAry[nIndex];
    if (nSNSock == sock)
    { // 处理通道连接
        pSocket->Op |= OP_WRITE;
        if (pSocket->Op & OP_TRANS)
        {
            PRINT_INFO("%s Cli %s,%d: Tun socketID %d prepare to SendTunLogin\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
            SendTunLogin(pSocket);
            pSocket->Op = 0;
            FireWriteEvent(sock);
        }
        else
        {
            bool nError = false;
            CLfrpSocket* pTunSocket = pSocket;
            for (int i = 0; i < pTunSocket->vecSendBuf.size(); i++)
            {
                CSendBuffer& buf = pTunSocket->vecSendBuf[i];

                int nType, nPakLen, nSocketID, nSeq;
                GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                PRINT_INFO("%s Cli %s,%d: Tun send socketID %d pack to TunServer size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen, nSeq);

                // 判断所在socket是否正常，数据是否需要发送
                //CLfrpSocket* pSocket = GetSockFromInstanceMap(nSocketID);
                //if (pSocket)
                //{ // 
                //    //uint64_t uTimeRange = buf.uCreateTime - pSocket->uCreateTime;
                //    //if (uTimeRange > 0x7FFFFFFF )
                //    //{ // buf创建时间比socket创建还要早（负数转成大正数），是复用socket导致，需要丢弃
                //    //    // todo, 下面注释改成INFO级别
                //    //    PRINT_ERROR("%s Cli %s,%d: socketID %d resued\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID);
                //    //    delete[] buf.pBuffer;
                //    //    continue;
                //    //}
                //}
                //else
                //{ // 如果socket已经销毁，不需要发送
                //    delete[] buf.pBuffer;
                //    continue;
                //}

                // 发送前加密
                char* pSendBuffer = buf.pBuffer;
                int nSendLen = buf.nLen;
#ifdef USE_AES
                CAES cAes;
                pSendBuffer = (char*)cAes.Encrypt(buf.pBuffer, buf.nLen, nSendLen, true);
#endif
                //开始send
                nRet = send(pTunSocket->sock, pSendBuffer + buf.nSendIndex, nSendLen - buf.nSendIndex, LFRP_SEND_FLAGS);
                if (nRet > 0 && nRet < nSendLen - buf.nSendIndex)
                { // 发送一半，等下次发剩余的
                    buf.nSendIndex += nRet;
                    nError = true;
                    CVecSendBuffer& vecBuf = pTunSocket->vecSendBuf;
                    DeleteBufItems(vecBuf, i);
                    break;
                }
                if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                { // 堵住就等下一个EPOLLOUT事件，清掉已经发送的数据
                    PRINT_ERROR("%s Cli %s,%d: send to Tun err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSendLen);
                    nError = true;
                    CVecSendBuffer& vecBuf = pTunSocket->vecSendBuf;
                    DeleteBufItems(vecBuf, i);
                    /*while (i > 0)
                    {
                        i--;
                        vecBuf.erase(vecBuf.begin());
                    }*/
                    break;
                }
#ifdef USE_AES
                delete[] pSendBuffer;
#endif
                delete[] buf.pBuffer;
                buf.pBuffer = nullptr;
                buf.nLen = 0;
                //事实上，这里可能会有nRet小于bufLen的情况
                if (nRet == SOCKET_ERROR || nRet == 0)
                {
                    PRINT_ERROR("%s Cli %s,%d: Tun SocketID %d disconnect because send err %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->sock, nRet);
                    // Server关闭了
                    CloseLfrpSocket(pTunSocket);
                    delete pTunSocket;
                    SetSockBySN(nServiceNum, INVALID_SOCKET);
                    // 通道关闭，所有客户侧连接清掉
                    for (CSocketMap::iterator iter = mapSvr.begin(); iter != mapSvr.end(); iter++)
                    {
                        if (iter->second->sock != INVALID_SOCKET)
                        {
                            PRINT_ERROR("%s Cli %s,%d: Svr SocketID %d disconnect because tun socket disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                            CloseLfrpSocket(iter->second);
                            delete iter->second;
                        }
                    }
                    mapSvr.clear();
                    nError = true;

                    // 发送通道重连通知
                    //FireConnectEvent(nServiceNum);
                    AddDelayReConnect(nServiceNum);

                    break; // socket异常不发剩余数据
                }
            }
            if (!nError)
            {
                pTunSocket->vecSendBuf.clear();
                //pTunSocket->Op = OP_READ;
            }
        }
    }
    else
    { // 写数据到业务客户端
        CLfrpSocket* pTunSocket = GetSockFromInstanceMap(nSNSock);
        if (pTunSocket)
        {
            bool nError = false;
            for (int i = 0; i < pSocket->vecSendBuf.size(); i++)
            {
                CSendBuffer& buf = pSocket->vecSendBuf[i];
                if (buf.nLen > PACK_SIZE_DATA)
                {
                    int nType, nPakLen, nSocketID, nSeq;
                    GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                    PRINT_INFO("%s Cli %s,%d: Svr send socketID %d pack to User size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen - PACK_SIZE_DATA, nSeq);

                    //开始send
                    nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA + buf.nSendIndex, buf.nLen - PACK_SIZE_DATA - buf.nSendIndex, LFRP_SEND_FLAGS);
                    if (nRet > 0 && nRet < buf.nLen - PACK_SIZE_DATA - buf.nSendIndex)
                    { // 发送一半，等下次发剩余的
                        buf.nSendIndex += nRet;
                        nError = true;
                        CVecSendBuffer& vecBuf = pSocket->vecSendBuf;
                        DeleteBufItems(vecBuf, i);
                        break;
                    }
                    if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                    { // 缓冲区堵塞等一下重发
                        PRINT_ERROR("%s Cli %s,%d: send to User err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen - PACK_SIZE_DATA);
                        nError = true;
                        CVecSendBuffer& vecBuf = pSocket->vecSendBuf;
                        DeleteBufItems(vecBuf, i);
                        /*while (i > 0)
                        {
                            i--;
                            vecBuf.erase(vecBuf.begin());
                        }*/
                        break;
                    }
                    //事实上，这里可能会有nRet小于bufLen的情况
                    if (nRet == SOCKET_ERROR || nRet == 0)
                    {
                        PRINT_ERROR("%s Cli %s,%d: Svr SocketID %d disconnect because send err %x wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet, WSAGetLastError());
                        // 客户侧连接失败，需要通知服务侧清掉这条连接
                        DoBusSocketErr(nIndex, pSocket, pTunSocket);
                        CSocketMap::iterator iter = mapSvr.find(pSocket->nSocketID);
                        if (iter != mapSvr.end())
                        {
                            mapSvr.erase(iter);
                        }
                        CloseLfrpSocket(pSocket);
                        delete pSocket;
                        nError = true;
                        break; // socket异常不发剩余数据
                    }
                }
                delete[] buf.pBuffer;
                buf.pBuffer = nullptr;
                buf.nLen = 0;
            }
            if (!nError)
            {
                pSocket->vecSendBuf.clear();
                //pSocket->Op = OP_READ;
            }
        }
    }
    return 0;
}

int CliClose(int nIndex, int sock)
{
    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (pSocket == nullptr)
    {
        PRINT_INFO("%s Tun %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return 0;
    }

    CSocketMap& mapSvr = pSvrMapAry[nIndex];
    int nServiceNum = GetServiceNum(sock);
    int nSNSock = GetSockBySN(nServiceNum);
    if (nSNSock == sock)
    { // 处理通道断开，需要重连
        CloseLfrpSocket(pSocket);
        delete pSocket;
        SetSockBySN(nServiceNum, INVALID_SOCKET);

        // 通道关闭，所有客户侧连接清掉
        for (CSocketMap::iterator iter = mapSvr.begin(); iter != mapSvr.end(); iter++)
        {
            if (iter->second->sock != INVALID_SOCKET)
            {
                PRINT_ERROR("%s Cli %s,%d: Svr SocketID %d disconnect because tun socket disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                CloseLfrpSocket(iter->second);
                delete iter->second;
            }
        }
        mapSvr.clear();

        // 发送通道重连通知
        //FireConnectEvent(nServiceNum);
        AddDelayReConnect(nServiceNum);
    }
    else
    { // 业务连接断开通知业务侧
        //PRINT_ERROR("%s Cli %s,%d: Svr SocketID %d disconnect because send err %x wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet, WSAGetLastError());
        // 客户侧连接失败，需要通知服务侧清掉这条连接
        CLfrpSocket* pTunSocket = GetSockFromInstanceMap(nSNSock);
        if (pTunSocket)
        {
            DoBusSocketErr(nIndex, pSocket, pTunSocket);
            //FireWriteEvent(pTunSocket->sock);
        }
        CSocketMap& mapSvr = pSvrMapAry[nIndex];
        CSocketMap::iterator iter = mapSvr.find(pSocket->nSocketID);
        if (iter != mapSvr.end())
        {
            mapSvr.erase(iter);
        }
        CloseLfrpSocket(pSocket);
        delete pSocket;
    }

    return 0;
}

unsigned int uLastHeartBeatSec;
int CliTimer()
{
    CommTimer();

    unsigned int uSec = GetCurSecond();
    if (uSec - uLastHeartBeatSec > 10)
    {
        std::vector<int> vecSNSock = GetActiveSNSock();
        for (std::vector<int>::iterator iter = vecSNSock.begin(); iter != vecSNSock.end(); iter++)
        {
            FireHeartBeatEvent(*iter);
        }
    }

    return 0;
}
#endif

int main(int argc, char** argv)
{
    int nRet = 0;
    PRINT_ERROR("%s Cli used as 'lfrpCli -th tunHost -tp tunPort -sp LocalServerPort -sn ServiceNumber -k AESKey', default is 'lfrpCli -th %s -tp %d -sp %d -sn %d -k %s'\n", GetCurTimeStr(), strTun.c_str(), nTunPort, nSvrPort, nServiceNumber, strAesKey.c_str());
    int i = 0;
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-th") == 0 && i + 1 <= argc)
        {
            i++;
            strTun = argv[i];
        }
        else if (strcmp(argv[i], "-tp") == 0 && i + 1 <= argc)
        {
            i++;
            nTunPort = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-sp") == 0 && i + 1 <= argc)
        {
            i++;
            nSvrPort = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-k") == 0 && i + 1 <= argc)
        {
            i++;
            strAesKey = argv[i];
        }
        else if (strcmp(argv[i], "-sn") == 0 && i + 1 <= argc)
        {
            i++;
            nServiceNumber = atoi(argv[i]);
        }
#ifdef USE_EPOLL
        else if (strcmp(argv[i], "-snr") == 0 && i + 1 <= argc)
        { // service number range，"1-4,7-8,13"
            i++;
            std::string strNumbers = argv[i];
            std::vector<std::string> vecGroup = stringSplit(strNumbers, ',');
            for (size_t i = 0; i < vecGroup.size(); i++)
            {
                std::vector<std::string> vecRange = stringSplit(vecGroup[i], '-');
                if (vecRange.size() > 1)
                { // 只取前2个，且要前面小于后面
                    int nSNBeg = atoi(vecRange[0].c_str());
                    int nSNEnd = atoi(vecRange[1].c_str());
                    for (size_t k = nSNBeg; k <= nSNEnd; k++)
                    {
                        vecServieNumber.push_back(k);
                    }
                }
                else
                {
                    vecServieNumber.push_back(atoi(vecRange[0].c_str()));
                }
            }
        }
#endif
    }
#ifdef USE_EPOLL
    // Epoll模式默认开4个ServiceNumber，注意不要开多个相同ServiceNumber的进程
    if (vecServieNumber.size() == 0)
    {
        for (size_t i = 0; i < DEFAULT_EPOLL_SERVICE_NUM; i++)
        {
            vecServieNumber.push_back(i);
        }
    }
#endif

    // 初始化AES密钥信息
    CAES::GlobalInit(strAesKey.c_str());

    // 初始化socket
    InitSocket();
    
    InitSection("Cli");
#ifdef USE_EPOLL
    uLastHeartBeatSec = GetCurSecond();
    InitLog("./Cli.txt");
    // 初始化epooll工作线程相关
    SetBusWorkerCallBack(CliRead, CliWrite, CliClose, CliTrans, CliPostAccept, CliTimer);
    InitWorkerThreads();
    pSvrMapAry = new CSocketMap[nThreadCount];

    // 负责所有ServiceNumber连接和重连通道
    std::thread* pConnectThread = new std::thread(ConnectWorker, strTun.c_str(), nTunPort);
#endif

    // 监听端口
    SOCKET sockListen = INVALID_SOCKET;
#ifdef USE_EPOLL
    nRet = EpollListenSocket(epollfd, sockListen, strSvr.c_str(), nSvrPort);
#else
    nRet = ListenSocket(sockListen, strSvr.c_str(), nSvrPort);
#endif
    if (nRet != 0)
    {
        return 1;
    };


#ifdef USE_EPOLL
    FireConnectEvent(-1);
    mainEpoll(epollfd, sockListen);
    bExitPorcess = true;
#else
    mainSelect(sockListen);
#endif
}
