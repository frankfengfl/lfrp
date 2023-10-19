// lfrpSvr.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
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

// 本地业务服务信息
std::string strSvr = "127.0.0.1";
#if defined(_DEBUG) || !defined(_WIN32) // Windows调试模式和Linux模式，默认都连接EchoServer
int nSvrPort = 10001;
#else
int nSvrPort = 3389;
#endif

// 通道服务信息
std::string strTun = "127.0.0.1"; 
int nTunPort = 6868;

// 远端服务信息
int nServiceNumber = 1;

// AES key
std::string strAesKey = "asdf1234567890";

// 业务服务连接失败，需要通知client侧清掉这条连接
void DoBusSocketErr(CLfrpSocket* pSocket, CLfrpSocket* pTunSocket)
{
    CBuffer buf;
    int nSeq = GetNextSeq(SEQ_SERVER, pSocket->sock);
    RemoveSeqKey(pSocket->sock);
    MakeDataEndPack(buf, pSocket->nSocketID, nSeq);
    if (pTunSocket && pTunSocket->sock != INVALID_SOCKET)
    {
        pTunSocket->vecSendBuf.push_back(buf);
        pTunSocket->Op = OP_WRITE;
    }
}

int ProcessRead(CLfrpSocket* pTunSocket, CSocketMap& mapBusinessSvr, fd_set& fdRead)
{
    int nFunRet = 0;
    int nRet = 0;
    if (FD_ISSET(pTunSocket->sock, &fdRead))
    {
        int nRet = LfrpRecv(pTunSocket);
        if (nRet <= 0)
        {
            PRINT_ERROR("%s Svr %s,%d: Tun SocketID %d disconnect because read err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->sock, nRet, WSAGetLastError());
            CloseLfrpSocket(pTunSocket);
            // 通道关闭，所有业务服务连接清掉
            for (CSocketMap::iterator iter = mapBusinessSvr.begin(); iter != mapBusinessSvr.end(); iter++)
            {
                if (iter->second->sock != INVALID_SOCKET)
                {
                    PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because tun socket disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                    CloseLfrpSocket(iter->second);
                    delete iter->second;
                }
            }
            mapBusinessSvr.clear();
            nFunRet = -1;
        }
        else
        {
            // 包收完全了
            while (pTunSocket->nBufLen >= pTunSocket->nPackLen && pTunSocket->nPackLen > 0)
            {
                PRINT_INFO("%s Svr %s,%d: Tun recv socketID %d pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->nSocketID, nRet, pTunSocket->nPackSeq);
                if (pTunSocket->nType == PACK_TYPE_DATA_BEG)
                {
                    CLfrpSocket* pSocket = new CLfrpSocket;
                    CSocketMap::iterator iter = mapBusinessSvr.find(pTunSocket->nSocketID);
                    if (iter != mapBusinessSvr.end())
                    {
                        PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because the same sockeID send DataBeg\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                        // 相同Client侧SocketID还有业务连接，正常是客户端复用SocketID，而本服务未清除
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                        mapBusinessSvr.erase(iter);
                    }

                    // 新的Client连接过来，配套一条连到业务服务
                    if (ConnectSocket(pSocket->sock, strSvr.c_str(), nSvrPort) != 0)
                    { 
                        printf("%s connect() Svr Failed: %d\n", GetCurTimeStr(), WSAGetLastError());
                        // 连接业务服务失败，需要通知client侧清掉这条连接
                        DoBusSocketErr(pSocket, pTunSocket);
                        delete pSocket;
                    }
                    else
                    {
                        pSocket->nSocketID = pTunSocket->nSocketID;
                        mapBusinessSvr.insert(std::make_pair(pSocket->nSocketID, pSocket));
                    }

                    // 取掉起始包
                    DropOnePack(pTunSocket);
                }
                else if (pTunSocket->nType == PACK_TYPE_DATA_END)
                { // 客户端断开
                    CSocketMap::iterator iter = mapBusinessSvr.find(pTunSocket->nSocketID);
                    if (iter != mapBusinessSvr.end())
                    {
                        PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because Cli send DataEnd\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                        // 客户侧断开，也要同时断开业务侧连接
                        RemoveSeqKey(iter->second->sock);  // 客户端断开，从map中删除
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                        mapBusinessSvr.erase(iter);
                    }

                    // 取掉结束包
                    DropOnePack(pTunSocket);
                }
                else if (pTunSocket->nType > PACK_TYPE_DATA_BEG && pTunSocket->nType <= PACK_TYPE_DATA_END)
                {
                    CSocketMap::iterator iter = mapBusinessSvr.find(pTunSocket->nSocketID);
                    if (iter != mapBusinessSvr.end())
                    {
                        if (MoveSendPack(pTunSocket, iter->second))
                        {
                            iter->second->Op = OP_WRITE;
                        }
                    }
                }
                else if (pTunSocket->nType == PACK_TYPE_TUN_END)
                { // 客户端通道整个断开，清掉所有相关业务连接
                    for (CSocketMap::iterator iter = mapBusinessSvr.begin(); iter != mapBusinessSvr.end(); iter++)
                    {
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                    }
                    mapBusinessSvr.clear();

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
    for (CSocketMap::iterator iter = mapBusinessSvr.begin(); iter != mapBusinessSvr.end(); iter++)
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
                    PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because read err %x wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock, nRet, WSAGetLastError());
                    // 连接业务服务失败，需要通知client侧清掉这条连接
                    DoBusSocketErr(pSocket, pTunSocket);
                    CloseLfrpSocket(pSocket);
                    vecDelSocket.push_back(pSocket);
                    nFunRet = -1;
                }
                else if (nRet > 0)
                {
                    pSocket->nLastRecvSec = GetCurSecond();
                    int nSeq = GetNextSeq(SEQ_SERVER, pSocket->sock);
                    PRINT_INFO("%s Svr %s,%d: Svr socketID %d recv from BusinessServer pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->first, nRet, nSeq);

                    CBuffer buf;
                    buf.pBuffer = new char[PACK_SIZE_DATA + nRet];
                    buf.nLen = PACK_SIZE_DATA + nRet;
                    int* pData = (int*)buf.pBuffer;
                    pData[0] = MAGIC_NUMBER;
                    pData[1] = PACK_TYPE_DATA;
                    pData[2] = buf.nLen;
                    pData[3] = iter->first; // 使用客户端的SocketID
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
            for (CSocketMap::iterator iter = mapBusinessSvr.begin(); iter != mapBusinessSvr.end(); iter++)
            {
                if (vecDelSocket[i] == iter->second)
                {
                    mapBusinessSvr.erase(iter);
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
                CBuffer& buf = pTunSocket->vecSendBuf[i];

                int nType, nPakLen, nSocketID, nSeq;
                GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                PRINT_INFO("%s Svr %s,%d: Tun send socketID %d pack to TunSvr size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen, nSeq);

                // 发送前加密
                char* pSendBuffer = buf.pBuffer;
                int nSendLen = buf.nLen;
#ifdef USE_AES
                CAES cAes;
                pSendBuffer = (char*)cAes.Encrypt(buf.pBuffer, buf.nLen, nSendLen, true);
#endif

                //开始send
                nRet = send(pTunSocket->sock, pSendBuffer, nSendLen, LFRP_SEND_FLAGS);
                while (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                { // 缓冲区堵塞等一下重发
                    PRINT_ERROR("%s Svr %s,%d: send to Server err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSendLen);
                    Sleep(1);
                    nRet = send(pTunSocket->sock, pSendBuffer, nSendLen, LFRP_SEND_FLAGS);
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
                    PRINT_ERROR("%s Svr %s,%d: Tun SocketID %d disconnect because send err %x wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->sock, nRet, WSAGetLastError());
                    
                    // 通道失败，清掉所有业务侧连接
                    CloseLfrpSocket(pTunSocket);
                    for (CSocketMap::iterator iter = mapSvr.begin(); iter != mapSvr.end(); iter++)
                    {
                        if (iter->second->sock != INVALID_SOCKET)
                        {
                            PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because tun send err to disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
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
                    CBuffer& buf = pSocket->vecSendBuf[i];
                    if (buf.nLen > PACK_SIZE_DATA)
                    {
                        int nType, nPakLen, nSocketID, nSeq;
                        GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                        PRINT_INFO("%s Svr %s,%d: Server send socketID %d pack to Bussiness size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen - PACK_SIZE_DATA, nSeq);

                        //开始send
                        nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA, buf.nLen - PACK_SIZE_DATA, LFRP_SEND_FLAGS);
                        while (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                        { // 缓冲区堵塞等一下重发
                            PRINT_ERROR("%s Svr %s,%d: send to Server err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen - PACK_SIZE_DATA);
                            Sleep(1);
                            nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA, buf.nLen - PACK_SIZE_DATA, LFRP_SEND_FLAGS);
                        }
                        //事实上，这里可能会有nRet小于bufLen的情况
                        if (nRet == SOCKET_ERROR || nRet == 0)
                        {
                            PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because send err %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock, nRet);
                            // 连接业务服务失败，需要通知client侧清掉这条连接
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
    CBuffer buf;
    buf.pBuffer = new char[PACK_SIZE_AUTH];
    buf.nLen = PACK_SIZE_AUTH;
    int* pData = (int*)buf.pBuffer;
    pData[0] = MAGIC_NUMBER;
    pData[1] = PACK_TYPE_AUTH_SERVER;
    pData[2] = PACK_SIZE_AUTH;
#ifdef USE_EPOLL
    pData[3] = pTunSocket->nServiceNumber;
#else
    pData[3] = nServiceNumber;
#endif
    pTunSocket->vecSendBuf.push_back(buf);
    pTunSocket->Op = OP_WRITE;
}

int mainSelect()
{
    struct sockaddr_in clientService;
    int nRet = 0;
    CLfrpSocket sockTun;
    CSocketMap mapSvr;
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
    while (true)
    {
        //循环判断是否有请求需要处理
        fd_set fdRead, fdWrite;
        while (true)
        {
            SOCKET maxSock = 0;
            bool bSetFD = false;
            FD_ZERO(&fdRead);
            FD_ZERO(&fdWrite);
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
                nRet = select(maxSock + +1, &fdRead, &fdWrite, NULL, &timevalSelect);
#endif
                if (nRet == 0)
                {
                    unsigned int uSec = GetCurSecond();
                    if (sockTun.sock != INVALID_SOCKET && uSec - uLastHeartBeatSec > 10)
                    { // 10秒心跳
                        uLastHeartBeatSec = uSec;
                        CBuffer buf;
                        MakeHeartBeatPack(buf);
                        sockTun.vecSendBuf.push_back(buf);
                        sockTun.Op = OP_WRITE;
                    }
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
                // 通道连接失败要重连
                if (sockTun.sock == INVALID_SOCKET && uSec - uLastTunSec > 5)
                {
                    PRINT_ERROR("%s Cli %s,%d: ConnectSocket %s:%d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, strTun.c_str(), nTunPort);
                    if (ConnectSocket(sockTun.sock, strTun.c_str(), nTunPort) != 0)
                    {
                        sockTun.sock = INVALID_SOCKET;
                        printf("%s reconnect() Tun Failed: %d\n", GetCurTimeStr(), WSAGetLastError());
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
// BusSvr
typedef std::map<int64_t, CLfrpSocket*> CSocketWorkerMap;         // 业务端点根据ServiceNumber + soketID管理多连接
CSocketWorkerMap* pSvrMapAry = nullptr;   // 按照工作线程数，落对应几个ServiceNumber的所有socket，其中要求不同Cli不能共用ServiceNumber，保证ServiceNumber + soketID唯一

// 业务服务连接失败，需要通知client侧清掉这条连接
void DoBusSocketErr(int nIndex, CLfrpSocket* pSocket, CLfrpSocket* pTunSocket)
{
    CBuffer buf;
    int nSeq = GetNextSeq(nIndex, SEQ_SERVER, pSocket->sock);
    RemoveSeqKey(pSocket->sock);
    MakeDataEndPack(buf, pSocket->nSocketID, nSeq);
    if (pTunSocket && pTunSocket->sock != INVALID_SOCKET)
    {
        pTunSocket->vecSendBuf.push_back(buf);
        //pTunSocket->Op = OP_WRITE;
    }
}

int SvrTrans(int nIndex, int sock, CLfrpSocket* pSocket)
{ // 转换后用于通道登录
    if (pSocket == nullptr)
    {
        pSocket = GetSockFromInstanceMap(sock);
    }
    if (pSocket == nullptr)
    {
        PRINT_ERROR("%s Tun %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return 0;
    }

    int nServiceNum = GetServiceNum(sock);
    int nSNSock = GetSockBySN(nServiceNum);
    PRINT_INFO("%s %s,%d: SvrTrans SocketID %d ServiceNum %d SNSock %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nServiceNum, nSNSock);
    // 处理通道连接
    if (nSNSock == sock)
    {
        pSocket->Op |= OP_TRANS;
        if (pSocket->Op & OP_WRITE)
        {
            SendTunLogin(pSocket);
            pSocket->Op = 0;
            FireWriteEvent(sock);
        }
    }

    return 0;
}

int SvrRead(int nIndex, int sock, char* pBuffer, int nCount)
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
        CSocketWorkerMap& mapBusinessSvr = pSvrMapAry[nIndex];
        int nRet = AddAESRecvData(pTunSocket, pBuffer, nCount);
        if (nRet <= 0)
        {
            PRINT_ERROR("%s Svr %s,%d: Tun SocketID %d disconnect because read err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->sock, nRet, WSAGetLastError());
            CloseLfrpSocket(pTunSocket);
            // 通道关闭，所有业务服务连接清掉
            for (CSocketWorkerMap::iterator iter = mapBusinessSvr.begin(); iter != mapBusinessSvr.end(); iter++)
            {
                if (iter->second->sock != INVALID_SOCKET)
                {
                    PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because tun socket disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                    CloseLfrpSocket(iter->second);
                    delete iter->second;
                }
            }
            mapBusinessSvr.clear();

            // 发送通道重连通知
            //FireConnectEvent(nServiceNum);
            AddDelayReConnect(nServiceNum);
        }
        else
        {
            // 包收完全了
            while (pTunSocket->nBufLen >= pTunSocket->nPackLen && pTunSocket->nPackLen > 0)
            {
                PRINT_INFO("%s Svr %s,%d: Tun recv socketID %d pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->nSocketID, nRet, pTunSocket->nPackSeq);
                if (pTunSocket->nType == PACK_TYPE_DATA_BEG)
                {
                    CLfrpSocket* pSocket = new CLfrpSocket;
                    pSocket->nSocketID = pTunSocket->nSocketID;
                    pSocket->nServiceNumber = pTunSocket->nServiceNumber;
                    CSocketWorkerMap::iterator iter = mapBusinessSvr.find(MAKE_SOCKET_MAP_KEY(pTunSocket->nServiceNumber, pTunSocket->nSocketID));
                    if (iter != mapBusinessSvr.end())
                    {
                        PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because the same sockeID send DataBeg\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                        // 相同Client侧SocketID还有业务连接，正常是客户端复用SocketID，而本服务未清除
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                        mapBusinessSvr.erase(iter);
                    }

                    // 新的Client连接过来，配套一条连到业务服务
                    if (PreConnectSocket(pSocket->sock, strSvr.c_str(), nSvrPort) != 0)
                    {
                        printf("%s connect() Svr Failed: %d\n", GetCurTimeStr(), WSAGetLastError());
                        // 连接业务服务失败，需要通知client侧清掉这条连接
                        DoBusSocketErr(nIndex, pSocket, pTunSocket);
                        FireWriteEvent(pTunSocket->sock);
                        delete pSocket;
                    }
                    else
                    {
                        PRINT_INFO("%s %s,%d: SvrRead connect SocketID %d ServiceNumber %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, pSocket->nServiceNumber);
                        // 先把sock放到管理对象中
                        AddSockToInstanceMap(pSocket->sock, pSocket);    // 添加到实例，这里务必比SvrWrite先完成
                        SetServiceNum(pSocket->sock, nServiceNum);
                        mapBusinessSvr.insert(std::make_pair(MAKE_SOCKET_MAP_KEY(pSocket->nServiceNumber, pSocket->nSocketID), pSocket));

                        // 实际连接
                        int nRet = ProcssConnectSocket(pSocket->sock, strSvr.c_str(), nSvrPort);
                        nRet = EpollPostConnectSocket(epollfd, pSocket->sock, strSvr.c_str(), nSvrPort, nRet);
                        if (nRet < 0)
                        {
                            mapBusinessSvr.erase(mapBusinessSvr.find(MAKE_SOCKET_MAP_KEY(pSocket->nServiceNumber, pSocket->nSocketID)));
                            CloseLfrpSocket(pSocket);
                            delete pSocket;
                        }
                    }

                    // 取掉起始包
                    DropOnePack(pTunSocket);
                }
                else if (pTunSocket->nType == PACK_TYPE_DATA_END)
                { // 客户端断开
                    CSocketWorkerMap::iterator iter = mapBusinessSvr.find(MAKE_SOCKET_MAP_KEY(pTunSocket->nServiceNumber, pTunSocket->nSocketID));
                    if (iter != mapBusinessSvr.end())
                    {
                        PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because Cli send DataEnd\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
                        // 客户侧断开，也要同时断开业务侧连接
                        RemoveSeqKey(iter->second->sock);  // 客户端断开，从map中删除
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                        mapBusinessSvr.erase(iter);
                    }

                    // 取掉结束包
                    DropOnePack(pTunSocket);
                }
                else if (pTunSocket->nType > PACK_TYPE_DATA_BEG && pTunSocket->nType <= PACK_TYPE_DATA_END)
                {
                    CSocketWorkerMap::iterator iter = mapBusinessSvr.find(MAKE_SOCKET_MAP_KEY(pTunSocket->nServiceNumber, pTunSocket->nSocketID));
                    if (iter != mapBusinessSvr.end())
                    {
                        if (EpollMoveSendPack(pTunSocket, iter->second)) // Epoll复用Tun，收到的每个包pTunSocket->nSocketID可能变
                        {
                            //iter->second->Op = OP_WRITE;
                            // todo, 可能连接业务的connect还没完全，发送写事件可能写不进去，需要设置CLfrpSocket状态，并区分Epoll触发的FireWriteEvent来清除
                            FireWriteEvent(iter->second->sock);
                        }
                    }
                    else
                    {
                        // todo, 如果服务侧关闭，或没连成功，这里会空转？
                        // 连接没成功没关系，能保证先收到连接包头已经建出来CLfrpSocket；
                        // 但业务服务侧关闭后，客户端可能还是会发包过来，此时丢弃包，并报错
                        PRINT_ERROR("%s Svr %s,%d: Tun recv socketID %d Data, but can't find BusSvr\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->nSocketID);
                        // 取掉无效连接的包避免空转
                        DropOnePack(pTunSocket);
                    }
                }
                else if (pTunSocket->nType == PACK_TYPE_TUN_END)
                { // 客户端通道整个断开，清掉所有相关业务连接
                    for (CSocketWorkerMap::iterator iter = mapBusinessSvr.begin(); iter != mapBusinessSvr.end(); iter++)
                    {
                        CloseLfrpSocket(iter->second);
                        delete iter->second;
                    }
                    mapBusinessSvr.clear();

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
            int nSeq = GetNextSeq(nIndex, SEQ_SERVER, pSocket->sock);
            PRINT_INFO("%s Svr %s,%d: Svr socketID %d recv from BusinessServer pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->nSocketID, nCount, nSeq);

            CBuffer buf;
            buf.pBuffer = new char[PACK_SIZE_DATA + nCount];
            buf.nLen = PACK_SIZE_DATA + nCount;
            int* pData = (int*)buf.pBuffer;
            pData[0] = MAGIC_NUMBER;
            pData[1] = PACK_TYPE_DATA;
            pData[2] = buf.nLen;
            pData[3] = pSocket->nSocketID; // 使用客户端的SocketID
            pData[4] = nSeq;
            memcpy(buf.pBuffer + PACK_SIZE_DATA, pBuffer, nCount);
            pTunSocket->vecSendBuf.push_back(buf);
            //pTunSocket->Op = OP_WRITE;
            FireWriteEvent(pTunSocket->sock);
        }
    }
    return 0;
}

int SvrWrite(int nIndex, int sock)
{
    int nRet = 0;
    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (pSocket == nullptr)
    {
        PRINT_ERROR("%s Tun %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
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
    CSocketWorkerMap& mapSvr = pSvrMapAry[nIndex];
    if (nSNSock == sock)
    { // 处理通道连接
        pSocket->Op |= OP_WRITE;
        if (pSocket->Op & OP_TRANS)
        {
            SendTunLogin(pSocket);
            pSocket->Op = 0;
            FireWriteEvent(sock);
        }
        else
        { // 正常写数据
            bool nError = false;
            CLfrpSocket* pTunSocket = pSocket;
            for (int i = 0; i < pTunSocket->vecSendBuf.size(); i++)
            {
                CBuffer& buf = pTunSocket->vecSendBuf[i];

                int nType, nPakLen, nSocketID, nSeq;
                GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                PRINT_INFO("%s Svr %s,%d: Tun send socketID %d pack to TunSvr size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen, nSeq);

                // 发送前加密
                char* pSendBuffer = buf.pBuffer;
                int nSendLen = buf.nLen;
                CAES cAes;
                pSendBuffer = (char*)cAes.Encrypt(buf.pBuffer, buf.nLen, nSendLen, true);

                //开始send
                nRet = send(pTunSocket->sock, pSendBuffer, nSendLen, LFRP_SEND_FLAGS);
                if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                { // 堵住就等下一个EPOLLOUT事件，清掉已经发送的数据
                    nError = true;
                    CVecBuffer& vecBuf = pTunSocket->vecSendBuf;
                    while (i > 0)
                    {
                        i--;
                        vecBuf.erase(vecBuf.begin());
                    }
                    break;
                }
                delete[] pSendBuffer;
                delete[] buf.pBuffer;
                buf.pBuffer = nullptr;
                buf.nLen = 0;
                //事实上，这里可能会有nRet小于bufLen的情况
                if (nRet == SOCKET_ERROR || nRet == 0)
                {
                    PRINT_ERROR("%s Svr %s,%d: Tun SocketID %d disconnect because send err %x wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pTunSocket->sock, nRet, WSAGetLastError());

                    // 通道失败，清掉所有业务侧连接
                    CloseLfrpSocket(pTunSocket);
                    for (CSocketWorkerMap::iterator iter = mapSvr.begin(); iter != mapSvr.end(); iter++)
                    {
                        if (iter->second->sock != INVALID_SOCKET)
                        {
                            PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because tun send err to disconnect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second->sock);
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
    { // 写数据到业务服务
        CLfrpSocket* pTunSocket = GetSockFromInstanceMap(nSNSock);
        if (pTunSocket)
        {
            bool nError = false;
            for (int i = 0; i < pSocket->vecSendBuf.size(); i++)
            {
                CBuffer& buf = pSocket->vecSendBuf[i];
                if (buf.nLen > PACK_SIZE_DATA)
                {
                    int nType, nPakLen, nSocketID, nSeq;
                    GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                    PRINT_INFO("%s Svr %s,%d: Server send socketID %d pack to Bussiness size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen - PACK_SIZE_DATA, nSeq);

                    //开始send
                    nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA, buf.nLen - PACK_SIZE_DATA, LFRP_SEND_FLAGS);
                    if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                    { // 堵住就等下一个EPOLLOUT事件，清掉已经发送的数据
                        nError = true;
                        CVecBuffer& vecBuf = pTunSocket->vecSendBuf;
                        while (i > 0)
                        {
                            i--;
                            vecBuf.erase(vecBuf.begin());
                        }
                        break;
                    }
                    //事实上，这里可能会有nRet小于bufLen的情况
                    if (nRet == SOCKET_ERROR || nRet == 0)
                    {
                        PRINT_ERROR("%s Svr %s,%d: Svr SocketID %d disconnect because send err %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet);
                        // 连接业务服务失败，需要通知client侧清掉这条连接
                        DoBusSocketErr(nIndex, pSocket, pTunSocket);
                        CSocketWorkerMap::iterator iter = mapSvr.find(MAKE_SOCKET_MAP_KEY(pSocket->nServiceNumber, pSocket->nSocketID));
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

int SvrClose(int nIndex, int sock)
{
    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (pSocket == nullptr)
    {
        PRINT_ERROR("%s Tun %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return 0;
    }

    CSocketWorkerMap& mapSvr = pSvrMapAry[nIndex];
    int nServiceNum = GetServiceNum(sock);
    int nSNSock = GetSockBySN(nServiceNum);
    if (nSNSock == sock)
    { // 处理通道断开，需要重连
        CloseLfrpSocket(pSocket);
        delete pSocket;
        SetSockBySN(nServiceNum, INVALID_SOCKET);

        // 发送通道重连通知
        //FireConnectEvent(nServiceNum);
        AddDelayReConnect(nServiceNum);
    }
    else
    { // 业务连接断开通知业务侧
        // 连接业务服务失败，需要通知client侧清掉这条连接
        CLfrpSocket* pTunSocket = GetSockFromInstanceMap(nSNSock);
        if (pTunSocket)
        {
            DoBusSocketErr(nIndex, pSocket, pTunSocket);
            FireWriteEvent(pTunSocket->sock);
        }
        CSocketWorkerMap& mapSvr = pSvrMapAry[nIndex];
        CSocketWorkerMap::iterator iter = mapSvr.find(MAKE_SOCKET_MAP_KEY(pSocket->nServiceNumber, pSocket->nSocketID));
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
int SvrTimer()
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
    PRINT_ERROR("%s Cli used as 'lfrpSvr -th tunHost -tp tunPort -sh LocalServerHost -sp LocalServerPort -sn ServiceNumber -k AESKey', default is 'lfrpSvr -th %s -tp %d -sh %s -sp %d -sn %d -k %s'\n", \
        GetCurTimeStr(), strTun.c_str(), nTunPort, strSvr.c_str(), nSvrPort, nServiceNumber, strAesKey.c_str());
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
        else if (strcmp(argv[i], "-sh") == 0 && i + 1 <= argc)
        {
            i++;
            strSvr = argv[i];
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
        vecServieNumber.push_back(1);
        vecServieNumber.push_back(2);
        vecServieNumber.push_back(3);
        vecServieNumber.push_back(4);
    }
#endif

    // 初始化AES密钥信息
    CAES::GlobalInit(strAesKey.c_str());

    // 初始化socket
    InitSocket();

#ifdef USE_EPOLL
    uLastHeartBeatSec =  GetCurSecond();
    InitLog("./Svr.txt");
    // 初始化epooll工作线程相关
    SetBusWorkerCallBack(SvrRead, SvrWrite, SvrClose, SvrTrans, nullptr, SvrTimer);
    InitWorkerThreads();
    pSvrMapAry = new CSocketWorkerMap[nThreadCount];

    // 负责所有ServiceNumber连接和重连通道
    std::thread* pConnectThread = new std::thread(ConnectWorker, strTun.c_str(), nTunPort);
#endif

#ifdef USE_EPOLL
    SOCKET sockListen = INVALID_SOCKET;
    FireConnectEvent(-1);
    mainEpoll(epollfd, sockListen);
    bExitPorcess = true;
#else
    mainSelect();
#endif

    return 0;
}
