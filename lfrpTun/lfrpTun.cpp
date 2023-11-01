// lfrpTun.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
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

CSocketPairMap mapSocketPair;   // 提供服务和访问者对
CSocketVec vecSocket;          // 刚建立连接，还未判断类型的临时socket

// 服务监听端口信息
std::string strHost = "127.0.0.1";
int nPort = 6868;

// AES key
std::string strAesKey = "asdf1234567890";

void CloseServerSocket(CSocketPair& pair)
{
    CloseLfrpSocket(pair.pServer);
    if (pair.pVistor)
    {
        PRINT_ERROR("%s Tun %s,%d: Vistor SocketID %d disconnect because server disconnet\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->sock);
        CloseLfrpSocket(pair.pVistor);
    }
}

void CloseVistorSocket(CSocketPair& pair)
{
    // 访问者关闭，发结束消息给Server
    CBuffer buf;
    MakeTunEndPack(buf);
#ifdef USE_AES
    // lfrpTun的vecSendBuf里存AES加密后的数据，避免重复加解密
    EncryptBuffer(buf);
#endif
    pair.pServer->vecSendBuf.push_back(buf);
    pair.pServer->Op = OP_WRITE;
    CloseLfrpSocket(pair.pVistor);
    delete pair.pVistor;
    pair.pVistor = nullptr;
}

void DelSocketPairFromMap(std::vector<int>& vecDelPair, CSocketPairMap& mapSocketPair)
{
    for (int i = 0; i < vecDelPair.size(); i++)
    {
        iterSockets iter = mapSocketPair.find(vecDelPair[i]);
        if (iter != mapSocketPair.end())
        {
            if (iter->second.pServer)
            {
                delete iter->second.pServer;
            }
            if (iter->second.pVistor)
            {
                delete iter->second.pVistor;
            }
            mapSocketPair.erase(iter);
        }
    }
    vecDelPair.clear();
}

void ProcessRead(CSocketPairMap& mapSocketPair, fd_set& fdRead)
{
    int nRet = 0;
    std::vector<int> vecDelPair;
    // 处理所有socket对的收数据
    for (iterSockets iter = mapSocketPair.begin(); iter != mapSocketPair.end(); iter++)
    {
        CSocketPair& pair = iter->second;
        // todo，从vector移上来只处理了头包，还没处理数据包
        bool bServerHasPack = (pair.pServer->nBufLen >= pair.pServer->nPackLen && pair.pServer->nPackLen > 0);
        if (pair.pServer && FD_ISSET(pair.pServer->sock, &fdRead))
        {
#ifdef USE_AES
            int nRet = LfrpTunAESRecv(pair.pServer);
#else
            int nRet = LfrpRecv(pair.pServer);
#endif
            if (nRet <= 0)
            {
                PRINT_ERROR("%s Tun %s,%d: Server SocketID %d disconnect because read from Server err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pServer->sock, nRet, WSAGetLastError());
                // ServerTun断开，成对关掉，不需要通知，Server和Vistor两端断开会清理
                vecDelPair.push_back(iter->first);
                CloseServerSocket(pair);
            }
            else
            {
#ifdef USE_AES
                if (pair.pVistor && MoveSendAESPack(pair.pServer, pair.pVistor))
                {
                    PRINT_INFO("%s Tun %s,%d: Server send pack to Vistor\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                    pair.pVistor->Op = OP_WRITE;
                }
#else
                // 包收完全了
                if (pair.pServer->nBufLen >= pair.pServer->nPackLen && pair.pServer->nPackLen > 0)
                {
                    PRINT_INFO("%s Tun %s,%d: Server recv socketID %d pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pServer->nSocketID, nRet, pair.pServer->nPackSeq);
                    //pair.pServer->Op = OP_WRITE;
                    if (MoveSendPack(pair.pServer, pair.pVistor))
                    {
                        PRINT_INFO("%s Tun %s,%d: Server send pack to Vistor\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                        pair.pVistor->Op = OP_WRITE;
                    }
                }
#endif
            }
        }

        // todo，从vector移上来只处理了头包，还没处理数据包
        bool bVistorHasPack = (pair.pServer->nBufLen >= pair.pServer->nPackLen && pair.pServer->nPackLen > 0);
        if (pair.pVistor && FD_ISSET(pair.pVistor->sock, &fdRead))
        {
#ifdef USE_AES
            int nRet = LfrpTunAESRecv(pair.pVistor);
#else
            int nRet = LfrpRecv(pair.pVistor);
#endif
            if (nRet <= 0)
            {
                PRINT_ERROR("%s Tun %s,%d: Vistor SocketID %d disconnect because read from Server err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->sock, nRet, WSAGetLastError());
                CloseVistorSocket(pair);
            }
            else
            {
#ifdef USE_AES
                if (pair.pServer && MoveSendAESPack(pair.pVistor, pair.pServer))
                {
                    PRINT_INFO("%s Svr %s,%d: Vistor send pack to Server\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                    pair.pServer->Op = OP_WRITE;
                }
#else
                // 包收完全了
                if (pair.pVistor->nBufLen >= pair.pVistor->nPackLen && pair.pVistor->nPackLen > 0)
                {
                    PRINT_INFO("%s Tun %s,%d: Vistor socketID %d recv pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->nSocketID, nRet, pair.pVistor->nPackSeq);
                    if (MoveSendPack(pair.pVistor, pair.pServer))
                    {
                        PRINT_INFO("%s Svr %s,%d: Vistor send pack to Server\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                        pair.pServer->Op = OP_WRITE;
                    }
                }
#endif
            }
        }
    }
    // 删掉服务端断掉的
    DelSocketPairFromMap(vecDelPair, mapSocketPair);

    CSocketVec vecDelSocket;
    CSocketVec vecRemoveSocket;
    // 新建连接
    for (int i = 0; i < vecSocket.size(); i++)
    {
        if (FD_ISSET(vecSocket[i]->sock, &fdRead))
        {
            CLfrpSocket* pSocket = vecSocket[i];
#ifdef USE_AES
            int nRet = LfrpTunAESRecv(pSocket);
#else
            int nRet = LfrpRecv(pSocket);
#endif
            if (nRet <= 0)
            {
                PRINT_ERROR("%s Tun %s,%d: new SocketID %d disconnect because read from Server err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet, WSAGetLastError());
                // 新socket有问题，直接清除删掉
                CloseLfrpSocket(pSocket);
                vecDelSocket.push_back(pSocket);
                vecRemoveSocket.push_back(pSocket);
            }
            else
            {
                // 包收完全了
                if (pSocket->nBufLen >= pSocket->nPackLen && pSocket->nPackLen > 0 && pSocket->nPackLen > 0)
                {
                    PRINT_INFO("%s Tun %s,%d: new socket recv pack size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet);
                    //pSocket->Op = OP_WRITE;
                    if (pSocket->nType == PACK_TYPE_AUTH_SERVER)
                    {
                        iterSockets iter = mapSocketPair.find(pSocket->nServiceNumber);
                        if (iter != mapSocketPair.end())
                        {  // 业务Number有在用，因为整对关掉，不需要通知，Server和Vistor两端断开会清理
                            if (iter->second.pServer)
                            {
                                CloseLfrpSocket(iter->second.pServer);
                                delete iter->second.pServer;
                            }
                            if (iter->second.pVistor)
                            {
                                CloseLfrpSocket(iter->second.pVistor);
                                delete iter->second.pVistor;
                            }
                            
                            mapSocketPair.erase(iter);
                        }

                        CSocketPair pair;
                        pair.pServer = pSocket;
                        pair.pVistor = nullptr;
                        mapSocketPair.insert(std::make_pair(pSocket->nServiceNumber, pair));

                        // 取掉认证包
                        char* pBuffer = new char[pSocket->nPackLen];
                        FetchOnePack(pSocket, pBuffer);
                        delete[] pBuffer;
                    }
                    else if (pSocket->nType == PACK_TYPE_AUTH_VISTOR)
                    {
                        iterSockets iter = mapSocketPair.find(pSocket->nServiceNumber);
                        if (iter == mapSocketPair.end())
                        {
                            PRINT_ERROR("%s Tun %s,%d: new SocketID %d disconnect because no server number find\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock);
                            // 没有服务，失败
                            CloseLfrpSocket(pSocket);
                            vecDelSocket.push_back(pSocket);
                        }
                        else if(iter->second.pServer)
                        {
                            if (iter->second.pVistor)
                            { // 删除之前的Vistor，并通知业务
                                PRINT_ERROR("%s Tun %s,%d: Vistor SocketID %d disconnect because new Vistor connect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second.pVistor->sock);
                                CloseVistorSocket(iter->second);
                            }
                            iter->second.pVistor = pSocket;

                            // 取掉认证包
                            char* pBuffer = new char[pSocket->nPackLen];
                            FetchOnePack(pSocket, pBuffer);
                            delete[] pBuffer;
                        }
                    }
                    else // if (pSocket->nType == PACK_TYPE_DATA)
                    {
                        PRINT_ERROR("%s Tun %s,%d: new SocketID %d disconnect because first pack type is not auth type\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock);
                        // 第一个包必须认证，否则断开
                        CloseLfrpSocket(pSocket);
                        vecDelSocket.push_back(pSocket);
                    }

                    // 只要包收完全，必须移走
                    vecRemoveSocket.push_back(pSocket);
                }
            }
        }
    }

    //移除有效的连接
    for (int i = 0; i < vecRemoveSocket.size(); i++)
    {
        if (vecRemoveSocket[i])
        {
            for (CSocketVec::iterator iter = vecSocket.begin(); iter != vecSocket.end(); iter++)
            {
                if (vecRemoveSocket[i] == *iter)
                {
                    vecSocket.erase(iter);
                    break;
                }
            }
        }
    }

    //删掉无效的连接
    for (int i = 0; i < vecDelSocket.size(); i++)
    {
        if (vecDelSocket[i])
        {
            delete vecDelSocket[i];
        }
    }
}

void ProcessWrite(CSocketPairMap& mapSocketPair, fd_set& fdWrite)
{
    int nRet = 0;
    std::vector<int> vecDelPair;
    for (iterSockets iter = mapSocketPair.begin(); iter != mapSocketPair.end(); iter++)
    {
        CSocketPair& pair = iter->second;
        if (pair.pServer && FD_ISSET(pair.pServer->sock, &fdWrite))
        {
            if (pair.pServer->Op == OP_WRITE)
            {
                bool nError = false;
                for (int i = 0; i < pair.pServer->vecSendBuf.size(); i++)
                {
                    CBuffer& buf = pair.pServer->vecSendBuf[i];

                    // 调试日志
                    int nType, nPakLen, nSocketID, nSeq;
#ifdef USE_AES
                    CAES cAes;
                    CBuffer bufDec;
                    bufDec.nLen = 0;
                    //bufDec.pBuffer = (char*)cAes.Decrypt(buf.pBuffer, buf.nLen, bufDec.nLen); // 调试时开启，否则靠下面的GetInfoFromBuf初始化
                    GetInfoFromBuf(bufDec, nType, nPakLen, nSocketID, nSeq);
                    //delete[] bufDec.pBuffer; // 调试时开启，否则靠下面的GetInfoFromBuf初始化
#else
                    GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
#endif
                    PRINT_INFO("%s Tun %s,%d: Server send socketID %d pack to BusServer size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen, nSeq);

                    //开始send
                    nRet = send(pair.pServer->sock, buf.pBuffer, buf.nLen, LFRP_SEND_FLAGS);
                    while (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                    { // 缓冲区堵塞等一下重发
                        PRINT_ERROR("%s Tun %s,%d: send to Server err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen);
                        Sleep(1);
                        nRet = send(pair.pVistor->sock, buf.pBuffer, buf.nLen, LFRP_SEND_FLAGS);
                    }
                    delete[] buf.pBuffer;
                    buf.pBuffer = nullptr;
                    buf.nLen = 0;

                    if (nRet == SOCKET_ERROR || nRet == 0)
                    {
                        PRINT_ERROR("%s Tun %s,%d: send to Server err %d to disconnect wsaerr %x", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet, WSAGetLastError());
                        // ServerTun断开，成对关掉，不需要通知，Server和Vistor两端断开会清理
                        vecDelPair.push_back(iter->first);
                        CloseServerSocket(pair);

                        nError = true;
                        break;  // socket异常不发剩余数据
                    }
                }
                if (!nError)
                {
                    pair.pServer->vecSendBuf.clear();
                    pair.pServer->Op = OP_READ;
                }
            }
        }
        if (pair.pVistor && FD_ISSET(pair.pVistor->sock, &fdWrite))
        {
            if (pair.pVistor->Op == OP_WRITE)
            {
                bool nError = false;
                for (int i = 0; i < pair.pVistor->vecSendBuf.size(); i++)
                {
                    CBuffer& buf = pair.pVistor->vecSendBuf[i];
                    
                    // 调试日志
                    int nType, nPakLen, nSocketID, nSeq;
#ifdef USE_AES
                    CAES cAes;
                    CBuffer bufDec;
                    bufDec.nLen = 0;
                    //bufDec.pBuffer = (char*)cAes.Decrypt(buf.pBuffer, buf.nLen, bufDec.nLen); // 调试时开启，否则靠下面的GetInfoFromBuf初始化
                    GetInfoFromBuf(bufDec, nType, nPakLen, nSocketID, nSeq);
                    //delete[] bufDec.pBuffer; // 调试时开启，否则靠下面的GetInfoFromBuf初始化
#else
                    GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
#endif
                    PRINT_INFO("%s Tun %s,%d: Vistor send socketID %d pack to Client size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen, nSeq);

                    //开始send
                    nRet = send(pair.pVistor->sock, buf.pBuffer, buf.nLen, LFRP_SEND_FLAGS);
                    while (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                    { // 缓冲区堵塞等一下重发
                        PRINT_ERROR("%s Tun %s,%d: send to Vistor err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen);
                        Sleep(1);
                        nRet = send(pair.pVistor->sock, buf.pBuffer, buf.nLen, LFRP_SEND_FLAGS);
                    }
                    delete[] buf.pBuffer;
                    buf.pBuffer = nullptr;
                    buf.nLen = 0;
                    
                    if (nRet == SOCKET_ERROR || nRet == 0)
                    {
                        PRINT_ERROR("%s Tun %s,%d: send to Vistor err %d to disconnect wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet, WSAGetLastError());
                        // 访问者关闭，发结束消息给Server
                        CloseVistorSocket(pair);

                        nError = true;
                        break; // socket异常不发剩余数据
                    }
                }
                if (!nError)
                {
                    pair.pVistor->vecSendBuf.clear();
                    pair.pVistor->Op = OP_READ;
                }
            }
        }
    }

    // 删掉服务端断掉的
    DelSocketPairFromMap(vecDelPair, mapSocketPair);
}

void CheckSocketTimeout(CSocketPairMap& mapSocketPair)
{
    unsigned int uSec = GetCurSecond();
    std::vector<int> vecDelPair;
    for (iterSockets iter = mapSocketPair.begin(); iter != mapSocketPair.end(); iter++)
    {
        CSocketPair& pair = iter->second;
        if (pair.pServer && pair.pServer->sock != INVALID_SOCKET && uSec - pair.pServer->nLastRecvSec > 30)
        {
            PRINT_ERROR("%s Tun %s,%d: Server SocketID %d disconnect because receive timeout %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pServer->sock, uSec - pair.pServer->nLastRecvSec);
            // ServerTun断开，成对关掉，不需要通知，Server和Vistor两端断开会清理
            vecDelPair.push_back(iter->first);
            CloseServerSocket(pair);
        }
        else if (pair.pVistor && pair.pVistor->sock != INVALID_SOCKET && uSec - pair.pVistor->nLastRecvSec > 30)
        {
            PRINT_ERROR("%s Tun %s,%d: Vistor SocketID %d disconnect because receive timeout %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->sock, uSec - pair.pVistor->nLastRecvSec);
            // 访问者关闭，发结束消息给Server
            CloseVistorSocket(pair);
        }
    }

    // 删掉服务端断掉的
    DelSocketPairFromMap(vecDelPair, mapSocketPair);
}

int mainSelect(SOCKET& sockListen)
{
    int nRet = 0;
    unsigned int uLastHeartBeatSec = GetCurSecond();
    CLfrpSocket sListen;
    sListen.sock = sockListen;
    while (true)
    {
        //循环判断是否有请求需要处理
        fd_set fdRead, fdWrite;
        while (true)
        {
            FD_ZERO(&fdRead);
            FD_ZERO(&fdWrite);
            FD_SET(sListen.sock, &fdRead);
            SOCKET maxSock = sListen.sock;
            for (iterSockets iter = mapSocketPair.begin(); iter != mapSocketPair.end(); iter++)
            {
                CSocketPair pair = iter->second;
                // 每对socket都要置状态
                if (pair.pServer && pair.pServer->sock != INVALID_SOCKET)
                {
                    LfrpSetFD(pair.pServer, fdRead, fdWrite);
                    maxSock = max(maxSock, pair.pServer->sock);
                }
                if (pair.pVistor && pair.pVistor->sock != INVALID_SOCKET)
                {
                    LfrpSetFD(pair.pVistor, fdRead, fdWrite);
                    maxSock = max(maxSock, pair.pVistor->sock);
                }
            }

            CSocketVec vecDelSocket;
            for (int i = 0; i < vecSocket.size(); i++)
            {
                if (vecSocket[i] && vecSocket[i]->sock != INVALID_SOCKET)
                {
                    unsigned int nTime = GetCurSecond();
                    if (nTime - vecSocket[i]->nAcceptSec > 10)
                    { // 如果超过10秒还没发送包头，可能是非法连接，断开
                        vecDelSocket.push_back(vecSocket[i]);
                        CloseLfrpSocket(vecSocket[i]);
                    }
                    else
                    {
                        LfrpSetFD(vecSocket[i], fdRead, fdWrite);
                        maxSock = max(maxSock, vecSocket[i]->sock);
                    }
                }
            }

            for (int i = 0; i < vecDelSocket.size(); i++)
            {
                for (CSocketVec::iterator iter = vecSocket.begin(); iter != vecSocket.end(); iter++)
                {
                    if (vecDelSocket[i] == *iter)
                    {
                        delete vecDelSocket[i];
                        vecSocket.erase(iter);
                        break;
                    }
                }
            }

            timeval timevalSelect = { 5, 0 };
            //这个操作会被阻塞
#ifdef _WIN32
            nRet = select(0, &fdRead, &fdWrite, NULL, &timevalSelect);
#else
            nRet = select(maxSock + 1, &fdRead, &fdWrite, NULL, &timevalSelect);
#endif
            if (nRet == 0)
            {
                // lfrpSvr和lfrpCli都会发心跳，如果30秒还没数据，认为假连断开
                CheckSocketTimeout(mapSocketPair);
            }

            if (FD_ISSET(sockListen, &fdRead))
            {
                //socket可用了，这时accept一定会立刻返回成功或失败 这里需要处理最大连接数
                SOCKET sockNewClient = accept(sockListen, NULL, NULL);
                if (sockNewClient != INVALID_SOCKET)
                {
                    int enable = 1;
                    if (setsockopt(sockNewClient, IPPROTO_TCP, TCP_NODELAY, (char*)&enable, sizeof(enable)) == SOCKET_ERROR)
                    {
                        PRINT_ERROR("%s Tun %s,%d: accept socket setopt TCP_NODELAY error\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                    }

                    PRINT_ERROR("%s Tun %s,%d: accept new socketID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sockNewClient);
                    CLfrpSocket* pSocket = new CLfrpSocket;
                    pSocket->sock = sockNewClient;
                    pSocket->Op = OP_READ;
                    pSocket->nAcceptSec = GetCurSecond();
                    vecSocket.push_back(pSocket);
                }
            }
            //其他socket可用了，判断哪些能读，哪些能写
#ifdef _WIN32
            if (fdRead.fd_count > 0)
#endif
            {
                ProcessRead(mapSocketPair, fdRead);
            }
#ifdef _WIN32            
            if (fdWrite.fd_count > 0)
#endif
            {
                ProcessWrite(mapSocketPair, fdWrite);
            }
        }
    }

    return nRet;
}

#ifdef USE_EPOLL
CSocketPairMap* pSocketPairMapAry = nullptr;    // 提供服务和访问者对数组，一个工作线程使用一个Map

// bOnlyDel控制是否Close
void DeleteSocketPair(CSocketPairMap& mapSocketPair, int nServiceNum, bool bOnlyDel)
{
    CSocketPair pair;
    pair.pServer = pair.pVistor = nullptr;
    iterSockets iter = mapSocketPair.find(nServiceNum);
    if (iter != mapSocketPair.end())
    {  // 业务Number有在用，因为整对关掉，不需要通知，Server和Vistor两端断开会清理
        pair = iter->second;
        mapSocketPair.erase(iter);
    }
    if (pair.pServer)
    {
        if (!bOnlyDel)
        {
            CloseLfrpSocket(pair.pServer);
        }
        delete pair.pServer;
    }
    if (pair.pVistor)
    {
        if (!bOnlyDel)
        {
            CloseLfrpSocket(pair.pVistor);
        }
        delete pair.pVistor;
    }
}

int ProcessFirstReadPack(int nIndex, int sock, CLfrpSocket* pSocket)
{
    if (pSocket->nType == PACK_TYPE_AUTH_SERVER)
    {
        PRINT_INFO("%s Tun %s,%d: ProcessFirstReadPack SocketID %d ServiceNumber %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, pSocket->nServiceNumber);
        DeleteSocketPair(pSocketPairMapAry[nIndex], pSocket->nServiceNumber, false);

        CSocketPair pair;
        pair.pServer = pSocket;
        pair.pVistor = nullptr;
        pSocketPairMapAry[nIndex].insert(std::make_pair(pSocket->nServiceNumber, pair));

        // 取掉认证包
        char* pBuffer = new char[pSocket->nPackLen];
        FetchOnePack(pSocket, pBuffer);
        delete[] pBuffer;
    }
    else if (pSocket->nType == PACK_TYPE_AUTH_VISTOR)
    {
        iterSockets iter = pSocketPairMapAry[nIndex].find(pSocket->nServiceNumber);
        if (iter == pSocketPairMapAry[nIndex].end())
        {
            PRINT_ERROR("%s Tun %s,%d: new SocketID %d disconnect because no server number find\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock);
            // 没有服务，失败
            CloseLfrpSocket(pSocket);
            delete pSocket;
            return -1;
        }
        else if (iter->second.pServer)
        {
            if (iter->second.pVistor)
            { // 删除之前的Vistor，并通知业务
                PRINT_ERROR("%s Tun %s,%d: Vistor SocketID %d disconnect because new Vistor connect\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iter->second.pVistor->sock);
                CloseVistorSocket(iter->second);
                FireWriteEvent(iter->second.pServer->sock);
            }
            iter->second.pVistor = pSocket;

            // 取掉认证包
            char* pBuffer = new char[pSocket->nPackLen];
            FetchOnePack(pSocket, pBuffer);
            delete[] pBuffer;
        }
    }
    else // if (pSocket->nType == PACK_TYPE_DATA)
    {
        PRINT_ERROR("%s Tun %s,%d: new SocketID %d disconnect because first pack type is not auth type\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock);
        // 第一个包必须认证，否则断开
        CloseLfrpSocket(pSocket);
        delete pSocket;
        return -1;
    }
    return 0;
}

// 仅处理已读取的数据
int TunProcessFirstRead(int nIndex, int sock, CLfrpSocket* pSocket)
{
    if (pSocket == nullptr)
    {
        pSocket = GetSockFromInstanceMap(sock);
    }
    if (pSocket == nullptr)
    {
        PRINT_ERROR("%s Tun %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return 0;
    }
    
    // 处理第一个认证包
    if (ProcessFirstReadPack(nIndex, sock, pSocket) < 0)
    { // 解析第一个包失败，不再往下转包
        return -1;
    }

    CSocketPairMap::iterator iter = pSocketPairMapAry[nIndex].find(pSocket->nServiceNumber);
    if (iter == pSocketPairMapAry[nIndex].end())
    {
        PRINT_ERROR("%s Tun %s,%d: SocketID %d cant find nServiceNumber\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return -1;
    }

    CSocketPair& pair = iter->second;
    if (pair.pServer && pair.pServer->sock == sock)
    {
#ifdef USE_AES
        if (pair.pVistor && MoveSendAESPack(pair.pServer, pair.pVistor))
        {
            PRINT_INFO("%s Tun %s,%d: Server send pack to Vistor\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
            //pair.pVistor->Op = OP_WRITE;
            FireWriteEvent(pair.pVistor->sock);
        }
#else
        // 包收完全了
        if (pair.pServer->nBufLen >= pair.pServer->nPackLen && pair.pServer->nPackLen > 0)
        {
            PRINT_INFO("%s Tun %s,%d: Server recv socketID %d pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pServer->nSocketID, pair.pServer->nPackLen, pair.pServer->nPackSeq);
            if (MoveSendPack(pair.pServer, pair.pVistor))
            {
                PRINT_INFO("%s Tun %s,%d: Server send pack to Vistor\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                //pair.pVistor->Op = OP_WRITE;
                FireWriteEvent(pair.pVistor->sock);
            }
        }
#endif
    }
    else if (pair.pVistor && pair.pVistor->sock == sock)
    {
#ifdef USE_AES
        if (pair.pServer && MoveSendAESPack(pair.pVistor, pair.pServer))
        {
            PRINT_INFO("%s Svr %s,%d: Vistor send pack to Server\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
            //pair.pServer->Op = OP_WRITE;
            FireWriteEvent(pair.pServer->sock);
        }
#else
        // 包收完全了
        if (pair.pVistor->nBufLen >= pair.pVistor->nPackLen && pair.pVistor->nPackLen > 0)
        {
            PRINT_INFO("%s Tun %s,%d: Vistor socketID %d recv pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->nSocketID, pair.pVistor->nPackLen, pair.pVistor->nPackSeq);
            if (MoveSendPack(pair.pVistor, pair.pServer))
            {
                PRINT_INFO("%s Svr %s,%d: Vistor send pack to Server\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                //pair.pServer->Op = OP_WRITE;
                FireWriteEvent(pair.pServer->sock);
            }
        }
#endif
    }
    return 0;
}

int TunRead(int nIndex, int sock, char* pBuffer, int nCount)
{
    // 类似上面的ProcessRead区分业务处理
    int nServiceNum = GetServiceNum(sock);
    int nThreadIndex = nServiceNum == -1 ? GetThreadIndexByNum(sock) : GetThreadIndexByNum(nServiceNum);
    std::vector<int> vecDelPair;
    if (nServiceNum != -1)
    {
        CSocketPairMap::iterator iter = pSocketPairMapAry[nIndex].find(nServiceNum);
        CSocketPair& pair = iter->second;
        if (pair.pServer && pair.pServer->sock == sock)
        {
#ifdef USE_AES
            int nRet = AddTunAESRecvData(pair.pServer, pBuffer, nCount);
#else
            int nRet = AddAESRecvData(pair.pServer, pBuffer, nCount);
#endif
            if (nRet <= 0)
            {
                // ServerTun断开，成对关掉，不需要通知，Server和Vistor两端断开会清理
                CloseServerSocket(pair);
                DeleteSocketPair(pSocketPairMapAry[nIndex], nServiceNum,true);
            }
            else
            {
#ifdef USE_AES
                if (pair.pVistor && MoveSendAESPack(pair.pServer, pair.pVistor))
                {
                    PRINT_INFO("%s Tun %s,%d: Server send pack to Vistor\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                    //pair.pVistor->Op = OP_WRITE;
                    FireWriteEvent(pair.pVistor->sock);
                }
#else
                // 包收完全了
                if (pair.pServer->nBufLen >= pair.pServer->nPackLen && pair.pServer->nPackLen > 0)
                {
                    PRINT_INFO("%s Tun %s,%d: Server recv socketID %d pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pServer->nSocketID, nRet, pair.pServer->nPackSeq);
                    if (MoveSendPack(pair.pServer, pair.pVistor))
                    {
                        PRINT_INFO("%s Tun %s,%d: Server send pack to Vistor\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                        //pair.pVistor->Op = OP_WRITE;
                        FireWriteEvent(pair.pVistor->sock);
                    }
                }
#endif
            }
        }
        else if (pair.pVistor && pair.pVistor->sock == sock)
        {
#ifdef USE_AES
            int nRet = AddTunAESRecvData(pair.pVistor, pBuffer, nCount);
#else
            int nRet = AddAESRecvData(pair.pVistor, pBuffer, nCount);
#endif
            if (nRet <= 0)
            {
                PRINT_ERROR("%s Tun %s,%d: Vistor SocketID %d disconnect because read from Server err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->sock, nRet, WSAGetLastError());
                CloseVistorSocket(pair);
            }
            else
            {
#ifdef USE_AES
                if (pair.pServer && MoveSendAESPack(pair.pVistor, pair.pServer))
                {
                    PRINT_INFO("%s Svr %s,%d: Vistor send pack to Server\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                    //pair.pServer->Op = OP_WRITE;
                    FireWriteEvent(pair.pServer->sock);
                }
#else
                // 包收完全了
                if (pair.pVistor->nBufLen >= pair.pVistor->nPackLen && pair.pVistor->nPackLen > 0)
                {
                    PRINT_INFO("%s Tun %s,%d: Vistor socketID %d recv pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->nSocketID, nRet, pair.pVistor->nPackSeq);
                    if (MoveSendPack(pair.pVistor, pair.pServer))
                    {
                        PRINT_INFO("%s Svr %s,%d: Vistor send pack to Server\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                        //pair.pServer->Op = OP_WRITE;
                        FireWriteEvent(pair.pServer->sock);
                    }
                }
#endif
            }
        }
    }
    else
    { // 新请求？比如vistor被Server断开删除了仍收到读消息怎么办？按照第一个包解析非法退出？
        CLfrpSocket* pSocket = GetSockFromInstanceMap(sock); // todo, 实例放工作线程建立可以减少阻塞，但是要管理新连接不发请求的关掉，避免攻击
        if (pSocket == nullptr)
        {
            PRINT_ERROR("%s Tun %s,%d: new SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
            return 0;
        }
        
#ifdef USE_AES
        int nRet = AddTunAESRecvData(pSocket, pBuffer, nCount);
#else
        int nRet = AddAESRecvData(pSocket, pBuffer, nCount);
#endif
        if (nRet <= 0)
        {
            PRINT_ERROR("%s Tun %s,%d: new SocketID %d disconnect because read from Server err %d wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet, WSAGetLastError());
            // 新socket有问题，直接清除删掉
            CloseLfrpSocket(pSocket);
            delete pSocket;
        }
        else
        {
            // 包收完全了
            if (pSocket->nBufLen >= pSocket->nPackLen && pSocket->nPackLen > 0 && pSocket->nPackLen > 0)
            {
                PRINT_INFO("%s Tun %s,%d: new socket recv pack size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet);
                // 新连接设置到对应的线程
                int nThreadIndex = GetThreadIndexByNum(pSocket->nServiceNumber);
                SetServiceNum(sock, pSocket->nServiceNumber);

                // 新连接如果线程不对应，需要转到对应线程处理
                if (nThreadIndex != nIndex)
                { // 已经收了包但不处理，等切换到SN线程再处理
                    FireTransEvent(sock);
                    return 0;
                }
                
                TunProcessFirstRead(nIndex, sock, pSocket);
            }
        }
    }
    return 0;
}

int TunWrite(int nIndex, int sock)
{
    // 类似上面的ProcessRead区分业务处理
    int nRet = 0;
    int nServiceNum = GetServiceNum(sock);
    int nThreadIndex = nServiceNum == -1 ? GetThreadIndexByNum(sock) : GetThreadIndexByNum(nServiceNum);
    if (nThreadIndex != nIndex)
    { // Socket可用会收到可读和可写，可读会trans，但第一个可写会进这里不匹配
        return 0;
    }
    std::vector<int> vecDelPair;
    if (nServiceNum != -1)
    {
        CSocketPairMap::iterator iter = pSocketPairMapAry[nIndex].find(nServiceNum);
        if (iter != pSocketPairMapAry[nIndex].end())
        {
            CSocketPair& pair = iter->second;
            if (pair.pServer && pair.pServer->sock == sock)
            {
                bool nError = false;
                for (int i = 0; i < pair.pServer->vecSendBuf.size(); i++)
                {
                    CBuffer& buf = pair.pServer->vecSendBuf[i];

                    // 调试日志
                    int nType, nPakLen, nSocketID, nSeq;
#ifdef USE_AES
                    CAES cAes;
                    CBuffer bufDec;
                    bufDec.nLen = 0;
                    //bufDec.pBuffer = (char*)cAes.Decrypt(buf.pBuffer, buf.nLen, bufDec.nLen); // 调试时开启，否则靠下面的GetInfoFromBuf初始化
                    GetInfoFromBuf(bufDec, nType, nPakLen, nSocketID, nSeq);
                    //delete[] bufDec.pBuffer; // 调试时开启，否则靠下面的GetInfoFromBuf初始化
#else
                    GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
#endif
                    PRINT_INFO("%s Tun %s,%d: Server send socketID %d pack to BusServer size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen, nSeq);

                    //开始send
                    nRet = send(pair.pServer->sock, buf.pBuffer, buf.nLen, LFRP_SEND_FLAGS);
                    if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                    {
                        PRINT_ERROR("%s Tun %s,%d: send to Server err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen);
                        // 堵住就等下一个EPOLLOUT事件，清掉已经发送的数据
                        nError = true;
                        CVecBuffer& vecBuf = pair.pServer->vecSendBuf;
                        while (i > 0)
                        {
                            i--;
                            vecBuf.erase(vecBuf.begin());
                        }
                        break;
                    }
                    // 发送成功删掉数据内容
                    delete[] buf.pBuffer;
                    buf.pBuffer = nullptr;
                    buf.nLen = 0;

                    if (nRet == SOCKET_ERROR || nRet == 0)
                    {
                        PRINT_ERROR("%s Tun %s,%d: send to Server err %d to disconnect wsaerr %x", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet, WSAGetLastError());
                        // ServerTun断开，成对关掉，不需要通知，Server和Vistor两端断开会清理
                        CloseServerSocket(pair);
                        DeleteSocketPair(pSocketPairMapAry[nIndex], nServiceNum, true);

                        nError = true;
                        break;  // socket异常不发剩余数据
                    }
                }
                if (!nError)
                {
                    pair.pServer->vecSendBuf.clear();
                    //pair.pServer->Op = OP_READ;
                }
            }
            else if (pair.pVistor && pair.pVistor->sock == sock)
            {
                bool nError = false;
                for (int i = 0; i < pair.pVistor->vecSendBuf.size(); i++)
                {
                    CBuffer& buf = pair.pVistor->vecSendBuf[i];

                    // 调试日志
                    int nType, nPakLen, nSocketID, nSeq;
#ifdef USE_AES
                    CAES cAes;
                    CBuffer bufDec;
                    bufDec.nLen = 0;
                    //bufDec.pBuffer = (char*)cAes.Decrypt(buf.pBuffer, buf.nLen, bufDec.nLen); // 调试时开启，否则靠下面的GetInfoFromBuf初始化
                    GetInfoFromBuf(bufDec, nType, nPakLen, nSocketID, nSeq);
                    //delete[] bufDec.pBuffer; // 调试时开启，否则靠下面的GetInfoFromBuf初始化
#else
                    GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
#endif
                    PRINT_INFO("%s Tun %s,%d: Vistor send socketID %d pack to Client size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen, nSeq);

                    //开始send
                    nRet = send(pair.pVistor->sock, buf.pBuffer, buf.nLen, LFRP_SEND_FLAGS);
                    if (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                    {
                        PRINT_ERROR("%s Tun %s,%d: send to Vistor err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen);
                        // 堵住就等下一个EPOLLOUT事件，清掉已经发送的数据
                        nError = true;
                        CVecBuffer& vecBuf = pair.pVistor->vecSendBuf;
                        while (i > 0)
                        {
                            i--;
                            vecBuf.erase(vecBuf.begin());
                        }
                        break;
                    }
                    delete[] buf.pBuffer;
                    buf.pBuffer = nullptr;
                    buf.nLen = 0;

                    if (nRet == SOCKET_ERROR || nRet == 0)
                    {
                        PRINT_ERROR("%s Tun %s,%d: send to Vistor err %d to disconnect wsaerr %x\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet, WSAGetLastError());
                        // 访问者关闭，发结束消息给Server
                        CloseVistorSocket(pair);

                        nError = true;
                        break; // socket异常不发剩余数据
                    }
                }
                if (!nError)
                {
                    pair.pVistor->vecSendBuf.clear();
                    //pair.pVistor->Op = OP_READ;
                }
            }
        }
    }
    return nRet;
}

int TunClose(int nIndex, int sock)
{
    CLfrpSocket* pSocket = GetSockFromInstanceMap(sock);
    if (pSocket == nullptr)
    {
        PRINT_INFO("%s Tun %s,%d: SocketID %d cant find instance\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
        return 0;
    }

    // 类似上面的ProcessRead区分业务处理
    int nRet = 0;
    int nServiceNum = GetServiceNum(sock);
    int nThreadIndex = nServiceNum == -1 ? GetThreadIndexByNum(sock) : GetThreadIndexByNum(nServiceNum);
    if (nThreadIndex != nIndex)
    { // Socket可用会收到可读和可写，可读会trans，但第一个可写会进这里不匹配
        PRINT_ERROR("%s Tun %s,%d: TunClose SocketID %d thread index %d error\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock, nIndex);
        return 0;
    }
    
    if (nServiceNum != -1)
    {
        CSocketPairMap::iterator iter = pSocketPairMapAry[nIndex].find(nServiceNum);
        if (iter != pSocketPairMapAry[nIndex].end())
        {
            CSocketPair& pair = iter->second;
            if (pair.pServer && pair.pServer->sock == sock)
            {
                PRINT_ERROR("%s Tun %s,%d: server socketID %d close\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
                // ServerTun断开，成对关掉，不需要通知，Server和Vistor两端断开会清理
                CloseServerSocket(pair);
                DeleteSocketPair(pSocketPairMapAry[nIndex], nServiceNum, true);
                return 0;
            }
            else if (pair.pVistor && pair.pVistor->sock == sock)
            {
                PRINT_ERROR("%s Tun %s,%d: cli socketID %d close\n", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
                // 访问者关闭，发结束消息给Server
                CloseVistorSocket(pair);
                return 0;
            }
        }
    }

    PRINT_ERROR("%s Tun %s,%d: can't find socketID %d", GetCurTimeStr(), __FUNCTION__, __LINE__, sock);
    CloseSocketInstance(nIndex, sock);

    return -1;
}

int TunTimer()
{
    CommTimer();
    return 0;
}
#endif

int main(int argc, char** argv)
{
    int nRet = 0;
    PRINT_ERROR("%s Tun used as 'lfrpTun -p ListenPort -k AESKey', default is 'lfrpTun -p %d -k %s'\n", GetCurTimeStr(), nPort, strAesKey.c_str());
    int i = 0;
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 && i + 1 <= argc)
        {
            i++;
            strHost = argv[i];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 <= argc)
        {
            i++;
            nPort = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-k") == 0 && i + 1 <= argc)
        {
            i++;
            strAesKey = argv[i];
        }
    }

    // 初始化AES密钥信息
    CAES::GlobalInit(strAesKey.c_str());

    // 初始化socket
    InitSocket();

#ifdef USE_EPOLL
    InitLog("./Tun.txt");
    // 初始化epooll工作线程相关
    SetBusWorkerCallBack(TunRead, TunWrite, TunClose, TunProcessFirstRead, nullptr, TunTimer);
    InitWorkerThreads();
    pSocketPairMapAry = new CSocketPairMap[nThreadCount];
#endif

    // 监听端口
    SOCKET sockListen = INVALID_SOCKET;
#ifdef USE_EPOLL
    nRet = EpollListenSocket(epollfd, sockListen, strHost.c_str(), nPort);
    if (nRet != 0)
    {
        return 1;
    };

    mainEpoll(epollfd, sockListen);
    bExitPorcess = true;
#else
    nRet = ListenSocket(sockListen, strHost.c_str(), nPort);
    if (nRet != 0)
    {
        return 1;
    };

    mainSelect(sockListen);
#endif
}

