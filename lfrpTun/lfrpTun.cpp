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

#pragma comment(lib,"ws2_32.lib")

CSocketPairMap mapSocketPair;   // 提供服务和访问者对
CSocketVec vecSocket;          // 刚建立连接，还未判断类型的临时socket

// 服务监听端口信息
std::string strHost = "127.0.0.1";
int nPort = 6868;

// AES key
std::string strAesKey = "asdf1234567890";

void ProcessRead(CSocketPairMap& mapSocketPair, fd_set& fdRead)
{
    int nRet = 0;
    std::vector<int> vecDelPair;
    // 处理所有socket对的收数据
    for (iterSockets iter = mapSocketPair.begin(); iter != mapSocketPair.end(); iter++)
    {
        CSocketPair pair = iter->second;
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
                CloseLfrpSocket(pair.pServer);
                if (pair.pVistor)
                {
                    PRINT_ERROR("%s Tun %s,%d: Vistor SocketID %d disconnect because server disconnet\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->sock);
                    CloseLfrpSocket(pair.pVistor);
                }
            }
            else
            {
#ifdef USE_AES
                if (MoveSendAESPack(pair.pServer, pair.pVistor))
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

                // 访问者关闭，发结束消息给Server
                CBuffer buf;
                MakeTunEndPack(buf);
#ifdef USE_AES
                // lfrpTun的vecSendBuf里存AES加密后的数据，避免重复加解密
                EncryptBuffer(buf);
#endif
                iter->second.pServer->vecSendBuf.push_back(buf);
                iter->second.pServer->Op = OP_WRITE;
                CloseLfrpSocket(iter->second.pVistor);
                delete iter->second.pVistor;  
                iter->second.pVistor = nullptr;
            }
            else
            {
#ifdef USE_AES
                if (MoveSendAESPack(pair.pVistor, pair.pServer))
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
                                CBuffer buf;
                                MakeTunEndPack(buf);
#ifdef USE_AES
                                // lfrpTun的vecSendBuf里存AES加密后的数据，避免重复加解密
                                EncryptBuffer(buf);
#endif
                                iter->second.pServer->vecSendBuf.push_back(buf);
                                iter->second.pServer->Op = OP_WRITE;
                                CloseLfrpSocket(iter->second.pVistor);
                                delete iter->second.pVistor;
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
        CSocketPair pair = iter->second;
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
                        CloseLfrpSocket(pair.pServer);
                        if (pair.pVistor)
                        {
                            PRINT_ERROR("%s Tun %s,%d: Vistor SocketID %d disconnect because server disconnet\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pair.pVistor->sock);
                            CloseLfrpSocket(pair.pVistor);
                        }

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
                        CBuffer buf;
                        MakeTunEndPack(buf);
#ifdef USE_AES
                        // lfrpTun的vecSendBuf里存AES加密后的数据，避免重复加解密
                        EncryptBuffer(buf);
#endif
                        iter->second.pServer->vecSendBuf.push_back(buf);
                        iter->second.pServer->Op = OP_WRITE;
                        CloseLfrpSocket(iter->second.pVistor);
                        delete iter->second.pVistor;
                        iter->second.pVistor = nullptr;

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
}

int main(int argc, char** argv)
{
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
    //clientService.sin_addr.s_addr = inet_addr(strHost.c_str());
    clientService.sin_addr.s_addr = htonl(INADDR_ANY);  // 通道服务不限制
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
#ifdef _WIN32
        closesocket(sockListen);
#else
        close(sockListen);
#endif
        return 1;
    }
    if (SOCKET_ERROR == listen(sockListen, DEFAULT_BACKLOG))
    {
        Print_ErrCode("listen()");
#ifdef _WIN32
        closesocket(sockListen);
#else
        close(sockListen);
#endif
    }
    printf("%s [Server]监听 %s:%d\n", GetCurTimeStr(), strHost.c_str(), nPort);    //存放所有的socket，包括用于accept的socket。
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

            //这个操作会被阻塞
#ifdef _WIN32
            nRet = select(0, &fdRead, &fdWrite, NULL, NULL);
#else
            nRet = select(maxSock + 1, &fdRead, &fdWrite, NULL, NULL);
#endif
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
}

