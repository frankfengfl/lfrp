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
    CBuffer buf;
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
        int nRet = LfrpRecv(pTunSocket);
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
                        CBuffer buf;
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
                    int nSeq = GetNextSeq(SEQ_CLIENT, pSocket->sock);
                    PRINT_INFO("%s Cli %s,%d: Svr socketID %d recv pack size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock, nRet, nSeq);

                    CBuffer buf;
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
                CBuffer& buf = pTunSocket->vecSendBuf[i];

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
                nRet = send(pTunSocket->sock, pSendBuffer, nSendLen, LFRP_SEND_FLAGS);
                while (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                { // 缓冲区堵塞等一下重发
                    PRINT_ERROR("%s Cli %s,%d: send to Tun err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSendLen);
                    Sleep(1);
                    nRet = send(pTunSocket->sock, pSendBuffer, nSendLen, LFRP_SEND_FLAGS);
                }
#ifdef USE_AES
                delete[] pSendBuffer;
#endif
                delete[] buf.pBuffer;
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
                    CBuffer& buf = pSocket->vecSendBuf[i];
                    if (buf.nLen > PACK_SIZE_DATA)
                    {
                        int nType, nPakLen, nSocketID, nSeq;
                        GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
                        PRINT_INFO("%s Cli %s,%d: Svr send socketID %d pack to User size %d seq %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nSocketID, buf.nLen - PACK_SIZE_DATA, nSeq);

                        //开始send
                        nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA, buf.nLen - PACK_SIZE_DATA, LFRP_SEND_FLAGS);
                        while (nRet == SOCKET_ERROR && IsReSendSocketError(WSAGetLastError()))
                        { // 缓冲区堵塞等一下重发
                            PRINT_ERROR("%s Cli %s,%d: send to User err size %d wsaerr WSAEWOULDBLOCK\n", GetCurTimeStr(), __FUNCTION__, __LINE__, buf.nLen - PACK_SIZE_DATA);
                            Sleep(1);
                            nRet = send(pSocket->sock, buf.pBuffer + PACK_SIZE_DATA, buf.nLen - PACK_SIZE_DATA, LFRP_SEND_FLAGS);
                        }
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
    pData[1] = PACK_TYPE_AUTH_VISTOR;
    pData[2] = PACK_SIZE_AUTH;
    pData[3] = nServiceNumber;
    pTunSocket->vecSendBuf.push_back(buf);
    pTunSocket->Op = OP_WRITE;
}

void SendNewClientBegin(CLfrpSocket* pSocket, CLfrpSocket* pTunSocket)
{
    CBuffer buf;
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

int main(int argc, char** argv)
{
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
    //clientService.sin_addr.s_addr = inet_addr(strSvr.c_str());
    clientService.sin_addr.s_addr = htonl(INADDR_ANY);  // 不限制，可以部署到局域网虚拟机，允许连
    clientService.sin_port = htons(nSvrPort);
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
    printf("%s [Server]监听 %s:%d\n", GetCurTimeStr(), strSvr.c_str(), nSvrPort); 

    CLfrpSocket sockTun;
    CSocketMap mapSvr;    // 业务服务代理连接

    if (ConnectSocket(&sockTun.sock, strTun.c_str(), nTunPort) != 0)
    {
        sockTun.sock = INVALID_SOCKET;
        printf("%s connect() Tun Failed: %d\n", GetCurTimeStr(), WSAGetLastError());
    }
    else
    {
        SendTunLogin(&sockTun);
    }

    unsigned int uLastTunSec = GetCurSecond();
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
                    if (ConnectSocket(&sockTun.sock, strTun.c_str(), nTunPort) != 0)
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
}
