// global.cpp 
//

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include "global.h"

#pragma comment(lib,"ws2_32.lib")

void LfrpSetFD(CLfrpSocket* pSocket, fd_set& fdRead, fd_set& fdWrite)
{
    if (pSocket != nullptr)
    {
        //对需要send的客户端连接select
        if (pSocket->Op == OP_WRITE)
        {
            FD_SET(pSocket->sock, &fdWrite);
        }
        //对所有的客户端连接select
        FD_SET(pSocket->sock, &fdRead);
    }
}

int ParsePackHeader(CLfrpSocket* pSocket)
{
    if (pSocket->nType == PACK_TYPE_UNKNOW)
    {
        if (pSocket->nBufLen >= PACK_SIZE_HEADER)
        {
            int* pStream = (int*)GetSocketBuffer(pSocket);
            if (pStream[0] == MAGIC_NUMBER)
            {
                pSocket->nType = pStream[1];
                pSocket->nPackLen = pStream[2];
            }
        }
    }

    if (pSocket->nType == PACK_TYPE_AUTH_SERVER || pSocket->nType == PACK_TYPE_AUTH_VISTOR)
    {
        if (pSocket->nBufLen >= PACK_SIZE_AUTH)
        {
            int* pStream = (int*)GetSocketBuffer(pSocket);
            pSocket->nServerNumber = pStream[3];
        }
    }
    else if (pSocket->nType >= PACK_TYPE_DATA_BEG && pSocket->nType <= PACK_TYPE_DATA_END)
    {
        if (pSocket->nBufLen >= PACK_SIZE_DATA)
        {
            int* pStream = (int*)GetSocketBuffer(pSocket);
            pSocket->nSocketID = pStream[3];
            pSocket->nPackSeq = pStream[4];
        }
    }
    else if (pSocket->nType >= PACK_TYPE_TUN_BEG && pSocket->nType <= PACK_TYPE_TUN_END)
    {
        if (pSocket->nBufLen >= PACK_SIZE_HEADER)
        {
            // nothing added for Tun pack
        }
    }

    return 0;
}

char* GetSocketBuffer(CLfrpSocket* pSocket)
{
    if (pSocket->nBufLen > ELEM_BUFFER_SIZE)
    {
        return pSocket->pBuffer;
    }
    else
    {
        return pSocket->Buffer;
    }
}

int LfrpRecv(CLfrpSocket* pSocket)
{
    if (pSocket == nullptr)
    {
        return 0;
    }

    //开始recv
    char Buffer[RECV_BUFFER_SIZE];
    int nRet = recv(pSocket->sock, Buffer, RECV_BUFFER_SIZE, 0);
    if (nRet == SOCKET_ERROR || nRet == 0)   // 远端断开触发=0
    {
        return nRet;
    }
    else if (nRet > 0)
    {
        // 拷贝数据
        if (pSocket->nBufLen + nRet <= ELEM_BUFFER_SIZE)
        { // 只用Buffer
            memcpy(&(pSocket->Buffer[pSocket->nBufLen]), Buffer, nRet);
            pSocket->nBufLen += nRet;
        }
        else
        { // 新数据存在pBuffer
            char* pBuffer = nullptr;
            if (pSocket->nBufLen + nRet > pSocket->nBufAlloc)
            { // 原存储不够（原先存Buffer或pBuffer）
                // 2倍扩张
                if (pSocket->nBufAlloc == 0) 
                    pSocket->nBufAlloc = ELEM_BUFFER_SIZE * 2;     // 初始2倍
                while (pSocket->nBufAlloc < pSocket->nBufLen + nRet)
                {
                    pSocket->nBufAlloc = pSocket->nBufAlloc * 2;
                }
                pBuffer = new char[pSocket->nBufAlloc];

                if (pSocket->nBufLen > ELEM_BUFFER_SIZE)
                { // 原先数据存在pBuffer
                    memcpy(pBuffer, pSocket->pBuffer, pSocket->nBufLen);
                    memcpy(&(pBuffer[pSocket->nBufLen]), Buffer, nRet);
                    delete[] pSocket->pBuffer;
                    pSocket->pBuffer = pBuffer;
                }
                else
                { // 原先数据存在Buffer
                    memcpy(pBuffer, pSocket->Buffer, pSocket->nBufLen);
                    memcpy(&(pBuffer[pSocket->nBufLen]), Buffer, nRet);
                    pSocket->pBuffer = pBuffer;
                }
            }
            else
            { // 够的，肯定已经有pBuffer了，直接加数据即可
                pBuffer = pSocket->pBuffer;
                memcpy(&(pBuffer[pSocket->nBufLen]), Buffer, nRet);
            }
            
            pSocket->nBufLen = pSocket->nBufLen + nRet;  
        }

        ParsePackHeader(pSocket);
    }
    return nRet;
}

void CopyOnePack(CLfrpSocket* pSocket, char* pBuf)
{
    if (pSocket->nPackLen <= 0 && pSocket->nBufLen >= pSocket->nPackLen)
        return;

    if (pSocket->nBufLen > ELEM_BUFFER_SIZE)
    {
        memcpy(pBuf, pSocket->pBuffer, pSocket->nPackLen);
        if (pSocket->nBufLen - pSocket->nPackLen > ELEM_BUFFER_SIZE)
        { //仍存pBuffer
            memmove(pSocket->pBuffer, &(pSocket->pBuffer[pSocket->nPackLen]), pSocket->nBufLen - pSocket->nPackLen);
        }
        else
        { // 移到Buffer
            memcpy(pSocket->Buffer, &(pSocket->pBuffer[pSocket->nPackLen]), pSocket->nBufLen - pSocket->nPackLen);
            delete[] pSocket->pBuffer;
            pSocket->pBuffer = nullptr;
            pSocket->nBufAlloc = 0;
        }
    }
    else
    {
        memcpy(pBuf, pSocket->Buffer, pSocket->nPackLen);
        if (pSocket->nBufLen > pSocket->nPackLen)
        {
            memmove(pSocket->Buffer, &(pSocket->Buffer[pSocket->nPackLen]), pSocket->nBufLen - pSocket->nPackLen);
        }
    }

    pSocket->nBufLen -= pSocket->nPackLen;
    pSocket->nPackLen = 0;
    pSocket->nType = PACK_TYPE_UNKNOW;

    // 取走包要看下一个包内容，用于粘包时业务连续处理
    ParsePackHeader(pSocket);
}

int MoveSendPack(CLfrpSocket* pSrcSocket, CLfrpSocket* pDesSocket)
{
    bool bDestSend = false;
    if (pSrcSocket->nBufLen >= pSrcSocket->nPackLen && pSrcSocket->nPackLen > 0)
    {
        if (pDesSocket)
        {
            CBuffer buf;
            buf.nLen = pSrcSocket->nPackLen;
            buf.pBuffer = new char[pSrcSocket->nPackLen];
            CopyOnePack(pSrcSocket, buf.pBuffer);
            pDesSocket->vecSendBuf.push_back(buf);
            //pair.pVistor->Op = OP_WRITE;
            bDestSend = true;

            int nType, nPakLen, nSocketID, nSeq;
            GetInfoFromBuf(buf, nType, nPakLen, nSocketID, nSeq);
            PRINT_INFO("%s,%d: socketID %d trans pack size %d seq %d\n ", __FUNCTION__, __LINE__, nSocketID, nPakLen, nSeq);

            // 如果源有多个数据包，一次转过去
            ParsePackHeader(pSrcSocket);
            if (pSrcSocket->nType >= PACK_TYPE_DATA_BEG && pSrcSocket->nType <= PACK_TYPE_DATA_END)
            {
                MoveSendPack(pSrcSocket, pDesSocket);
            }
            else if (pSrcSocket->nType >= PACK_TYPE_TUN_BEG && pSrcSocket->nType <= PACK_TYPE_TUN_END)
            {
                MoveSendPack(pSrcSocket, pDesSocket);
            }
        }
    }
    return bDestSend;
}

void DropOnePack(CLfrpSocket* pSocket)
{
    if (pSocket->nPackLen > RECV_BUFFER_SIZE + PACK_SIZE_HEADER_MAX)
    {
        char* pBuffer = new char[pSocket->nPackLen];
        CopyOnePack(pSocket, pBuffer);
        delete[] pBuffer;
    }
    else
    { // 不用new节约性能
        char buffer[RECV_BUFFER_SIZE + PACK_SIZE_HEADER_MAX];
        CopyOnePack(pSocket, buffer);
    }
}

void MakeDataEndPack(CBuffer& buf,int nSocketID, int nSeq)
{
    buf.pBuffer = new char[PACK_SIZE_DATA];
    buf.nLen = PACK_SIZE_DATA;
    int* pData = (int*)buf.pBuffer;
    pData[0] = MAGIC_NUMBER;
    pData[1] = PACK_TYPE_DATA_END;
    pData[2] = buf.nLen;
    pData[3] = nSocketID; // pSocket->nSocketID;
    pData[4] = nSeq; // pSocket->nPackSeq;
}

void MakeTunEndPack(CBuffer& buf)
{
    buf.pBuffer = new char[PACK_SIZE_DATA];
    buf.nLen = PACK_SIZE_HEADER;
    int* pData = (int*)buf.pBuffer;
    pData[0] = MAGIC_NUMBER;
    pData[1] = PACK_TYPE_TUN_END;
    pData[2] = buf.nLen;
}

void CloseLfrpSocket(CLfrpSocket* pSocket)
{
    closesocket(pSocket->sock);
    pSocket->ClearBuffer();
    pSocket->sock = INVALID_SOCKET;
}

CSeqMap mapSeq; 
int GetNextSeq(SeqEnum nType, int nSocketID)
{
    // 无效连接或者刚开始连接Seq都为0
    if (nSocketID == INVALID_SOCKET)
    {
        return 0;
    }

    int nRetSeq = 0;
    CSeqMap::iterator iter = mapSeq.find(nSocketID);
    if (iter == mapSeq.end())
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
        mapSeq.insert(std::make_pair(nSocketID, nSeqBeg+1));
    }
    else
    {
        nRetSeq = iter->second;
        iter->second++;
    }
    return nRetSeq;
}

void RemoveSeqKey(int nSocketID)
{
    CSeqMap::iterator iter = mapSeq.find(nSocketID);
    if (iter != mapSeq.end())
    {
        mapSeq.erase(iter);
    }
}

void GetInfoFromBuf(CBuffer& buf, int& nType, int& nLen, int& nSocketID, int& nSeq)
{
    nType = PACK_TYPE_UNKNOW;
    nSocketID = INVALID_SOCKET;
    nLen = 0;
    nSeq = 0;
    if (buf.nLen > PACK_SIZE_HEADER)
    {
        int* pData = (int*)buf.pBuffer;
        nType = pData[1];
        nLen = pData[2];
        if (nType == PACK_TYPE_AUTH_SERVER || nType == PACK_TYPE_AUTH_VISTOR)
        {
            if (nLen >= PACK_SIZE_AUTH)
            {
                int nServerNumber = pData[3];
            }
        }
        else if (nType >= PACK_TYPE_DATA_BEG && nType <= PACK_TYPE_DATA_END)
        {
            if (nLen >= PACK_SIZE_DATA)
            {
                nSocketID = pData[3];
                nSeq = pData[4];
            }
        }
        else if (nType >= PACK_TYPE_TUN_BEG && nType <= PACK_TYPE_TUN_END)
        {
            if (nLen >= PACK_SIZE_HEADER)
            {
                // nothing to get
            }
        }
    }
}

int ConnectSocket(SOCKET* pSocket, const char* pIPAddress, int nPort)
{
    //创建套接字
    *pSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (*pSocket == INVALID_SOCKET)
    {
        return -2;
    }

    int TimeOut = 2*1000;			//设置发送超时2秒
    if (::setsockopt(*pSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&TimeOut, sizeof(TimeOut)) == SOCKET_ERROR)
    {
        PRINT_ERROR("%s,%d: connect socket %s:%d setopt SendTimeout %d error\n ", __FUNCTION__, __LINE__, pIPAddress, nPort, TimeOut);
    }

    TimeOut = 2*1000;			//设置接收超时2秒
    if (::setsockopt(*pSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&TimeOut, sizeof(TimeOut)) == SOCKET_ERROR)
    {
        PRINT_ERROR("%s,%d: connect socket %s:%d setopt RecvTimeout %d error\n ", __FUNCTION__, __LINE__, pIPAddress, nPort, TimeOut);
    }

    // 设置TCP的NoDelay，避免小包延迟
    int enable = 1;
    if (setsockopt(*pSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&enable, sizeof(enable)) == SOCKET_ERROR)
    {
        PRINT_ERROR("%s,%d: connect socket %s:%d setopt TCP_NODELAY error\n ", __FUNCTION__, __LINE__, pIPAddress, nPort);
    }
    
    SOCKADDR_IN addrSrv;
    addrSrv.sin_addr.S_un.S_addr = inet_addr(pIPAddress);
    addrSrv.sin_family = AF_INET;
    addrSrv.sin_port = htons(nPort);

    /* 非阻塞式连接 */
    unsigned long mode = 1;
    int iRet = ioctlsocket(*pSocket, FIONBIO, &mode);
    if (iRet != NO_ERROR)
    {
        PRINT_ERROR("%s,%d: connect socket %s:%d ioctlsocket error %d\n ", __FUNCTION__, __LINE__, pIPAddress, nPort, iRet);
    }
    
    int conn_ret = connect(*pSocket, (sockaddr*)&addrSrv, sizeof(sockaddr));

    mode = 0;
    iRet = ioctlsocket(*pSocket, FIONBIO, &mode);
    if (iRet != NO_ERROR)
    {
        PRINT_ERROR("%s,%d: connect socket %s:%d ioctlsocket error %d\n ", __FUNCTION__, __LINE__, pIPAddress, nPort, iRet);
    }

    TIMEVAL timeval = { 0 };
    timeval.tv_sec = 0;
    timeval.tv_usec = 950 * 1000;

    fd_set Write, Err;
    FD_ZERO(&Write);
    FD_ZERO(&Err);
    FD_SET(*pSocket, &Write);
    FD_SET(*pSocket, &Err);

    select(*pSocket + 1, NULL, &Write, &Err, &timeval);
    if (FD_ISSET(*pSocket, &Write))
    {
        return 0;
    }
    else
    {
        closesocket(*pSocket);
        pSocket = nullptr;
        return -3;
    }
}

std::string GetCurTimeStr()
{
    // 获取当前系统时间
    std::time_t currentTime = std::time(nullptr);

    // 将时间转换为本地时间
    std::tm* localTime = std::localtime(&currentTime);

    // 使用 std::strftime 函数将时间格式化为字符串
    char timeString[100];
    std::strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", localTime);

    return timeString;
}
