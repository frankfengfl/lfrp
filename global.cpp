// global.cpp 
//

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>
#include "global.h"
#include "aes.h"

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

bool AddDataToSocketBuffer(char Buffer[], char*& pBuffer, int& nBufLen, int& nBufAlloc, char* pData, int nRet)
{
    // 拷贝数据
    if (nBufLen + nRet <= ELEM_BUFFER_SIZE)
    { // 只用Buffer
        memcpy(&(Buffer[nBufLen]), pData, nRet);
        nBufLen += nRet;
    }
    else
    { // 新数据存在pBuffer
        char* pNewBuf = nullptr;
        if (nBufLen + nRet > nBufAlloc)
        { // 原存储不够（原先存Buffer或pBuffer）
            // 2倍扩张
            if (nBufAlloc == 0)
                nBufAlloc = ELEM_BUFFER_SIZE * 2;     // 初始2倍
            while (nBufAlloc < nBufLen + nRet)
            {
                nBufAlloc = nBufAlloc * 2;
            }
            pNewBuf = new char[nBufAlloc];

            if (nBufLen > ELEM_BUFFER_SIZE)
            { // 原先数据存在pBuffer
                memcpy(pNewBuf, pBuffer, nBufLen);
                memcpy(&(pNewBuf[nBufLen]), pData, nRet);
                delete[] pBuffer;
                pBuffer = pNewBuf;
            }
            else
            { // 原先数据存在Buffer
                memcpy(pNewBuf, Buffer, nBufLen);
                memcpy(&(pNewBuf[nBufLen]), pData, nRet);
                pBuffer = pNewBuf;
            }
        }
        else
        { // 够的，肯定已经有pBuffer了，直接加数据即可
            memcpy(&(pBuffer[nBufLen]), pData, nRet);
        }

        nBufLen = nBufLen + nRet;
    }

    return true;
}

bool RemoveDataFromSocketBuffer(char Buffer[], char*& pBuffer, int& nBufLen, int& nBufAlloc, char* pBuf, int& nPackLen)
{
    if (nPackLen <= 0 || nBufLen < nPackLen)
        return false;

    if (nBufLen > ELEM_BUFFER_SIZE)
    {
        memcpy(pBuf, pBuffer, nPackLen);
        if (nBufLen - nPackLen > ELEM_BUFFER_SIZE)
        { //仍存pBuffer
            memmove(pBuffer, &(pBuffer[nPackLen]), nBufLen - nPackLen);
        }
        else
        { // 移到Buffer
            memcpy(Buffer, &(pBuffer[nPackLen]), nBufLen - nPackLen);
            delete[] pBuffer;
            pBuffer = nullptr;
            nBufAlloc = 0;
        }
    }
    else
    {
        memcpy(pBuf, Buffer, nPackLen);
        memmove(Buffer, &(Buffer[nPackLen]), nBufLen - nPackLen);
    }

    nBufLen -= nPackLen;
    nPackLen = 0;

    return true;
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
        PRINT_INFO("Svr %s,%d: LfrpRecv recv pack size %d\n ", __FUNCTION__, __LINE__, nRet);
#ifdef USE_AES
        // 先加数据到编码缓存
        AddDataToSocketBuffer(pSocket->EncBuffer, pSocket->pEncBuffer, pSocket->nEncBufLen, pSocket->nEncBufAlloc, Buffer, nRet);
        if (pSocket->nEncBufLen >= AES_BLOCK_SIZE)
        { // 有足够的解码数据了
            int nPackLen = pSocket->nEncBufLen / AES_BLOCK_SIZE * AES_BLOCK_SIZE;   // 取整块
            char* pBuf = new char[nPackLen];
            if (pBuf)
            {
                int nDecPackLen = nPackLen;
                if (RemoveDataFromSocketBuffer(pSocket->EncBuffer, pSocket->pEncBuffer, pSocket->nEncBufLen, pSocket->nEncBufAlloc, pBuf, nPackLen))
                {
                    CAES cAes;
                    int nDecLen = 0;
                    char* pDec = (char*)cAes.Decrypt(pBuf, nDecPackLen, nDecLen);
                    if (pDec && nDecLen >= AES_BLOCK_SIZE)   // 接触包至少有一个AES_BLOCK_SIZE，否则就是有问题
                    {
                        bool bAddHeader = false;
                        char* pData = pDec;
                        int nDataLen = nDecLen;
                        if (pSocket->nBufLen < PACK_SIZE_HEADER)
                        { // 原先不够，拷贝包头大小过去解析，否则如果原先有头信息了，不需要拷贝节省性能
                            bAddHeader = true;
                        }
                        // 一次可能收到多个包，循环处理
                        while (nDataLen >= AES_BLOCK_SIZE)
                        {
                            if (bAddHeader)
                            { // 原先不够，拷贝包头大小过去解析，否则如果原先有头信息了，不需要拷贝节省性能
                                PRINT_INFO("%s,%d: Add header size %d\n ", __FUNCTION__, __LINE__, PACK_SIZE_HEADER);
                                AddDataToSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, pData, PACK_SIZE_HEADER);
                                pData += PACK_SIZE_HEADER;
                                nDataLen -= PACK_SIZE_HEADER;
                            }
                            ParsePackHeader(pSocket);

                            int nBufLen = 0;
                            int nPackLen = 0;
                            // Buffer里可能多个包，需要连到最后一个包上。取出最后一个包已经收到的数据，以及包大小
                            GetLastPackLenInfo(pSocket, nBufLen, nPackLen);     
                            if (nBufLen + nDataLen > nPackLen)
                            { // 如果包收全了，解码包里才会有补码，跳过补码
                                int nFillLen = ((nPackLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE - nPackLen;
                                PRINT_INFO("%s,%d: aes fill size %d\n ", __FUNCTION__, __LINE__, nFillLen);
                                //if (nFillLen)
                                {
                                    int nRPackLen = nPackLen - nBufLen; // 剩余包大小是整个包大小减去已经移到Buffer里的
                                    if (nRPackLen > 0)
                                    { // 剩余包还有内容，先填入
                                        PRINT_INFO("%s,%d: Add nRPackLen size %d\n ", __FUNCTION__, __LINE__, nRPackLen);
                                        AddDataToSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, pData, nRPackLen);
                                    }
                                    pData = pData + nRPackLen + nFillLen;
                                    nDataLen = nDataLen - nRPackLen - nFillLen;
                                }
                                
                                // 剩余nDataLen是下个包，继续解析
                                bAddHeader = true;  // 下个包需要先添加包头
                                //continue;
                            }
                            else
                            {
                                // 如果包还没收全或正好收全，不会碰到补码，直接添加
                                if (nDataLen)
                                {
                                    PRINT_INFO("%s,%d: Add rest nDataLen size %d\n ", __FUNCTION__, __LINE__, nDataLen);
                                    AddDataToSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, pData, nDataLen);
                                    nDataLen = 0;
                                }
                            }
                        }
                        
                        delete[] pDec;
                    }
                    else
                    {
                        PRINT_ERROR("%s,%d: aes decrypt error\n ", __FUNCTION__, __LINE__);
                    }
                }
                delete[] pBuf;
            }
            else
            {
                PRINT_ERROR("%s,%d: new buffer error size %d\n ", __FUNCTION__, __LINE__, nPackLen);
            }
        }
        
#else
        AddDataToSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, Buffer, nRet);
#endif

        ParsePackHeader(pSocket);
    }
    return nRet;
}

void CopyOnePack(CLfrpSocket* pSocket, char* pBuf)
{
    if (RemoveDataFromSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, pBuf, pSocket->nPackLen))
    {
        pSocket->nType = PACK_TYPE_UNKNOW;

        // 取走包要看下一个包内容，用于粘包时业务连续处理
        ParsePackHeader(pSocket);
    }
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

void GetLastPackLenInfo(CLfrpSocket* pSocket, int& nBufLen, int& nPackLen)
{
    char* pBuffer = GetSocketBuffer(pSocket);
    nBufLen = pSocket->nBufLen;
    nPackLen = pSocket->nPackLen;
    if (pBuffer)
    {
        while (nBufLen > nPackLen)
        {
            nBufLen -= nPackLen;
            pBuffer += nPackLen;
            int* pData = (int*)pBuffer;
            nPackLen = pData[2];    // 这个函数这里肯定有足够的头了，直接取
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
