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
#include "globalEpoll.h"
#ifndef _WIN32
#include<sys/time.h>
#include <stdarg.h>
int geterror() { return errno; }
#endif

#ifdef _WIN32
#pragma comment(lib,"ws2_32.lib")
#endif

CLfrpSocket::CLfrpSocket()
{
    InitMember();
}

CLfrpSocket::~CLfrpSocket()
{
    ClearBuffer();
}

void CLfrpSocket::InitMember()
{
    sock = INVALID_SOCKET;
    Op = 0;
    nMagicNum = MAGIC_NUMBER;
    nType = PACK_TYPE_UNKNOW;
    nPackLen = 0;
    nServiceNumber = -1;
    nSocketID = INVALID_SOCKET;
    nPackSeq = 0;
    nAcceptSec = 0;
    nLastRecvSec = 0;

    nBufLen = 0;
    pBuffer = nullptr;
    nBufAlloc = 0;
    memset(Buffer, 0, ELEM_BUFFER_SIZE);

#ifdef USE_AES
    pEncBuffer = nullptr;
    nEncBufAlloc = 0;
    nEncBufLen = 0;
    memset(EncBuffer, 0, ELEM_BUFFER_SIZE);
#endif
}

void CLfrpSocket::ClearBuffer()
{
    if (pBuffer)
    {
        delete[] pBuffer;
        pBuffer = nullptr;
        nBufAlloc = 0;
    }

#ifdef USE_AES
    if (pEncBuffer)
    {
        delete[] pEncBuffer;
        pEncBuffer = nullptr;
        nEncBufAlloc = 0;
    }
    nEncBufLen = 0;
    memset(EncBuffer, 0, ELEM_BUFFER_SIZE);
#endif

    Op = 0;
    nType = PACK_TYPE_UNKNOW;
    nBufLen = 0;
    nPackLen = 0;
    //nServiceNumber = -1;
    nSocketID = INVALID_SOCKET;
    nPackSeq = 0;
    memset(Buffer, 0, ELEM_BUFFER_SIZE);

    for (int i = 0; i < vecSendBuf.size(); i++)
    {
        CBuffer& buf = vecSendBuf[i];
        if (buf.pBuffer)
        {
            delete[] buf.pBuffer;
        }
    }
    vecSendBuf.clear();
}

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
            else
            {
                // 公网上会有网络扫描，类似Cookie: mstshash = Administr
                return -110;
            }
        }
    }

    if (pSocket->nType == PACK_TYPE_AUTH_SERVER || pSocket->nType == PACK_TYPE_AUTH_VISTOR)
    {
        if (pSocket->nBufLen >= PACK_SIZE_AUTH)
        {
            int* pStream = (int*)GetSocketBuffer(pSocket);
            pSocket->nServiceNumber = pStream[3];
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
    else if (pSocket->nType == PACK_TYPE_HEART_BEAT)
    {
        if (pSocket->nBufLen >= PACK_SIZE_HEADER)
        {
            // nothing added for Tun pack
        }
    }

    return 0;
}

int ParsePackHeader(char* pBuffer, int nBufLen, int& nType, int& nPackLen)
{
    if (nBufLen >= PACK_SIZE_HEADER)
    {
        int* pStream = (int*)pBuffer;
        if (pStream[0] == MAGIC_NUMBER)
        {
            nType = pStream[1];
            nPackLen = pStream[2];
        }
        else
        {
            // 公网上会有网络扫描，类似Cookie: mstshash = Administr
            return -110;
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

char* GetSocketEncBuffer(CLfrpSocket* pSocket)
{
    if (pSocket->nEncBufLen > ELEM_BUFFER_SIZE)
    {
        return pSocket->pEncBuffer;
    }
    else
    {
        return pSocket->EncBuffer;
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

int AddAESRecvData(CLfrpSocket* pSocket, char* Buffer, int nRet)
{
    pSocket->nLastRecvSec = GetCurSecond();
    PRINT_INFO("%s %s,%d: LfrpRecv recv pack size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet);
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
                            //PRINT_INFO("%s %s,%d: Add header size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, PACK_SIZE_HEADER);
                            AddDataToSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, pData, PACK_SIZE_HEADER);
                            pData += PACK_SIZE_HEADER;
                            nDataLen -= PACK_SIZE_HEADER;
                        }
                        int nParseRet = ParsePackHeader(pSocket);
                        if (nParseRet < 0)
                        {
                            // 如果是非法包，长度不够到这里10s还没收到认证包会断开，长度足够进入这个逻辑需要跳出
                            PRINT_ERROR("%s %s,%d: receive illegal Pack size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet);
                            delete[] pDec;
                            delete[] pBuf;
                            return nParseRet;
                        }

                        int nBufLen = 0;
                        int nPackLen = 0;
                        // Buffer里可能多个包，需要连到最后一个包上。取出最后一个包已经收到的数据，以及包大小
                        GetLastPackLenInfo(pSocket, nBufLen, nPackLen);
                        if (nBufLen + nDataLen > nPackLen)
                        { // 如果包收全了，解码包里才会有补码，跳过补码
                            int nFillLen = ((nPackLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE - nPackLen;
                            //PRINT_INFO("%s %s,%d: aes fill size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nFillLen);
                            //if (nFillLen)
                            {
                                int nRPackLen = nPackLen - nBufLen; // 剩余包大小是整个包大小减去已经移到Buffer里的
                                if (nRPackLen > 0)
                                { // 剩余包还有内容，先填入
                                    //PRINT_INFO("%s %s,%d: Add nRPackLen size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRPackLen);
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
                                //PRINT_INFO("%s %s,%d: Add rest nDataLen size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nDataLen);
                                AddDataToSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, pData, nDataLen);
                                nDataLen = 0;
                            }
                        }
                    }

                    delete[] pDec;
                }
                else
                {
                    PRINT_ERROR("%s %s,%d: aes decrypt error\n", GetCurTimeStr(), __FUNCTION__, __LINE__);
                }
            }
            delete[] pBuf;
        }
        else
        {
            PRINT_ERROR("%s %s,%d: new buffer error size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nPackLen);
        }
    }

#else
    AddDataToSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, Buffer, nRet);
#endif

    // 非AES加密的首个包在这里解析
    int nParseRet = ParsePackHeader(pSocket);
    if (nParseRet < 0)
    {
        return nParseRet;
    }
    return nRet;
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
        if (AddTunAESRecvData(pSocket, Buffer, nRet) < 0)
            return -1;
    }
    return nRet;
}

int AddTunAESRecvData(CLfrpSocket* pSocket, char* Buffer, int nRet)
{
    pSocket->nLastRecvSec = GetCurSecond();
    PRINT_INFO("%s Svr %s,%d: LfrpRecv recv pack size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet);
    // 先加数据到编码缓存
    AddDataToSocketBuffer(pSocket->EncBuffer, pSocket->pEncBuffer, pSocket->nEncBufLen, pSocket->nEncBufAlloc, Buffer, nRet);
    if (pSocket->nEncBufLen >= AES_BLOCK_SIZE)
    { // 有足够的解码数据了
        CAES cAes;
        int nDecLen = 0;
        char* pDecHeader = (char*)cAes.Decrypt(GetSocketEncBuffer(pSocket), AES_BLOCK_SIZE, nDecLen);
        int nType = PACK_TYPE_UNKNOW;
        int nPackLen = 0;

        // Parse AES package header
        int nParseRet = ParsePackHeader(pDecHeader, nDecLen, nType, nPackLen);
        if (nParseRet < 0)
        {
            // 如果是非法包，长度不够到这里10s还没收到认证包会断开，长度足够进入这个逻辑需要跳出
            PRINT_ERROR("%s %s,%d: receive illegal Pack size %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nRet);
            return nParseRet;
        }

        int nEncBufLen = ((nPackLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        int nFillLen = nEncBufLen - nPackLen;
        if (pSocket->nEncBufLen >= nEncBufLen)
        { // 包接收完全了
            if (nType == PACK_TYPE_AUTH_SERVER || nType == PACK_TYPE_AUTH_VISTOR)
            { // 认证包
                char buf[AES_BLOCK_SIZE];
                RemoveDataFromSocketBuffer(pSocket->EncBuffer, pSocket->pEncBuffer, pSocket->nEncBufLen, pSocket->nEncBufAlloc, buf, nEncBufLen);

                if (nPackLen <= nDecLen)
                { // 包已经解码完全了
                    AddDataToSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, pDecHeader, nPackLen);
                    ParsePackHeader(pSocket);
                }
                else
                { // 认证包目前16字节，不会超过
                    PRINT_ERROR("%s %s,%d: Auth Pack Size %d is bigger than decode len %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nPackLen, nDecLen);
                }
            }
            else if (nType == PACK_TYPE_HEART_BEAT)
            {// 心跳包丢弃
                char buf[AES_BLOCK_SIZE];
                RemoveDataFromSocketBuffer(pSocket->EncBuffer, pSocket->pEncBuffer, pSocket->nEncBufLen, pSocket->nEncBufAlloc, buf, nEncBufLen);
                if (nPackLen > nDecLen)
                { // 心跳包目前12字节，不会超过16字节
                    PRINT_ERROR("%s %s,%d: HeartBeat Pack Size %d is bigger than decode len %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nPackLen, nDecLen);
                }
            }
        }
    }

    // 非AES加密的首个包在这里解析
    int nParseRet = ParsePackHeader(pSocket);
    if (nParseRet < 0)
    {
        return nParseRet;
    }
    return nRet;
}

// 通道接收AES数据转发
int LfrpTunAESRecv(CLfrpSocket* pSocket)
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
        if (AddTunAESRecvData(pSocket, Buffer, nRet) < 0)
            return -1;
    }
    return nRet;
}

void FetchOnePack(CLfrpSocket* pSocket, char* pBuf)
{
    if (RemoveDataFromSocketBuffer(pSocket->Buffer, pSocket->pBuffer, pSocket->nBufLen, pSocket->nBufAlloc, pBuf, pSocket->nPackLen))
    {
        pSocket->nType = PACK_TYPE_UNKNOW;

        // 取走包要看下一个包内容，用于粘包时业务连续处理
        ParsePackHeader(pSocket);
    }
}

bool MoveSendPack(CLfrpSocket* pSrcSocket, CLfrpSocket* pDesSocket)
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
                MoveSendPack(pSrcSocket, pDesSocket);
            }
            else if (pSrcSocket->nType >= PACK_TYPE_TUN_BEG && pSrcSocket->nType <= PACK_TYPE_TUN_END)
            {
                MoveSendPack(pSrcSocket, pDesSocket);
            }
            else if (pSrcSocket->nType == PACK_TYPE_HEART_BEAT)
            { // 中间如果有心跳包，取掉包进下一个循环
                DropOnePack(pSrcSocket);
                ParsePackHeader(pSrcSocket);
                MoveSendPack(pSrcSocket, pDesSocket);
            }
        }
    }
    return bDestSend;
}

bool MoveSendAESPack(CLfrpSocket* pSrcSocket, CLfrpSocket* pDesSocket)
{
    bool bDestSend = false;
    // 如果源有多个数据包，一次转过去
    while (pSrcSocket->nEncBufLen >= AES_BLOCK_SIZE)
    { // 有足够的解码数据了
        CAES cAes;
        int nDecLen = 0;
        char* pDecHeader = (char*)cAes.Decrypt(GetSocketEncBuffer(pSrcSocket), AES_BLOCK_SIZE, nDecLen);
        int nType = PACK_TYPE_UNKNOW;
        int nPackLen = 0;

        // Parse AES package header
        int nParseRet = ParsePackHeader(pDecHeader, nDecLen, nType, nPackLen);
        if (nParseRet < 0)
        {
            // 如果是非法包，长度不够到这里10s还没收到认证包会断开，长度足够进入这个逻辑需要跳出
            PRINT_ERROR("%s %s,%d: receive illegal Pack size ret %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, nParseRet);
            return nParseRet;
        }

        int nEncBufLen = ((nPackLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        int nFillLen = nEncBufLen - nPackLen;
        if (pSrcSocket->nEncBufLen >= nEncBufLen)
        { // 包接收完全了
            CBuffer buf;
            buf.nLen = nEncBufLen;
            buf.pBuffer = new char[nEncBufLen];
            RemoveDataFromSocketBuffer(pSrcSocket->EncBuffer, pSrcSocket->pEncBuffer, pSrcSocket->nEncBufLen, pSrcSocket->nEncBufAlloc, buf.pBuffer, nEncBufLen);
            if (nType == PACK_TYPE_HEART_BEAT)
            { // 心跳包丢弃
                delete[] buf.pBuffer;
            }
            else
            {
                pDesSocket->vecSendBuf.push_back(buf);
                bDestSend = true;
            }
        }
        else
        {
            break; //还未接收完成，这个AES头白解了，不过一般接收不完是大包，一个AES块白解还好
        }
    }

    return bDestSend;
}

void DropOnePack(CLfrpSocket* pSocket)
{
    if (pSocket->nPackLen > RECV_BUFFER_SIZE + PACK_SIZE_HEADER_MAX)
    {
        char* pBuffer = new char[pSocket->nPackLen];
        FetchOnePack(pSocket, pBuffer);
        delete[] pBuffer;
    }
    else
    { // 不用new节约性能
        char buffer[RECV_BUFFER_SIZE + PACK_SIZE_HEADER_MAX];
        FetchOnePack(pSocket, buffer);
    }
}

void MakeHeartBeatPack(CBuffer& buf)
{
    buf.pBuffer = new char[PACK_SIZE_HEADER];
    buf.nLen = PACK_SIZE_HEADER;
    int* pData = (int*)buf.pBuffer;
    pData[0] = MAGIC_NUMBER;
    pData[1] = PACK_TYPE_HEART_BEAT;
    pData[2] = buf.nLen; 
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
    buf.pBuffer = new char[PACK_SIZE_HEADER];
    buf.nLen = PACK_SIZE_HEADER;
    int* pData = (int*)buf.pBuffer;
    pData[0] = MAGIC_NUMBER;
    pData[1] = PACK_TYPE_TUN_END;
    pData[2] = buf.nLen;
}

void EncryptBuffer(CBuffer& buf)
{
    if (buf.nLen <= 0)
        return;

    int nEncLen = 0;
    CAES cAes;
    char* pEncBuffer = (char*)cAes.Encrypt(buf.pBuffer, buf.nLen, nEncLen, true);
    delete[] buf.pBuffer;
    buf.pBuffer = pEncBuffer;
    buf.nLen = nEncLen;
}

void CloseLfrpSocket(CLfrpSocket* pSocket)
{
    if (pSocket == nullptr)
        return;
    PRINT_INFO("%s %s,%d: close socketID %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pSocket->sock);

#ifdef USE_EPOLL
    EpollDeleteEvent(epollfd, pSocket->sock, DEFAULT_EPOLL_STAT);
    SetServiceNum(pSocket->sock, -1);
    RemoveSockFromInstanceMap(pSocket->sock);

    // todo, 关闭socket前需要清楚worker线程的待做buf，否则复用socket句柄会变成另外的消息，会触发误读写失败？
    // 最主要问题是运行错线程导致锁失败，目前是靠事件处理前再判断一次线程是否正确，这个无法从逻辑上保证，可能检测后再加入其他线程了
    AddDelayClose(pSocket->sock);   // 延迟关闭，避免太早复用事件错乱
#else
    if (pSocket->sock != INVALID_SOCKET)
    {
#ifdef _WIN32
        closesocket(pSocket->sock);
#else
        close(pSocket->sock);
#endif
    }
#endif

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
                int nServiceNumber = pData[3];
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
        else if (nType == PACK_TYPE_HEART_BEAT)
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

int CheckConnected(SOCKET& sockCon)
{
#ifdef _WIN32
    unsigned long mode = 0;
    int iRet = ioctlsocket(sockCon, FIONBIO, &mode);
#else
    int iRet = fcntl(sockCon, F_SETFL, (fcntl(sockCon, F_GETFL, 0) & ~O_NONBLOCK));
#endif
    if (iRet != NO_ERROR)
    {
        PRINT_ERROR("%s %s,%d: connect socket %s:%d ioctlsocket error %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, iRet);
    }

    timeval timeval = { 0 };
    timeval.tv_sec = 0;
    timeval.tv_usec = 3 * 1000 * 1000;

    fd_set Write, Err;
    FD_ZERO(&Write);
    FD_ZERO(&Err);
    FD_SET(sockCon, &Write);
    FD_SET(sockCon, &Err);

    select(sockCon + 1, NULL, &Write, &Err, &timeval);
    if (FD_ISSET(sockCon, &Write))
    {
        return 0;
    }
    else
    {
#ifdef _WIN32
        closesocket(sockCon);
#else
        close(sockCon);
#endif
        sockCon = INVALID_SOCKET;
        return -3;
    }
}

int PreConnectSocket(SOCKET& sockCon, const char* pIPAddress, int nPort)
{
    //创建套接字
    sockCon = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockCon == INVALID_SOCKET)
    {
        return -2;
    }

#ifdef _WIN32
    int TimeOut = 2 * 1000;			//设置发送超时2秒
    if (::setsockopt(sockCon, SOL_SOCKET, SO_SNDTIMEO, (char*)&TimeOut, sizeof(TimeOut)) == SOCKET_ERROR)
    {
        PRINT_ERROR("%s %s,%d: connect socket %s:%d setopt SendTimeout %d error\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pIPAddress, nPort, TimeOut);
    }

    TimeOut = 2 * 1000;			//设置接收超时2秒
    if (::setsockopt(sockCon, SOL_SOCKET, SO_RCVTIMEO, (char*)&TimeOut, sizeof(TimeOut)) == SOCKET_ERROR)
    {
        PRINT_ERROR("%s %s,%d: connect socket %s:%d setopt RecvTimeout %d error\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pIPAddress, nPort, TimeOut);
    }
#else
    timeval timevalSendRecv = { 3, 0 };
    if (::setsockopt(sockCon, SOL_SOCKET, SO_SNDTIMEO, (char*)&timevalSendRecv, sizeof(timevalSendRecv)) == SOCKET_ERROR)
    {
        PRINT_ERROR("%s %s,%d: connect socket %s:%d setopt SendTimeout %d error\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pIPAddress, nPort, 3);
    }
    if (::setsockopt(sockCon, SOL_SOCKET, SO_RCVTIMEO, (char*)&timevalSendRecv, sizeof(timevalSendRecv)) == SOCKET_ERROR)
    {
        PRINT_ERROR("%s %s,%d: connect socket %s:%d setopt RecvTimeout %d error\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pIPAddress, nPort, 3);
    }
#endif

    // 设置TCP的NoDelay，避免小包延迟
    int enable = 1;
    if (setsockopt(sockCon, IPPROTO_TCP, TCP_NODELAY, (char*)&enable, sizeof(enable)) == SOCKET_ERROR)
    {
        PRINT_ERROR("%s %s,%d: connect socket %s:%d setopt TCP_NODELAY error\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pIPAddress, nPort);
    }

    return 0;
}
int ProcssConnectSocket(SOCKET& sockCon, const char* pIPAddress, int nPort)
{
    sockaddr_in addrSrv;
#ifdef _WIN32
    addrSrv.sin_addr.S_un.S_addr = inet_addr(pIPAddress);
#else
    addrSrv.sin_addr.s_addr = inet_addr(pIPAddress);
#endif
    addrSrv.sin_family = AF_INET;
    addrSrv.sin_port = htons(nPort);

    /* 非阻塞式连接 */
#ifdef _WIN32
    unsigned long mode = 1;
    int iRet = ioctlsocket(sockCon, FIONBIO, &mode);
#else
    int flags;
    flags = fcntl(sockCon, F_GETFL, NULL);
    int iRet = fcntl(sockCon, F_SETFL, flags | O_NONBLOCK);
#endif
    if (iRet != NO_ERROR)
    {
        PRINT_ERROR("%s %s,%d: connect socket %s:%d ioctlsocket error %d\n", GetCurTimeStr(), __FUNCTION__, __LINE__, pIPAddress, nPort, iRet);
    }

    int conn_ret = connect(sockCon, (sockaddr*)&addrSrv, sizeof(sockaddr));
    return conn_ret;
}

int ConnectSocket(SOCKET& sockCon, const char* pIPAddress, int nPort)
{
    if (PreConnectSocket(sockCon, pIPAddress, nPort) < 0)
    {
        return 0;
    }
    
    int conn_ret = ProcssConnectSocket(sockCon, pIPAddress, nPort);
#ifdef USE_EPOLL
    return conn_ret;
#else
    return CheckConnected(sockCon);
#endif
}

int InitSocket()
{
#ifdef _WIN32
    int nStartup = 0;
    WSADATA wsaData;
    if (0 != (nStartup = WSAStartup(MAKEWORD(2, 2), &wsaData)))
    {
        WSASetLastError(nStartup); //WSAStartup不会自动设置错误代码
        Print_ErrCode("WSAStartup()");
        return -1;
    }
#elif defined(USE_EPOLL)
    // 初始化epoll相关
    EpollInit();
#endif

    return 0;
}

int ListenSocket(SOCKET& sockListen, const char* pIPAddress, int nPort)
{
    struct sockaddr_in clientService;
    sockListen = INVALID_SOCKET;
    int nRet = 0;

    clientService.sin_family = AF_INET;
    //clientService.sin_addr.s_addr = inet_addr(pIPAddress);
    clientService.sin_addr.s_addr = htonl(INADDR_ANY);  // 通道服务不限制
    clientService.sin_port = htons(nPort);
    if (INVALID_SOCKET ==
        (sockListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))
        )
    {
        Print_ErrCode("socket()");
        return -1;
    }

    // 端口释放后立即就可以被再次使用。
    int opt = 1;
    setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

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
        return -1;
    }
    if (SOCKET_ERROR == listen(sockListen, DEFAULT_BACKLOG))
    {
        Print_ErrCode("listen()");
#ifdef _WIN32
        closesocket(sockListen);
#else
        close(sockListen);
#endif
        return -1;
    }
    printf("%s [Server]监听 %s:%d\n", GetCurTimeStr(), pIPAddress, nPort); 

    return 0;
}

bool IsReSendSocketError(int nError)
{
#ifdef _WIN32
    return (nError == WSAEWOULDBLOCK);
#else
    return (nError == EAGAIN || nError == EWOULDBLOCK || nError == EINTR);
#endif
}

unsigned int GetCurSecond()
{
#ifdef _WIN32
    return (unsigned int)GetTickCount() / 1000;
#else
    struct timeval tm;
    float timeuse;
    gettimeofday(&tm, NULL);
    return tm.tv_sec;
#endif
}

// 此函数务必单线程使用，里面使用了静态变量
const char* GetCurTimeStr()
{
    // 获取当前系统时间
    time_t currentTime = time(nullptr);

    // 将时间转换为本地时间
    tm* localTime = localtime(&currentTime);

    // 使用 std::strftime 函数将时间格式化为字符串
    static char timeString[100];
    strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", localTime);

    return timeString;
}

FILE* pFile = nullptr;
std::mutex mtxLogFile;
void InitLog(const char* file)
{
    pFile = fopen(file, "wa+");
}

void PrintToFile(const char* format, ...)
{
    if (pFile)
    {
#define LOG_BUFFER_SIZE 10 * 1024
        char ay[LOG_BUFFER_SIZE] = { 0 };
        va_list va;
        va_start(va, format);
        vsnprintf(ay, LOG_BUFFER_SIZE, format, va);
        //vsprintf(ay, format, va);
        //vsprintf(format, va);
        va_end(va);
        int nLen = strlen(ay);
        std::unique_lock<std::mutex> lock(mtxLogFile);
        fwrite(ay, sizeof(char), nLen, pFile);
        fflush(pFile);
    }
}

std::vector<std::string> stringSplit(const std::string& str, char delim) 
{
    std::size_t previous = 0;
    std::size_t current = str.find(delim);
    std::vector<std::string> elems;
    while (current != std::string::npos) {
        if (current > previous) {
            elems.push_back(str.substr(previous, current - previous));
        }
        previous = current + 1;
        current = str.find(delim, previous);
    }
    if (previous != str.size()) {
        elems.push_back(str.substr(previous));
    }
    return elems;
}

std::vector<int> TransStrToInt(std::vector<std::string>& vecStr)
{
    std::vector<int> vecInt;
    for (int i = 0; i < vecStr.size(); i++)
    {
        vecInt.push_back(atoi(vecStr[i].c_str()));
    }
    return vecInt;
}
