#ifndef _AES_H_
#define _AES_H_
 
#pragma once

#define AES_BLOCK_SIZE  16

class CAES 
{
public:
    CAES();
    virtual ~CAES();

    static void GlobalInit(const char* key);

    /**
     * 加密
     * @param in 输入加密数据
     * @param inlen 输入加密数据长度
     * @param outlen 输出加密后数据长度
     * @param fill 如果不是16的整数倍，是否用0值补全。 true:用0值补全, false:用xor加密多余的数据
     * @return 返回加密后数据
     */
    void* Encrypt(void* in, int inlen, int& outlen, bool fill = false);

    /**
     * 解密
     * @param in 输入解密数据
     * @param inlen 输入解密数据长度
     * @param outlen 输出解密后数据长度
     * @return 返回解密后数据
     */
    void* Decrypt(void* in, int inlen, int& outlen);

private:
    /**
     * 密钥扩展函数 - 对128位密钥进行扩展得到 w[11][4][4]
     * @param key 16位密钥
     */
    static void KeyExpansion(const char* key);

    /**
     * 异或加解密
     * @param in 加解密输入数据
     * @param len 加解密输入数据长度
     */
    void Xor(unsigned char* in, int len);

    /**
     * 加密，传入的数组大小必须是16字节
     * @param data 加密数据
     */
    void Encrypt(unsigned char* data);

    /**
     * 解密，传入的数组也必须是16字节
     * @param data 解密数据
     */
    void Decrypt(unsigned char* data);

    /**
     * S 盒变换
     * @param state 变换数据
     */
    void SubBytes(unsigned char state[][4]);

    /**
     * 行变换
     * @param state 变换数据
     */
    void ShiftRows(unsigned char state[][4]);

    /**
     * 列变换
     * @param state 变换数据
     */
    void MixColumns(unsigned char state[][4]);

    /**
     * 与扩展密钥的异或
     * @param state 变换数据
     */
    void AddRoundKey(unsigned char state[][4], unsigned char k[][4]);

    /**
     * 逆 S 盒变换
     * @param state 变换数据
     */
    void InvSubBytes(unsigned char state[][4]);

    /**
     * 逆行变换
     * @param state 变换数据
     */
    void InvShiftRows(unsigned char state[][4]);

    /**
     * 逆列变换
     * @param state 变换数据
     */
    void InvMixColumns(unsigned char state[][4]);

private:
    // 本程序全局只用一个密钥，不用每次做初始化
    static char sKey[128];
    // S 盒变换
    static unsigned char Sbox[256];
    // 逆 S 盒变换
    static unsigned char InvSbox[256];
    // 密钥
    static unsigned char w[11][4][4];
};
 
#endif