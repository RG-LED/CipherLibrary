/* ========================================================================== */
/**
 * @file    blake2b.cpp
 * @brief   BLAKE2b hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "blake2b.h"
#include "secure.h"

#define B2B_IV0 0x6a09e667f3bcc908ull
#define B2B_IV1 0xbb67ae8584caa73bull
#define B2B_IV2 0x3c6ef372fe94f82bull
#define B2B_IV3 0xa54ff53a5f1d36f1ull
#define B2B_IV4 0x510e527fade682d1ull
#define B2B_IV5 0x9b05688c2b3e6c1full
#define B2B_IV6 0x1f83d9abfb41bd6bull
#define B2B_IV7 0x5be0cd19137e2179ull

/* SIGMA table */
const UINT8 CBlake2b::m_SIGMA[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

CBlake2b::CBlake2b()
{
    Clear();
}

CBlake2b::~CBlake2b()
{
    Clear();
}

VOID CBlake2b::Clear()
{
    secure_zero(m_H, sizeof(m_H));
    secure_zero(m_T, sizeof(m_T));
    secure_zero(m_F, sizeof(m_F));
    secure_zero(m_Buf, sizeof(m_Buf));
    m_BufLen = 0;
}

BOOL CBlake2b::Initialize(const UINT8 * key, SIZE_T keylen, SIZE_T outlen)
{
    if ( outlen < 1 || outlen > 64 )
    {
        return FALSE;
    }

    if ( key == NULL )
    {
        keylen = 0;
    }
    else if ( keylen > 64 )
    {
        keylen = 64;
    }
    m_H[0] = B2B_IV0 ^ (0x01010000u | (UINT8)outlen | (keylen << 8));
    m_H[1] = B2B_IV1;
    m_H[2] = B2B_IV2;
    m_H[3] = B2B_IV3;
    m_H[4] = B2B_IV4;
    m_H[5] = B2B_IV5;
    m_H[6] = B2B_IV6;
    m_H[7] = B2B_IV7;
    m_T[0] = 0;
    m_T[1] = 0;
    m_F[0] = 0;
    m_F[1] = 0;
    m_BufLen = 0;
    m_OutLen = outlen;
    /* embed key block first if key exists */
    if ( keylen > 0 )
    {
        // corresponding to update(block,64)
        secure_zero(m_Buf, sizeof(m_Buf));
        memcpy(m_Buf, key, keylen);
        m_BufLen = BlockSize;
    }

    return TRUE;
}


VOID CBlake2b::Compress(const UINT8 block[128], INT32 is_last)
{
    UINT64 m[16];
    UINT64 v[16];

    for ( INT32 i = 0; i < 16; i++ )
    {
        m[i] =  (UINT64)block[i * 8 + 0] |
               ((UINT64)block[i * 8 + 1] <<  8) |
               ((UINT64)block[i * 8 + 2] << 16) |
               ((UINT64)block[i * 8 + 3] << 24) |
               ((UINT64)block[i * 8 + 4] << 32) |
               ((UINT64)block[i * 8 + 5] << 40) |
               ((UINT64)block[i * 8 + 6] << 48) |
               ((UINT64)block[i * 8 + 7] << 56);
    }

    for ( INT32 i = 0; i < 8; i++ )
    {
        v[i] = m_H[i];
    }
    v[ 8] = B2B_IV0;
    v[ 9] = B2B_IV1;
    v[10] = B2B_IV2;
    v[11] = B2B_IV3;
    v[12] = B2B_IV4 ^ m_T[0];
    v[13] = B2B_IV5 ^ m_T[1];
    v[14] = B2B_IV6 ^ (is_last ? 0xffffffffffffffffull : m_F[0]);
    v[15] = B2B_IV7 ^ m_F[1];

#define ROTR64(x, n)    (((x) >> (n)) | ((x) << (64u - (n))))
#define G(a, b, c, d, x, y) { \
    (a) = (a) + (b) + (x); (d) = ROTR64((d) ^ (a), 32); \
    (c) = (c) + (d);       (b) = ROTR64((b) ^ (c), 24); \
    (a) = (a) + (b) + (y); (d) = ROTR64((d) ^ (a), 16); \
    (c) = (c) + (d);       (b) = ROTR64((b) ^ (c), 63); }

    for ( INT32 r = 0; r < 12; r++ )
    {
        const UINT8 * s = m_SIGMA[r];
        G(v[0], v[4], v[ 8], v[12], m[s[ 0]], m[s[ 1]]);
        G(v[1], v[5], v[ 9], v[13], m[s[ 2]], m[s[ 3]]);
        G(v[2], v[6], v[10], v[14], m[s[ 4]], m[s[ 5]]);
        G(v[3], v[7], v[11], v[15], m[s[ 6]], m[s[ 7]]);
        G(v[0], v[5], v[10], v[15], m[s[ 8]], m[s[ 9]]);
        G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        G(v[2], v[7], v[ 8], v[13], m[s[12]], m[s[13]]);
        G(v[3], v[4], v[ 9], v[14], m[s[14]], m[s[15]]);
    }
    for ( INT32 i = 0; i < 8; i++ )
    {
        m_H[i] ^= v[i] ^ v[i + 8];
    }
}

VOID CBlake2b::Update(const VOID * in, SIZE_T inlen)
{
    const UINT8 * p = (const UINT8 *)in;

    while ( inlen > 0 )
    {
        if ( m_BufLen == BlockSize )
        {
            m_T[0] += BlockSize;
            if ( m_T[0] < BlockSize )
            {
                m_T[1]++; // 128 bit counter extension
            }
            Compress(m_Buf, 0);
            m_BufLen = 0;
        }
        SIZE_T space = BlockSize - m_BufLen;
        SIZE_T take = (inlen < space) ? inlen : space;
        memcpy(m_Buf + m_BufLen, p, take);
        m_BufLen += take;
        p += take;
        inlen -= take;
    }
}

VOID CBlake2b::Finish(UINT8 out[])
{
    m_T[0] += (UINT32)m_BufLen;
    if ( m_T[0] < m_BufLen )
    {
        m_T[1]++;
    }

    /* is_last=1 at last compress */
    UINT8 block[128] = { 0 };

    memcpy(block, m_Buf, m_BufLen);
    Compress(block, 1);

    for ( SIZE_T i = 0; i < m_OutLen; i++ )
    {
        out[i] = (UINT8)(m_H[i / 8] >> ((i % 8) * 8));
    }
}

