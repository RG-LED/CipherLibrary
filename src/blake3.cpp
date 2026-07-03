/* ========================================================================== */
/**
 * @file    blake3.cpp
 * @brief   BLAKE3 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "blake3.h"
#include "secure.h"

#define CHUNK_START 0x01    // 0 first block (64B) within a chunk (1024B)
#define CHUNK_END   0x02    // 1 last block within a chunk
#define PARENT      0x04    // 2 calculating parent node of tree
#define ROOT        0x08    // 3 calculating root node of tree
#define KEYED_HASH  0x10    // 4 keyed hash mode
#define DERIVE_KEY  0x20    // 5 derived key mode

#define B3_IV0 0x6a09e667u
#define B3_IV1 0xbb67ae85u
#define B3_IV2 0x3c6ef372u
#define B3_IV3 0xa54ff53au
#define B3_IV4 0x510e527fu
#define B3_IV5 0x9b05688cu
#define B3_IV6 0x1f83d9abu
#define B3_IV7 0x5be0cd19u

const UINT32 CBlake3::IV[8] = {
    B3_IV0, B3_IV1, B3_IV2, B3_IV3,
    B3_IV4, B3_IV5, B3_IV6, B3_IV7
};

/* SIGMA table */
const UINT8 CBlake3::m_SIGMA[7][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    {  2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8 },
    {  3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1 },
    { 10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6 },
    { 12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4 },
    {  9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7 },
    { 11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13 }
};


CBlake3::CBlake3()
{
    Initialize();
}


CBlake3::~CBlake3()
{
    Initialize();
}


VOID CBlake3::Initialize()
{
    secure_zero(m_stack, sizeof(m_stack));
    secure_zero(m_buf, sizeof(m_buf));
    m_counter = 0;
    m_bufLen = 0;
}


VOID CBlake3::Compress(UINT32 out[16], const UINT32 cv[8], const UINT8 block[64], SIZE_T block_len, UINT64 counter, UINT32 flags)
{
    UINT32 m[16];
    UINT32 v[16];

    for ( INT32 i = 0; i < 16; i++ )
    {
        m[i] =  (UINT32)block[i * 4 + 0] |
               ((UINT32)block[i * 4 + 1] <<  8) |
               ((UINT32)block[i * 4 + 2] << 16) |
               ((UINT32)block[i * 4 + 3] << 24);
    }

    for (INT32 i = 0; i < 8; i++ )
    {
        v[i] = cv[i];
    }
    v[ 8] = B3_IV0;
    v[ 9] = B3_IV1;
    v[10] = B3_IV2;
    v[11] = B3_IV3;
    v[12] = (UINT32)counter;
    v[13] = (UINT32)(counter >> 32);
    v[14] = (UINT32)block_len;
    v[15] = flags;

#define ROTR32(x, n)    (((x) >> (n)) | ((x) << (32u - (n))))
#define G(a, b, c, d, x, y) { \
    (a) = (a) + (b) + (x); (d) = ROTR32((d) ^ (a), 16); \
    (c) = (c) + (d);       (b) = ROTR32((b) ^ (c), 12); \
    (a) = (a) + (b) + (y); (d) = ROTR32((d) ^ (a),  8); \
    (c) = (c) + (d);       (b) = ROTR32((b) ^ (c),  7); }

    for ( INT32 r = 0; r < 7; r++ )
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
        out[i + 8] = v[i + 8] ^ cv[i]; // this line first in case 'out' and 'cv' are overlapped
        out[i] = v[i] ^ v[i + 8];
    }

    secure_zero(m, sizeof(m));
    secure_zero(v, sizeof(v));
}


VOID CBlake3::ProcessChunk()
{
    UINT32 cv[8];
    UINT32 cvout[16];

    memcpy(cv, IV, sizeof(cv));

    for ( INT32 i = 0; i < 16; i++ )
    {
        UINT32 flags = 0;
        if ( i == 0 )
        {
            flags |= CHUNK_START;
        }
        if ( i == 15 )
        {
            flags |= CHUNK_END;
        }

        Compress(cvout, cv, &m_buf[i * 64], 64, m_counter, flags);
        memcpy(cv, cvout, sizeof(cv));
    }
    // push cv (32 bytes) into stack
    PushStack(cv, m_counter);

    secure_zero(cv, sizeof(cv));
    secure_zero(cvout, sizeof(cvout));
}


VOID CBlake3::PushStack(const UINT32 cv[8], UINT64 chunk_idx)
{
    UINT32 current_cv[8];
    UINT32 cvout[16];
    memcpy(current_cv, cv, 32);

    // loop while LSB is 1 (right child exists) shifting chunk_count right
    INT32 i;
    for ( i = 0; (chunk_idx >> i) & 1; i++ )
    {
        // extract 'left child' from stack, and join with 'right child'
        // flag has PARENT because it will be parent node
        // counter of parent note is always 0, and its block_len is 64
        UINT8 block[64];
        memcpy(block, m_stack[i], 32);      // left child
        memcpy(block + 32, current_cv, 32); // right child

        Compress(cvout, IV, block, 64, 0, PARENT);
        memcpy(current_cv, cvout, sizeof(current_cv));
    }

    // store proper depth of stack for next joining
    memcpy(m_stack[i], current_cv, 32);

    secure_zero(current_cv, sizeof(current_cv));
    secure_zero(cvout, sizeof(cvout));
}


VOID CBlake3::Update(const UINT8 * in, SIZE_T inlen)
{
    while ( inlen > 0 )
    {
        if ( m_bufLen == sizeof(m_buf) )
        {
            ProcessChunk();
            m_counter++;
            m_bufLen = 0;
        }
        SIZE_T take = sizeof(m_buf) - m_bufLen;
        if ( take > inlen )
        {
            take = inlen;
        }

        memcpy(m_buf + m_bufLen, in, take);
        m_bufLen += take;
        in += take;
        inlen -= take;
    }
}


VOID CBlake3::Finish(UINT8 out[32])
{
    Finish();
    GetOutput(out, 32);
}


VOID CBlake3::Finish()
{
    UINT32 cv[8];
    UINT32 cvout[16];

    if ( m_bufLen == 0 )
    {
        secure_zero(m_buf, 64);
        Compress(cvout, IV, m_buf, 0, 0, CHUNK_START | CHUNK_END | ROOT);
        memcpy(m_rootCv, IV, sizeof(m_rootCv));
        memcpy(m_rootSrc, m_buf, sizeof(m_rootSrc));
        m_rootLen = 0;
        m_rootFlags = CHUNK_START | CHUNK_END | ROOT;
        memcpy(cv, cvout, sizeof(cv));
    }
    else
    {
        SIZE_T buflen = m_bufLen;

        memcpy(cv, IV, sizeof(cv));
        for ( INT32 i = 0; i < 16 && buflen > 0; i++ )
        {
            UINT32 flags = 0;
            SIZE_T len = 64;
            if ( i == 0 )
            {
                flags |= CHUNK_START;
            }
            if ( buflen <= 64 )
            {
                len = buflen;
                flags |= CHUNK_END;
                secure_zero(&m_buf[i * 64 + len], 64 - len);
                if ( m_counter == 0 )
                {
                    flags |= ROOT;
                }
            }

            Compress(cvout, cv, &m_buf[i * 64], len, m_counter, flags);
            if ( flags & ROOT )
            {
                memcpy(m_rootCv, cv, sizeof(m_rootCv));
                memcpy(m_rootSrc, &m_buf[i * 64], sizeof(m_rootSrc));
                m_rootLen = len;
                m_rootFlags = flags;
            }
            memcpy(cv, cvout, sizeof(cv));
            buflen -= len;
        }

        if ( m_counter > 0 )
        {
            INT32 lsb;
            INT32 msb;
            lsb = SearchBitPosition(m_counter, &msb);
            for ( INT32 i = lsb; i <= msb; i++ )
            {
                if ( ((m_counter >> i) & 1) != 0 )
                {
                    UINT32 flags = PARENT;
                    if ( i == msb )
                    {
                        flags |= ROOT;
                    }
                    UINT8 block[64];
                    memcpy(block, m_stack[i], 32);  // left child
                    memcpy(block + 32, cv, 32);     // right child

                    Compress(cvout, IV, block, 64, 0, flags);
                    if ( flags & ROOT )
                    {
                        memcpy(m_rootCv, IV, sizeof(m_rootCv));
                        memcpy(m_rootSrc, block, sizeof(m_rootSrc));
                        m_rootLen = 64;
                        m_rootFlags = flags;
                    }
                    memcpy(cv, cvout, sizeof(cv));
                }
            }
        }
    }
    memcpy(m_outBuf, cvout, sizeof(m_outBuf));
    m_outBufLen = 64;
    m_counter = 1;

    secure_zero(cv, sizeof(cv));
    secure_zero(cvout, sizeof(cvout));
}


VOID CBlake3::GetOutput(UINT8 * out, SIZE_T len)
{
    while ( len > 0 )
    {
        if ( m_outBufLen == 0 )
        {
            UINT32 cvout[16];
            Compress(cvout, m_rootCv, m_rootSrc, m_rootLen, m_counter, m_rootFlags);
            m_counter++;
            for ( INT32 i = 0; i < 16; i++ )
            {
                m_outBuf[i * 4 + 0] = (UINT8)(cvout[i]);
                m_outBuf[i * 4 + 1] = (UINT8)(cvout[i] >>  8);
                m_outBuf[i * 4 + 2] = (UINT8)(cvout[i] >> 16);
                m_outBuf[i * 4 + 3] = (UINT8)(cvout[i] >> 24);
            }
            m_outBufLen = 64;
        }
        SIZE_T take = (len > m_outBufLen) ? m_outBufLen : len;
        memcpy(out, &m_outBuf[64 - m_outBufLen], take);
        out += take;
        m_outBufLen -= take;
        len -= take;
    }
}


INT32 CBlake3::SearchBitPosition(UINT64 n, INT32 * msb)
{
    INT32 lsb = -1;
    INT32 m = -1;

    for ( INT32 i = 0; i < 64; i++ )
    {
        if ( (n & ((UINT64)1u << i)) != 0 )
        {
            m = i;
            if ( lsb < 0 )
            {
                lsb = i;
            }
        }
    }
    *msb = m;
    return lsb;
}

