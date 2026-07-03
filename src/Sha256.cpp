/* ========================================================================== */
/**
 * @file    Sha256.cpp
 * @brief   SHA-256 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "sha256.h"
#include "secure.h"

#define ROTR(x, n)      (((x) >> (n)) | ((x) << (32 - (n))))

#define CH(x, y, z)     (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x)       (ROTR((x),  2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define SIGMA1(x)       (ROTR((x),  6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define sigma0(x)       (ROTR((x),  7) ^ ROTR((x), 18) ^ ((x) >>  3))
#define sigma1(x)       (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))

/* ========================================================================== */
/**
 * SHA-256 hash class
 */
/* ========================================================================== */

/* ========================================================================== */
/**
 * destructor
 *
 * erase calculation result
 * @param           none
 * @return          none
 */
/* ========================================================================== */
CSha256::~CSha256()
{
    secure_zero(m_H, sizeof(m_H));
    secure_zero(m_Buffer, sizeof(m_Buffer));
    m_Len = m_BufLen = 0;
}

/* ========================================================================== */
/**
 * initialize instance
 *
 * prepare calculation
 * @param           none
 * @return          none
 */
/* ========================================================================== */
VOID CSha256::Initialize(VOID)
{
    static const UINT32 Initial_H[8] =
    {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    memcpy(m_H, Initial_H, sizeof(m_H));
    m_Len = 0;
    m_BufLen = 0;
}


/* ========================================================================== */
/**
 * finish calculation
 *
 * calculate last part to get hash value
 * @param[out]      hash        pointer to store result
 * @return          none
 */
/* ========================================================================== */
VOID CSha256::Finish(UINT8 hash[32])
{
    static const UINT8 padding[64] =
    {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    UINT8 length[8];

    length[0] = (UINT8)(m_Len >> 53);
    length[1] = (UINT8)(m_Len >> 45);
    length[2] = (UINT8)(m_Len >> 37);
    length[3] = (UINT8)(m_Len >> 29);
    length[4] = (UINT8)(m_Len >> 21);
    length[5] = (UINT8)(m_Len >> 13);
    length[6] = (UINT8)(m_Len >>  5);
    length[7] = (UINT8)(m_Len <<  3);

    if ( m_BufLen < 56 )
    {
        Update(padding, 56 - m_BufLen);
    }
    else
    {
        Update(padding, 64 + 56 - m_BufLen);
    }

    Update(length, 8);

    for ( INT32 i = 0; i < 8; i++ )
    {
        hash[i * 4    ] = (UINT8)(m_H[i] >> 24);
        hash[i * 4 + 1] = (UINT8)(m_H[i] >> 16);
        hash[i * 4 + 2] = (UINT8)(m_H[i] >>  8);
        hash[i * 4 + 3] = (UINT8) m_H[i];
    }

    secure_zero(length, sizeof(length));
}


/* ========================================================================== */
/**
 * provide data for hash calculation
 *
 * update hash value using specified data
 * @param[in]       data        pointer to data for hash calculation
 * @param[in]       len         size of data
 * @return          none
 */
/* ========================================================================== */
VOID CSha256::Update(const UINT8 * data, SIZE_T len)
{
    m_Len += len;

    if ( m_BufLen + len < SHA256_BUFFER_SIZE )
    {
        memcpy(&m_Buffer[m_BufLen], data, len);
        m_BufLen += len;
        return;
    }

    if ( m_BufLen > 0 )
    {
        SIZE_T remain = SHA256_BUFFER_SIZE - m_BufLen;
        if ( remain > len )
        {
            remain = len;
        }
        memcpy(&m_Buffer[m_BufLen], data, remain);

        CalculateHash(m_Buffer);
        len -= remain;
        data += remain;
    }

    while ( len >= SHA256_BUFFER_SIZE )
    {
        CalculateHash(data);
        data += SHA256_BUFFER_SIZE;
        len -= SHA256_BUFFER_SIZE;
    }

    memcpy(m_Buffer, data, len);
    m_BufLen = len;
}


/* ========================================================================== */
/**
 * update hash value with one block data
 *
 * update hash value by calculation of specified one block data
 * @param[in]       data        pointer to one block data
 * @return          none
 */
/* ========================================================================== */
VOID CSha256::CalculateHash(const UINT8 data[64])
{
    UINT32 w[64];

    for ( INT32 i = 0; i < 16; i++ )
    {
        w[i] = ((UINT32)data[i * 4    ] << 24) |
               ((UINT32)data[i * 4 + 1] << 16) |
               ((UINT32)data[i * 4 + 2] <<  8) |
               ((UINT32)data[i * 4 + 3]      );
    }
    for ( INT32 i = 16; i < 64; i++ )
    {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }
    UpdateHash(w);
    secure_zero(w, sizeof(w));
}


/* ========================================================================== */
/**
 * update hash value
 *
 * update hash value with specified data
 * @param[in]       w           pointer to data
 * @return          none
 */
/* ========================================================================== */
VOID CSha256::UpdateHash(const UINT32 w[64])
{
    static const UINT32 K[64] =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    UINT32 a = m_H[0];
    UINT32 b = m_H[1];
    UINT32 c = m_H[2];
    UINT32 d = m_H[3];
    UINT32 e = m_H[4];
    UINT32 f = m_H[5];
    UINT32 g = m_H[6];
    UINT32 h = m_H[7];
    for ( INT32 i = 0; i < 64; i++ )
    {
        UINT32 T1 = h + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
        UINT32 T2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    m_H[0] += a;
    m_H[1] += b;
    m_H[2] += c;
    m_H[3] += d;
    m_H[4] += e;
    m_H[5] += f;
    m_H[6] += g;
    m_H[7] += h;
}

