/* ========================================================================== */
/**
 * @file    Sha512base.cpp
 * @brief   SHA-384/512 hash base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "sha512base.h"
#include "secure.h"

#define ROTR(x, n)      (((x) >> (n)) | ((x) << (64 - (n))))

#define CH(x, y, z)     (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x)       (ROTR((x), 28) ^ ROTR((x), 34) ^ ROTR((x), 39))
#define SIGMA1(x)       (ROTR((x), 14) ^ ROTR((x), 18) ^ ROTR((x), 41))
#define sigma0(x)       (ROTR((x),  1) ^ ROTR((x),  8) ^ ((x) >> 7))
#define sigma1(x)       (ROTR((x), 19) ^ ROTR((x), 61) ^ ((x) >> 6))

/* ========================================================================== */
/**
 * SHA-385/512 hash base class
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
CSha512Base::~CSha512Base()
{
    Initialize();
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
VOID CSha512Base::Initialize()
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
 * @param[in]       iv      initial vector
 * @return          none
 */
/* ========================================================================== */
VOID CSha512Base::Initialize(const UINT64 iv[8])
{
    Initialize();
    memcpy(m_H, iv, sizeof(UINT64) * 8);
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
VOID CSha512Base::Finish()
{
    static const UINT8 padding[128] =
    {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    UINT8 length[16];

    length[ 0] = 0;
    length[ 1] = 0;
    length[ 2] = 0;
    length[ 3] = 0;
    length[ 4] = 0;
    length[ 5] = 0;
    length[ 6] = 0;
    length[ 7] = (UINT8)(m_Len >> 61);
    length[ 8] = (UINT8)(m_Len >> 53);
    length[ 9] = (UINT8)(m_Len >> 45);
    length[10] = (UINT8)(m_Len >> 37);
    length[11] = (UINT8)(m_Len >> 29);
    length[12] = (UINT8)(m_Len >> 21);
    length[13] = (UINT8)(m_Len >> 13);
    length[14] = (UINT8)(m_Len >>  5);
    length[15] = (UINT8)(m_Len <<  3);

    if ( m_BufLen < 112 )
    {
        Update(padding, 112 - m_BufLen);
    }
    else
    {
        Update(padding, SHA512_BUFFER_SIZE + 112 - m_BufLen);
    }

    Update(length, 16);
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
VOID CSha512Base::Update(const UINT8 * data, SIZE_T len)
{
    m_Len += len;

    if ( m_BufLen + len < SHA512_BUFFER_SIZE )
    {
        memcpy(&m_Buffer[m_BufLen], data, len);
        m_BufLen += len;
        return;
    }

    if ( m_BufLen > 0 )
    {
        SIZE_T remain = SHA512_BUFFER_SIZE - m_BufLen;
        if ( remain > len )
        {
            remain = len;
        }
        memcpy(&m_Buffer[m_BufLen], data, remain);

        CalculateHash(m_Buffer);
        len -= remain;
        data += remain;
    }

    while ( len >= SHA512_BUFFER_SIZE )
    {
        CalculateHash(data);
        data += SHA512_BUFFER_SIZE;
        len -= SHA512_BUFFER_SIZE;
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
VOID CSha512Base::CalculateHash(const UINT8 data[128])
{
    UINT64 w[80];

    for ( INT32 i = 0; i < 16; i++ )
    {
        w[i] = ((UINT64)data[i * 8    ] << 56) |
               ((UINT64)data[i * 8 + 1] << 48) |
               ((UINT64)data[i * 8 + 2] << 40) |
               ((UINT64)data[i * 8 + 3] << 32) |
               ((UINT64)data[i * 8 + 4] << 24) |
               ((UINT64)data[i * 8 + 5] << 16) |
               ((UINT64)data[i * 8 + 6] <<  8) |
               ((UINT64)data[i * 8 + 7]      );
    }
    for ( INT32 i = 16; i < 80; i++ )
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
VOID CSha512Base::UpdateHash(const UINT64 w[80])
{
    static const UINT64 K[80] =
    {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1EULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    UINT64 a = m_H[0];
    UINT64 b = m_H[1];
    UINT64 c = m_H[2];
    UINT64 d = m_H[3];
    UINT64 e = m_H[4];
    UINT64 f = m_H[5];
    UINT64 g = m_H[6];
    UINT64 h = m_H[7];
    for ( INT32 i = 0; i < 80; i++ )
    {
        UINT64 T1 = h + SIGMA1(e) + CH(e, f, g) + K[i] + w[i];
        UINT64 T2 = SIGMA0(a) + MAJ(a, b, c);
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

