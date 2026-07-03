/* ========================================================================== */
/**
 * @file    shakebase.cpp
 * @brief   SHAKE128/256 hash base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "shakebase.h"
#include "secure.h"

#define ROL64(x, n) (((x) << ((n) & 63)) | ((x) >> (64 - ((n) & 63))))

/* ======== load/store little-endian ======== */
UINT64 CShakeBase::Load64le(const UINT8 *p)
{
    UINT64 v = 0;
    for (INT32 i = 0; i < 8; i++)
    {
        v |= (UINT64)p[i] << (8 * i);
    }
    return v;
}

VOID CShakeBase::Store64le(UINT8 *p, UINT64 v)
{
    for (INT32 i = 0; i < 8; i++)
    {
        p[i] = (UINT8)(v >> (8 * i));
    }
}

/* ======== Keccak-f[1600] permutation (24 rounds) ======== */
VOID CShakeBase::Keccakf1600()
{
    /* ======== Keccak-f[1600] constants ======== */
    static const UINT64 KECCAKF_ROUND_CONST[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };

    static const INT32 keccakf_rotc[24] = {
         1,  3,  6, 10, 15, 21, 28, 36,
        45, 55,  2, 14, 27, 41, 56,  8,
        25, 43, 62, 18, 39, 61, 20, 44
    };
    static const INT32 keccakf_piln[24] = {
        10,  7, 11, 17, 18,  3,  5, 16,
         8, 21, 24,  4, 15, 23, 19, 13,
        12,  2, 20, 14, 22,  9,  6,  1
    };

    UINT64 bc[5];

    for ( INT32 round = 0; round < 24; round++ )
    {
        for ( INT32 i = 0; i < 5; i++ )
        {
            bc[i] = m_A[i] ^ m_A[i + 5] ^ m_A[i + 10] ^ m_A[i + 15] ^ m_A[i + 20];
        }
        for ( INT32 i = 0; i < 5; i++ )
        {
            UINT64 d = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
            for ( INT32 j = 0; j < 25; j += 5 )
            {
                m_A[j + i] ^= d;
            }
        }
        UINT64 t = m_A[1];
        for ( INT32 i = 0; i < 24; i++ )
        {
            INT32 j = keccakf_piln[i];
            UINT64 tmp = m_A[j];
            m_A[j] = ROL64(t, keccakf_rotc[i]);
            t = tmp;
        }
        for ( INT32 j = 0; j < 25; j += 5 )
        {
            UINT64 b0 = m_A[j+0];
            UINT64 b1 = m_A[j+1];
            UINT64 b2 = m_A[j+2];
            UINT64 b3 = m_A[j+3];
            UINT64 b4 = m_A[j+4];
            m_A[j+0] = b0 ^ ((~b1) & b2);
            m_A[j+1] = b1 ^ ((~b2) & b3);
            m_A[j+2] = b2 ^ ((~b3) & b4);
            m_A[j+3] = b3 ^ ((~b4) & b0);
            m_A[j+4] = b4 ^ ((~b0) & b1);
        }
        m_A[0] ^= KECCAKF_ROUND_CONST[round];
    }

    secure_zero(bc, sizeof(bc));
}

/* ======== SHAKE256 context & API ======== */

CShakeBase::CShakeBase()
{
    Clear();
}

CShakeBase::~CShakeBase()
{
    Clear();
}

VOID CShakeBase::Clear()
{
    secure_zero(m_A, sizeof(m_A));
    secure_zero(m_Q, sizeof(m_Q));
    m_Qlen = 0;
}

VOID CShakeBase::Absorb(const UINT8 * in, SIZE_T inlen)
{
    SIZE_T i;
    /* If there is buffered data, fill to a block first */
    if ( m_Qlen )
    {
        SIZE_T take = m_rate - m_Qlen;
        if ( take > inlen )
        {
            take = inlen;
        }
        memcpy(m_Q + m_Qlen, in, take);
        m_Qlen += take;
        in += take;
        inlen -= take;
        if ( m_Qlen < m_rate )
        {
            return;
        }
        /* XOR the block into state and permute */
        for ( i = 0; i < m_rate / 8; i++ )
        {
            m_A[i] ^= Load64le(m_Q + 8 * i);
        }
        Keccakf1600();
        m_Qlen = 0;
    }
    /* Absorb full blocks directly from input */
    while ( inlen >= m_rate )
    {
        for ( i = 0; i < m_rate / 8; i++ )
        {
            m_A[i] ^= Load64le(in + 8 * i);
        }
        Keccakf1600();
        in += m_rate;
        inlen -= m_rate;
    }
    /* Buffer remaining */
    if ( inlen )
    {
        memcpy(m_Q, in, inlen);
        m_Qlen = inlen;
    }
}

/* apply domain separation + padding, then one permutation */
VOID CShakeBase::Finish()
{
    /* domain separation suffix (0x1F for SHAKE), then pad10*1 (0x80 at block end) */
    m_Q[m_Qlen++] = SHAKE_DSBYTE;
#if 0
    if ( m_Qlen >= m_rate )
    { /* should not happen for SHAKE, but be safe */
        while ( m_Qlen < m_rate )
        {
            m_Q[m_Qlen++] = 0;
        }
        for ( SIZE_T i = 0; i < m_rate / 8; i++ )
        {
            m_A[i] ^= Load64le(m_Q + 8*i);
        }
        Keccakf1600();
        m_Qlen = 0;
    }
#endif
    while ( m_Qlen < m_rate )
    {
        m_Q[m_Qlen++] = 0;
    }
    m_Q[m_rate - 1] ^= 0x80; /* final bit 1 */
    for ( SIZE_T i = 0; i < m_rate / 8; i++ )
    {
        m_A[i] ^= Load64le(m_Q + 8 * i);
    }
    Keccakf1600();
    m_Qlen = 0; /* ready to squeeze */
}

VOID CShakeBase::Squeeze(UINT8 * out, SIZE_T outlen)
{
    while ( outlen )
    {
        UINT8 buf[MAX_SHAKE_RATE];
        for ( SIZE_T i = 0; i < m_rate / 8; i++ )
        {
            Store64le(buf + 8 * i, m_A[i]);
        }
        SIZE_T take = (outlen < m_rate) ? outlen : m_rate;
        memcpy(out, buf, take);
        out += take;
        outlen -= take;
        if (outlen == 0)
        {
            break;
        }
        Keccakf1600();
    }
}

/* one-shot helper */
VOID CShakeBase::Shake(UINT8 * out, SIZE_T outlen, const UINT8 * in, SIZE_T inlen)
{
    Clear();
    Absorb(in, inlen);
    Finish();
    Squeeze(out, outlen);
}

