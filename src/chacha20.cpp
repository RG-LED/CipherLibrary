/* ========================================================================== */
/**
 * @file    chacha20.cpp
 * @brief   ChaCha20 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "chacha20.h"

CChacha20::CChacha20()
{
    m_Avail = 0;
#if SUPPORT_RESEED
    m_BlocksOut = 0;
#endif
}

VOID CChacha20::Refill()
{
    /* initial state (RFC 8439):
       constants: "expand 32-byte k" */
    UINT32 s[16];
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for ( INT32 i = 0; i < 8; i++ )
    {
        s[i + 4] = m_Key[i];
    }
    s[12] = m_Counter;
    s[13] = m_Nonce[0];
    s[14] = m_Nonce[1];
    s[15] = m_Nonce[2];
    UINT32 w[16];
    for ( INT32 i = 0; i < 16; i++ )
    {
        w[i] = s[i];
    }

    RunChaChaRounds(w);

    for ( INT32 i = 0; i < 16; i++ )
    {
        UINT32 r = w[i] + s[i];
        Store32(&m_Buf[4 * i], r);
    }

    m_Counter++;
    m_Avail = 64;
#if SUPPORT_RESEED
    m_BlocksOut++;
#endif
}

VOID CChacha20::RunChaChaRounds(UINT32 w[16])
{
/* 20 rounds = 10 double rounds */
#define QR(a, b, c, d) \
        a += b; d ^= a; d = Rotl32(d, 16); \
        c += d; b ^= c; b = Rotl32(b, 12); \
        a += b; d ^= a; d = Rotl32(d,  8); \
        c += d; b ^= c; b = Rotl32(b,  7);

    for ( INT32 i = 0; i < 10; i++ )
    {
        /* column rounds */
        QR(w[0], w[4], w[8],  w[12])
        QR(w[1], w[5], w[9],  w[13])
        QR(w[2], w[6], w[10], w[14])
        QR(w[3], w[7], w[11], w[15])
        /* diagonal rounds */
        QR(w[0], w[5], w[10], w[15])
        QR(w[1], w[6], w[11], w[12])
        QR(w[2], w[7], w[8],  w[13])
        QR(w[3], w[4], w[9],  w[14])
    }
#undef QR
}

/* --- public API --- */

#if SUPPORT_RESEED
VOID CChacha20::Initialize(const UINT8 seed32[32], const UINT8 nonce12[12], UINT32 counter, UINT64 reseed_interval_blocks)
#else
VOID CChacha20::Initialize(const UINT8 seed32[32], const UINT8 nonce12[12], UINT32 counter)
#endif
{
    for ( INT32 i = 0; i < 8; i++ )
    {
        m_Key[i] = Load32(seed32 + 4 * i);
    }
    m_Nonce[0] = Load32(nonce12 + 0);
    m_Nonce[1] = Load32(nonce12 + 4);
    m_Nonce[2] = Load32(nonce12 + 8);
    m_Counter  = counter;           /* start from 0; change if you prefer nonzero */
    m_Avail    = 0;
#if SUPPORT_RESEED
    m_BlocksOut = 0;
    m_ReseedIntervalBlocks = reseed_interval_blocks;
#endif
}

#if SUPPORT_RESEED
BOOL CChacha20::NeedReseed() const
{
    return (m_BlocksOut >= m_ReseedIntervalBlocks);
}

VOID CChacha20::Reseed(const UINT8 seed32[32], const UINT8 nonce12[12])
{
    for ( INT32 i = 0; i < 8; i++ )
    {
        m_Key[i] = Load32(&seed32[4 * i]);
    }
    m_Nonce[0] = Load32(&nonce12[0]);
    m_Nonce[1] = Load32(&nonce12[4]);
    m_Nonce[2] = Load32(&nonce12[8]);
    /* counter can be rewind to 0, but same nonce should not be reused with same key */
    m_Counter  = 0;
    m_Avail    = 0;
    m_BlocksOut = 0;
}
#endif

VOID CChacha20::Read(UINT8 * out, SIZE_T len)
{
    while ( len > 0 )
    {
        if ( m_Avail == 0 )
        {
            Refill();
        }
        SIZE_T take = m_Avail;
        if ( take > len )
        {
            take = len;
        }
        SIZE_T offset = 64 - m_Avail;
        memcpy(out, m_Buf + offset, take);
        m_Avail -= take;
        len -= take;
        out += take;
    }
}

UINT8 CChacha20::Read8()
{
    UINT8 out;
    Read(&out, sizeof(out));
    return out;
}

UINT16 CChacha20::Read16()
{
    UINT16 out;
    Read((UINT8 *)&out, sizeof(out));
    return out;
}

UINT32 CChacha20::Read32()
{
    UINT32 out;
    Read((UINT8 *)&out, sizeof(out));
    return out;
}

VOID CChacha20::ReadXor(UINT8 * out, const UINT8 * in, SIZE_T len)
{
    while ( len > 0 )
    {
        if ( m_Avail == 0 )
        {
            Refill();
        }
        SIZE_T take = m_Avail;
        if ( take > len )
        {
            take = len;
        }
        SIZE_T offset = 64 - m_Avail;
        for (SIZE_T i = 0; i < take; i++ )
        {
            out[i] = in[i] ^ m_Buf[offset + i];
        }
        m_Avail -= take;
        len -= take;
        in += take;
        out += take;
    }
}

#if 0
/* ======== for DOM-1: 18 bit mask extract utility ======== */
UINT32 CChacha20::Take18()
{
    UINT8 tmp[3];
    Read(tmp, 3);
    UINT32 v = ((UINT32)tmp[0]) | ((UINT32)tmp[1] << 8) | ((UINT32)tmp[2] << 16);
    return (v >> 6) & 0x3FFFFu;  /* upper 18 bit */
}
#endif

