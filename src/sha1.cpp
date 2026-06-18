/* ========================================================================== */
/**
 * @file    sha1.cpp
 * @brief   SHA-1 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "sha1.h"
#include "secure.h"

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

CSha1::CSha1()
{
    Initialize();
}

CSha1::~CSha1()
{
    secure_zero(m_h, sizeof(m_h));
    secure_zero(m_buf, sizeof(m_buf));
}

VOID CSha1::Initialize()
{
    m_h[0] = 0x67452301;
    m_h[1] = 0xefcdab89;
    m_h[2] = 0x98badcfe;
    m_h[3] = 0x10325476;
    m_h[4] = 0xc3d2e1f0;
    m_len = 0;
    m_bufLen = 0;
}

VOID CSha1::Transform()
{
    UINT32 W[80];
    UINT32 a, b, c, d, e, f, k, temp;

    for ( INT32 i = 0; i < 16; i++ )
    {
        W[i] = (m_buf[i * 4 + 0] << 24) |
               (m_buf[i * 4 + 1] << 16) |
               (m_buf[i * 4 + 2] <<  8) |
               (m_buf[i * 4 + 3]);
    }
    for ( INT32 i = 16; i < 80; i++ )
    {
        W[i] = ROTL32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }

    a = m_h[0];
    b = m_h[1];
    c = m_h[2];
    d = m_h[3];
    e = m_h[4];

    for ( INT32 i = 0; i < 80; i++ )
    {
        if ( i < 20 )
        {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        }
        else if ( i < 40 )
        {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        }
        else if ( i < 60 )
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }

        temp = ROTL32(a, 5) + f + e + k + W[i];
        e = d;
        d = c;
        c = ROTL32(b, 30);
        b = a;
        a = temp;
    }

    m_h[0] += a;
    m_h[1] += b;
    m_h[2] += c;
    m_h[3] += d;
    m_h[4] += e;
    secure_zero(W, sizeof(W));
}

void CSha1::Update(const UINT8 * data, SIZE_T len)
{
    m_len += len * 8;
    while ( len-- )
    {
        m_buf[m_bufLen++] = *data++;
        if ( m_bufLen == 64 )
        {
            Transform();
            m_bufLen = 0;
        }
    }
}

void CSha1::Finish(UINT8 out[20])
{
    m_buf[m_bufLen++] = 0x80;
    while ( m_bufLen != 56 )
    {
        if ( m_bufLen == 64 )
        {
            Transform();
            m_bufLen = 0;
        }
        m_buf[m_bufLen++] = 0x00;
    }

    for ( INT32 i = 7; i >= 0; i-- )
    {
        m_buf[m_bufLen++] = (m_len >> (i * 8)) & 0xff;
    }
    Transform();

    for ( INT32 i = 0; i < 5; i++ )
    {
        out[i * 4 + 0] = (m_h[i] >> 24) & 0xff;
        out[i * 4 + 1] = (m_h[i] >> 16) & 0xff;
        out[i * 4 + 2] = (m_h[i] >>  8) & 0xff;
        out[i * 4 + 3] = (m_h[i]      ) & 0xff;
    }
}
