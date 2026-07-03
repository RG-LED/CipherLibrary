/* ========================================================================== */
/**
 * @file    poly1305.cpp
 * @brief   Poly1305 MAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "poly1305.h"
#include "secure.h"


// clamping
// r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
VOID CPoly1305::CPolyKey::ClampR()
{
    m_Limbs[0] &= 0x0fffffffu;
    m_Limbs[1] &= 0x0ffffffcu;
    m_Limbs[2] &= 0x0ffffffcu;
    m_Limbs[3] &= 0x0ffffffcu;
    m_Limbs[4] &= 0x00000003u;
    for ( INT32 i = 5; i < BI256_LIMBS; i++ )
    {
        m_Limbs[i] = 0;
    }
}


VOID CPoly1305::CPolyKey::Reduce1305()
{
    CPolyKey hi;
    CPolyKey lo;

    // mod (2^130 - 5)
    for ( INT32 t = 0; t < 2; t++ )
    {
        // hi = *this >> 130
        for ( INT32 i = 0; i < BI256_LIMBS - 5; i++ )
        {
            hi.m_Limbs[i] = (m_Limbs[i + 4] >> 2) | (m_Limbs[i + 5] << (BI256_BASE_SHIFT - 2));
        }
        hi.m_Limbs[BI256_LIMBS - 5] = (m_Limbs[BI256_LIMBS - 1] >> 2);
        for ( INT32 i = BI256_LIMBS - 4; i < BI256_LIMBS; i++ )
        {
            hi.m_Limbs[i] = 0;
        }

        // lo = *this & (2^130 - 1)
        for ( INT32 i = 0; i < 4; i++ )
        {
            lo.m_Limbs[i] = m_Limbs[i];
        }
        lo.m_Limbs[4] = (m_Limbs[4] & 3);
        for ( INT32 i = 5; i < BI256_LIMBS; i++ )
        {
            lo.m_Limbs[i] = 0;
        }

        // *this = lo + hi * 5
        CALC_TYPE c = 0;
        for ( INT32 i = 0; i < BI256_LIMBS; i++ )
        {
            c = (CALC_TYPE)hi.m_Limbs[i] * 5 + (CALC_TYPE)lo.m_Limbs[i] + c;
            m_Limbs[i] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_LIMB(c);
        }
    }
    ConditionalSubP();
}


VOID CPoly1305::CPolyKey::Mul(CPolyKey & out, const CPolyKey & n, const CPolyKey & m)
{
    FOLD_BUF buf;
    CFeBigInt256::Mul(buf, n, m);
    Extract(out, buf);
    secure_zero(buf, sizeof(buf));
}


VOID CPoly1305::CPolyKey::ConditionalSubP()
{
    static BASE_TYPE P[BI256_LIMBS] = {
        0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff, 0x00000003, 0x00000000, 0x00000000, 0x00000000
    };
    CALC_TYPE b = 0;
    BASE_TYPE diff[BI256_LIMBS];
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        b = (CALC_TYPE)m_Limbs[i] - P[i] - b;
        diff[i] = (BASE_TYPE)b;
        BI256_SHIFT_RIGHT_CARRY(b);
    }
    BASE_TYPE mask = (BASE_TYPE)(b - 1);
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        m_Limbs[i] = (m_Limbs[i] & ~mask) | (diff[i] & mask);
    }
}


CPoly1305::CPoly1305()
{
    m_bufferLen = 0;
}


CPoly1305::~CPoly1305()
{
    Reset();
}


VOID CPoly1305::Initialize(const UINT8 key[32])
{
    // r = key[0..15](LE)
    m_r.fromBytesLE(key, 16);

    m_r.ClampR();

    // h = 0
    m_h = 0;

    // s = key[16..31]
    m_s.fromBytesLE(key + 16, 16);

    m_bufferLen = 0;
}


VOID CPoly1305::Update(const UINT8 * msg, SIZE_T len)
{
    while ( len > 0 )
    {
        SIZE_T take = sizeof(m_buffer) - m_bufferLen;
        if ( take > len )
        {
            take = len;
        }
        memcpy(&m_buffer[m_bufferLen], msg, take);
        m_bufferLen += take;
        msg += take;
        len -= take;

        if ( m_bufferLen == sizeof(m_buffer) )
        {
            ProcessBlock();
            m_bufferLen = 0;
        }
    }
}


VOID CPoly1305::Finish(UINT8 tag[16])
{
    // process the remaining
    if ( m_bufferLen > 0 )
    {
        ProcessBlock();
        m_bufferLen = 0;
    }

    // h += s
    CPolyKey::Add(m_h, m_h, m_s);

    // output lower 128 bits
    m_h.toBytesLE(tag, 16);
}


VOID CPoly1305::Reset()
{
    m_h = 0;
    m_bufferLen = 0;
    secure_zero(m_buffer, sizeof(m_buffer));
}


VOID CPoly1305::ProcessBlock()
{
    CPolyKey m;

    // m = block || 1 (even if len<16)
    UINT8 tmp[16 + 1];
    memcpy(tmp, m_buffer, m_bufferLen);
    tmp[m_bufferLen] = 1;

    m.fromBytesLE(tmp, m_bufferLen + 1);

    // h = h + m
    CPolyKey::Add(m_h, m_h, m);

    // h = h * r
    MultiplyAndReduce();
}


VOID CPoly1305::MultiplyAndReduce()
{
    CPolyKey::Mul(m_h, m_h, m_r);
    m_h.Reduce1305();
}

