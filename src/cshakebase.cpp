/* ========================================================================== */
/**
 * @file    cshakebase.cpp
 * @brief   cSHAKE128/256 hash base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "cshakebase.h"
#include "secure.h"


VOID CcShakeBase::Initialize(const UINT8 * func, SIZE_T funclen, const UINT8 * custom, SIZE_T customlen)
{
    Clear();
    m_cshake = (funclen > 0 || customlen > 0);
    if ( m_cshake )
    {
        DoPrefix(func, funclen, custom, customlen);
    }
}


VOID CcShakeBase::Finish(UINT8 * out, SIZE_T outlen)
{
    m_Q[m_Qlen++] = m_cshake ? CSHAKE_DSBYTE : SHAKE_DSBYTE;
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

    Squeeze(out, outlen);
}


VOID CcShakeBase::DoPrefix(const UINT8 * func, SIZE_T funclen, const UINT8 * custom, SIZE_T customlen)
{
    SIZE_T total;

    total = EncodeInteger(m_rate); // bytes

    total += EncodeString(func, funclen);
    total += EncodeString(custom, customlen);

    Padding(total);
}


VOID CcShakeBase::Padding(SIZE_T len)
{
    static const UINT8 zero[8] = { 0 };
    SIZE_T padding = (m_rate - 1) - ((len + m_rate - 1) % m_rate);
    while ( padding >= sizeof(zero) )
    {
        Absorb(zero, sizeof(zero));
        padding -= sizeof(zero);
    }
    Absorb(zero, padding);
}


SIZE_T CcShakeBase::EncodeString(const UINT8 * str, SIZE_T len)
{
    SIZE_T size;

    size = EncodeInteger(len * 8); // bits
    Absorb(str, len);

    return size + len;
}


SIZE_T CcShakeBase::EncodeInteger(SIZE_T len)
{
    UINT8 enc[sizeof(len) + 1];
    UINT32 i = sizeof(enc) - 1;

    do
    {
        enc[i] = (UINT8)len;
        len >>= 8;
        i--;
    }
    while ( len > 0 && i > 0 );
    SIZE_T nbytes = sizeof(enc) - i;
    enc[i] = (UINT8)(nbytes - 1);
    Absorb(enc + i, nbytes);

    secure_zero(enc, sizeof(enc));

    return nbytes;
}

