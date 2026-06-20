/* ========================================================================== */
/**
 * @file    aessiv.cpp
 * @brief   AES-SIV cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aessiv.h"
#include "aesctr.h"
#include "secure.h"

/************************************************************/
CAesSiv::CAesSiv()
{
    ClearWork();
}

CAesSiv::~CAesSiv()
{
    ClearWork();
}

VOID CAesSiv::ClearWork()
{
    secure_zero(m_v, sizeof(m_v));
    secure_zero(m_d, sizeof(m_d));
    secure_zero(m_ctrkey, sizeof(m_ctrkey));
}


BOOL CAesSiv::SetKeys(const UINT8 keys[], SIZE_T len)
{
    switch ( len )
    {
        case 32: case 48: case 64:
            break;
        default:
            return FALSE;
    }

    m_keylen = len / 2;
    BOOL ret = CAesCmac::SetKeys(keys, m_keylen);   // first key for CMAC
    memcpy(m_ctrkey, &keys[m_keylen], m_keylen);    // second key for CTR

    UINT8 zero[NBb] = { 0 };
    Update(zero, sizeof(zero));
    Finish(m_d);

    return ret;
}


VOID CAesSiv::AddAad(const UINT8 * aad, SIZE_T len)
{
    UINT8 s[NBb];

    Reset();
    Update(aad, len);
    Finish(s);

    Double(m_d);
    for ( INT32 i = 0; i < NBb; i++ )
    {
        m_d[i] ^= s[i];
    }
}


VOID CAesSiv::Seal(UINT8 * out, SIZE_T & outlen, const UINT8 * in, SIZE_T inlen)
{
    UINT8 v[NBb];
    UINT8 q[NBb];

    FinishS2V(v, in, inlen);
    memcpy(q, v, sizeof(q));
    q[8] &= 0x7f;
    q[12] &= 0x7f;

    memcpy(out, v, sizeof(v));
    out += sizeof(v);
    outlen = inlen + sizeof(v);

    CAesCtr<AesCtrSpec::BIG128> aesctr;

    aesctr.SetKeys(m_ctrkey, m_keylen);
    aesctr.SetInitialVector(q);
    aesctr.Crypt(out, in, inlen);
}


BOOL CAesSiv::Open(UINT8 * out, SIZE_T & outlen, const UINT8 * in, SIZE_T inlen)
{
    UINT8 v[NBb];

    if ( inlen < sizeof(v) )
    {
        return FALSE;
    }

    memcpy(v, in, sizeof(v));
    in += sizeof(v);
    outlen = inlen - sizeof(v);

    UINT8 q[NBb];
    memcpy(q, v, sizeof(q));
    q[8] &= 0x7f;
    q[12] &= 0x7f;

    CAesCtr<AesCtrSpec::BIG128> aesctr;

    aesctr.SetKeys(m_ctrkey, m_keylen);
    aesctr.SetInitialVector(q);
    aesctr.Crypt(out, in, outlen);

    UINT8 t[NBb];

    FinishS2V(t, out, outlen);

    if ( !secure_equal(t, v, sizeof(t)) )
    {
        secure_zero(out, outlen);
        return FALSE;
    }

    return TRUE;
}


VOID CAesSiv::FinishS2V(UINT8 out[NBb], const UINT8 * in, SIZE_T len)
{
    UINT8 t[NBb];

    Reset();
    if ( len >= sizeof(m_d) )
    {
        SIZE_T start = len - sizeof(m_d);
        Update(in, start);
        for ( SIZE_T i = 0; i < sizeof(t); i++ )
        {
            t[i] = in[start + i] ^ m_d[i];
        }
    }
    else
    {
        memcpy(t, m_d, sizeof(t));
        Double(t);
        for ( SIZE_T i = 0; i < len; i++ )
        {
            t[i] ^= in[i];
        }
        t[len++] ^= 0x80;
    }
    Update(t, sizeof(t));
    Finish(out);
}


VOID CAesSiv::Double(UINT8 data[NBb])
{
    UINT8 carry = 0;
    for ( INT32 i = NBb - 1; i >= 0; i-- )
    {
        UINT8 msb = data[i] >> 7; // 0 or 1
        data[i] = (data[i] << 1) | carry;
        carry = msb;
    }
    data[NBb - 1] ^= (carry != 0) ? 0x87 : 0x00;
}


VOID CAesSiv::Increment(UINT8 data[NBb])
{
    INT32 carry = 1;
    for ( INT32 i = NBb - 1; i >= 0; i-- )
    {
        carry += data[i];
        data[i] = (UINT8)carry;
        carry >>= 8;
    }
}

