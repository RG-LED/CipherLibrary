/* ========================================================================== */
/**
 * @file    aesxts.cpp
 * @brief   AES-XTS cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aesxts.h"
#include "secure.h"

/************************************************************/
CAesXts::~CAesXts()
{
    secure_zero(m_tweak, sizeof(m_tweak));
}

BOOL CAesXts::SetKeys(const UINT8 keys[], SIZE_T len)
{
    switch ( len )
    {
        case 32: case 64:
        case 48: // optional
            break;
        default:
            return FALSE;
    }

    SIZE_T keylen = len / 2;

    BOOL ret1 = CAesBase::SetKeys(keys, keylen);            // first key for main encryption
    BOOL ret2 = m_aestweak.SetKeys(keys + keylen, keylen);  // second key for tweak

    return ret1 && ret2;
}


BOOL CAesXts::Encrypt(UINT8 out[], const UINT8 in[], SIZE_T len, UINT64 unitnum)
{
    UINT8 buf[NBb];

    for ( INT32 i = 0; i < sizeof(buf); i++ )
    {
        buf[i] = (UINT8)unitnum;
        unitnum >>= 8;
    }
    return Encrypt(out, in, len, buf);
}


BOOL CAesXts::Decrypt(UINT8 out[], const UINT8 in[], SIZE_T len, UINT64 unitnum)
{
    UINT8 buf[NBb];

    for ( INT32 i = 0; i < sizeof(buf); i++ )
    {
        buf[i] = (UINT8)unitnum;
        unitnum >>= 8;
    }
    return Decrypt(out, in, len, buf);
}


BOOL CAesXts::Encrypt(UINT8 out[], const UINT8 in[], SIZE_T len, const UINT8 unitnum[16])
{
    if ( len < NBb )
    {
        return FALSE;
    }

    MakeTweak(unitnum);

    while ( len >= NBb )
    {
        EncryptOneBlock(out, in);
        NextTweak();
        in += NBb;
        out += NBb;
        len -= NBb;
    }
    if ( len > 0 )
    {
        out -= NBb; // rewind 'out' to previous block
        for ( SIZE_T i = 0; i < len; i++ )
        {   // keep this order to prevent losing data
            out[i + NBb] = out[i];
            out[i] = in[i] ^ m_tweak[i];
        }
        for ( SIZE_T i = len; i < NBb; i++ )
        {
            out[i] ^= m_tweak[i];
        }
        EncryptBlock(out);
        Xor(out, m_tweak);
    }
    return TRUE;
}


BOOL CAesXts::Decrypt(UINT8 out[], const UINT8 in[], SIZE_T len, const UINT8 unitnum[16])
{
    if ( len < NBb )
    {
        return FALSE;
    }

    MakeTweak(unitnum);

    while ( len >= NBb * 2 )
    {
        DecryptOneBlock(out, in);
        NextTweak();
        in += NBb;
        out += NBb;
        len -= NBb;
    }
    if ( len == NBb )
    {
        DecryptOneBlock(out, in);
    }
    else // NBb < len < NBb * 2
    {
        UINT8 last_tweak[NBb];
        memcpy(last_tweak, m_tweak, sizeof(last_tweak));
        NextTweak();
        DecryptOneBlock(out, in);
        in += NBb;  // proceed 'in' but keep 'out' here
        len -= NBb;

        for ( SIZE_T i = 0; i < len; i++ )
        {   // keep this order to prevent losing data
            out[i + NBb] = out[i];
            out[i] = in[i] ^ last_tweak[i];
        }
        for ( SIZE_T i = len; i < NBb; i++ )
        {
            out[i] ^= last_tweak[i];
        }
        DecryptBlock(out);
        Xor(out, last_tweak);
        secure_zero(last_tweak, sizeof(last_tweak));
    }
    return TRUE;
}


VOID CAesXts::EncryptOneBlock(UINT8 out[], const UINT8 in[])
{
    memcpy(out, in, NBb);
    Xor(out, m_tweak);
    EncryptBlock(out);
    Xor(out, m_tweak);
}


VOID CAesXts::DecryptOneBlock(UINT8 out[], const UINT8 in[])
{
    memcpy(out, in, NBb);
    Xor(out, m_tweak);
    DecryptBlock(out);
    Xor(out, m_tweak);
}


VOID CAesXts::MakeTweak(const UINT8 unitnum[16])
{
    memcpy(m_tweak, unitnum, sizeof(m_tweak));
    m_aestweak.EncryptBlock(m_tweak);
}


VOID CAesXts::Xor(UINT8 a[NBb], const UINT8 b[NBb])
{
    for ( INT32 i = 0; i < NBb; i++ )
    {
        a[i] ^= b[i];
    }
}


VOID CAesXts::NextTweak()
{
    // shift one bit left
    UINT32 carry = 0;
    for ( INT32 i = 0; i < NBb; i++ )
    {
        carry = (((UINT32)m_tweak[i] << 1) | carry);
        m_tweak[i] = (UINT8)carry;
        carry >>= 8;
    }

    m_tweak[0] ^= (carry != 0) ? 0x87 : 0x00; // xor Rb
}

