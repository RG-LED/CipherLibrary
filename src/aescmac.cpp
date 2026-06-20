/* ========================================================================== */
/**
 * @file    aescmac.cpp
 * @brief   AES-CMAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aescmac.h"
#include "secure.h"

BOOL CAesCmac::SetKeys(const UINT8 key[], SIZE_T keylen)
{
    if ( !CAesBase::SetKeys(key, keylen) )
    {
        return FALSE;
    }

    Reset();

    return TRUE;
}


VOID CAesCmac::Update(const UINT8 in[], SIZE_T len)
{
    while ( len > 0 )
    {
        if ( m_buflen >= sizeof(m_buffer) )
        {
            ProcessBuffer();
            m_buflen = 0;
        }
        SIZE_T take = sizeof(m_buffer) - m_buflen;
        if ( take > len )
        {
            take = len;
        }
        memcpy(&m_buffer[m_buflen], in, take);
        in += take;
        m_buflen += take;
        len -= take;
    }
}


VOID CAesCmac::Finish(UINT8 mac[16])
{
    Finalize();
    memcpy(mac, m_mac, sizeof(m_mac));
}


BOOL CAesCmac::Verify(const UINT8 mac[16])
{
    Finalize();
    return secure_equal(mac, m_mac, sizeof(m_mac));
}


VOID CAesCmac::Reset()
{
    UINT8 buf[16] = { 0 };

    EncryptBlock(buf);
    MakeSubkey(m_k1, buf);
    MakeSubkey(m_k2, m_k1);

    m_buflen = 0;
    secure_zero(m_mac, sizeof(m_mac));
}


VOID CAesCmac::Clear()
{
    m_buflen = 0;
    secure_zero(m_k1, sizeof(m_k1));
    secure_zero(m_k2, sizeof(m_k2));
    secure_zero(m_mac, sizeof(m_mac));
    secure_zero(m_buffer, sizeof(m_buffer));
}


VOID CAesCmac::ProcessBuffer()
{
    Xor(m_mac, m_buffer);
    EncryptBlock(m_mac);
}


VOID CAesCmac::Finalize()
{
    if ( m_buflen >= 16 )
    {
        Xor(m_buffer, m_k1);
    }
    else // m_buflen >= 0 && m_buflen < 16
    {
        m_buffer[m_buflen++] = 0x80;
        secure_zero(m_buffer + m_buflen, sizeof(m_buffer) - m_buflen);
        Xor(m_buffer, m_k2);
    }
    ProcessBuffer();
    m_buflen = 0;
}


VOID CAesCmac::MakeSubkey(UINT8 key[16], const UINT8 in[16])
{
    BOOL msb = ((in[0] & 0x80) != 0);

    // shift one bit left
    UINT32 carry = 0;
    for ( INT32 i = 15; i >= 0; i-- )
    {
        key[i] = (UINT8)((in[i] << 1) | carry);
        carry = (in[i] >> 7) & 0x01;
    }

    if ( msb )
    {
        // xor Rb
        key[15] ^= 0x87;
    }
}

