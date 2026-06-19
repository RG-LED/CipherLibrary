/* ========================================================================== */
/**
 * @file    aesgcm.cpp
 * @brief   AES-GCM cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aesgcm.h"
#include "ghash.h"
#include "secure.h"


CAesGcm::CAesGcm()
{
    m_H.Zero();
    m_Y.Zero();
    m_aadLen = m_dataLen = 0;
}


CAesGcm::~CAesGcm()
{
    m_H.Zero();
    m_Y.Zero();
    m_aadLen = m_dataLen = 0;
    secure_zero(m_buffer, sizeof(m_buffer));
    secure_zero(m_S, sizeof(m_S));
    secure_zero(m_tag, sizeof(m_tag));
}


BOOL CAesGcm::SetKeys(const UINT8 keys[], SIZE_T len)
{
    BOOL ret = CAesCtr<AesCtrSpec::BIG32>::SetKeys(keys, len);
    if ( ret )
    {
        UINT8 h[16] = { 0 };
        EncryptBlock(h);
        m_H.LoadBE(h);
    }
    return ret;
}


VOID CAesGcm::Init(const UINT8 iv[], SIZE_T ivLen, const UINT8 * aad, SIZE_T aadLen)
{
    UINT8 vec[16];

    if ( ivLen == 12 )
    {
        memcpy(vec, iv, 12);
        vec[12] = 0;
        vec[13] = 0;
        vec[14] = 0;
        vec[15] = 1;
    }
    else
    {
        SIZE_T len = ivLen;
        UINT8 buf[16];

        m_gHash.Init(m_H);
        while ( len >= 16 )
        {
            m_gHash.UpdateBlock(iv);
            iv += 16;
            len -= 16;
        }
        if ( len > 0 )
        {
            memcpy(buf, iv, len);
            secure_zero(&buf[len], 16 - len);
            m_gHash.UpdateBlock(buf);
        }
        secure_zero(buf, sizeof(buf));
        buf[11] = (UINT8)(ivLen >> 29);
        buf[12] = (UINT8)(ivLen >> 21);
        buf[13] = (UINT8)(ivLen >> 13);
        buf[14] = (UINT8)(ivLen >> 5);
        buf[15] = (UINT8)(ivLen << 3);
        m_gHash.UpdateBlock(buf);
        m_gHash.Get(vec);
    }

    SetInitialVector(vec);

    memcpy(m_S, m_vector, sizeof(m_S));
    EncryptBlock(m_S);
    IncrementVector();

    m_Y.Zero();

    m_gHash.Init(m_H);
    m_aadLen = aadLen;
    m_dataLen = 0;

    while ( aadLen >= 16 )
    {
        m_gHash.UpdateBlock(aad);
        aad += 16;
        aadLen -= 16;
    }
    if ( aadLen > 0 )
    {
        UINT8 block[16] = { 0 };
        memcpy(block, aad, aadLen);
        m_gHash.UpdateBlock(block);
    }
    m_bufLen = 0;
}


VOID CAesGcm::Encrypt(UINT8 * out, const UINT8 * in, SIZE_T len)
{
    Crypt(out, in, len);
    m_dataLen += len;

    if ( m_bufLen > 0 )
    {
        SIZE_T n = (NBb - m_bufLen < len) ? (NBb - m_bufLen) : len;
        memcpy(&m_buffer[m_bufLen], out, n);
        len -= n;
        out += n;
        m_bufLen += n;
        if ( m_bufLen >= NBb )
        {
            m_gHash.UpdateBlock(m_buffer);
            m_bufLen = 0;
        }
    }

    while ( len >= NBb )
    {
        m_gHash.UpdateBlock(out);
        len -= NBb;
        out += NBb;
    }

    if ( len > 0 )
    {
        memcpy(&m_buffer[0], out, len);
        m_bufLen = len;
    }
}


VOID CAesGcm::Decrypt(UINT8 * out, const UINT8 * in, SIZE_T len)
{
    Crypt(out, in, len);
    m_dataLen += len;

    if ( m_bufLen > 0 )
    {
        SIZE_T n = (NBb - m_bufLen < len) ? (NBb - m_bufLen) : len;
        memcpy(&m_buffer[m_bufLen], in, n);
        len -= n;
        in += n;
        m_bufLen += n;
        if ( m_bufLen >= NBb )
        {
            m_gHash.UpdateBlock(m_buffer);
            m_bufLen = 0;
        }
    }

    while ( len >= NBb )
    {
        m_gHash.UpdateBlock(in);
        len -= NBb;
        in += NBb;
    }

    if ( len > 0 )
    {
        memcpy(&m_buffer[0], in, len);
        m_bufLen = len;
    }
}


VOID CAesGcm::Finalize()
{
    if ( m_bufLen > 0 )
    {
        secure_zero(&m_buffer[m_bufLen], NBb - m_bufLen);
        m_gHash.UpdateBlock(m_buffer);
    }

    m_gHash.Final((UINT64)m_aadLen << 3, (UINT64)m_dataLen << 3);
}


VOID CAesGcm::GetTag(UINT8 tag[16]) const
{
    UINT8 y[NBb];
    m_gHash.Get(y);
    for ( INT32 i = 0; i < NBb; i++ )
    {
        tag[i] = y[i] ^ m_S[i];
    }
}


VOID CAesGcm::SetTag(const UINT8 tag[16])
{
    for ( INT32 i = 0; i < NBb; i++ )
    {
        m_tag[i] = tag[i];
    }
}


BOOL CAesGcm::CheckTag() const
{
    UINT8 y[NBb];
    m_gHash.Get(y);
    UINT8 diff = 0;
    for ( INT32 i = 0; i < NBb; i++ )
    {
        diff |= (m_tag[i] ^ y[i] ^ m_S[i]);
    }
    return (diff == 0);
}

