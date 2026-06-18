/* ========================================================================== */
/**
 * @file    aesgcmsiv.cpp
 * @brief   AES-GCM cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aesgcmsiv.h"
#include "ghash.h"
#include "secure.h"


CAesGcmSiv::CAesGcmSiv()
{
    m_H.Zero();
    m_aadLen = 0;
}


CAesGcmSiv::~CAesGcmSiv()
{
    m_H.Zero();
    m_aadLen = 0;
    secure_zero(m_iv, sizeof(m_iv));
}


BOOL CAesGcmSiv::Initialize(const UINT8 * key, SIZE_T keyLen, const UINT8 nonce[12], const UINT8 * aad, SIZE_T aadLen)
{
    BOOL ret = CAesCtr<AesCtrSpec::LITTLE32>::SetKeys(key, keyLen);
    if ( ret )
    {
        if ( keyLen == 24 )
        {
            return FALSE;
        }

        MakeKeyPart(m_macKey, nonce, 0);
        MakeKeyPart(m_macKey + 8, nonce, 1);
        MakeKeyPart(m_encKey, nonce, 2);
        MakeKeyPart(m_encKey + 8, nonce, 3);
        if ( keyLen == 32 )
        {
            MakeKeyPart(m_encKey + 16, nonce, 4);
            MakeKeyPart(m_encKey + 24, nonce, 5);
        }

        CAesCtr<AesCtrSpec::LITTLE32>::SetKeys(m_macKey, 16);
        m_H.LoadLE(m_macKey);
        m_polyval.Init(m_H);

        m_aadLen = 0;
        if ( aad != NULL && aadLen > 0 )
        {
            m_aadLen = aadLen;
            while ( aadLen >= 16 )
            {
                m_polyval.UpdateBlock(aad);
                aad += 16;
                aadLen -= 16;
            }
            if ( aadLen > 0 )
            {
                UINT8 buf[16] = { 0 };
                memcpy(buf, aad, aadLen);
                m_polyval.UpdateBlock(buf);
            }
        }

        m_keyLen = keyLen;
        memcpy(m_iv, nonce, sizeof(m_iv));
    }

    return ret;
}


VOID CAesGcmSiv::MakeKeyPart(UINT8 out[8], const UINT8 nonce[12], INT32 count)
{
    UINT8 buf[16];

    buf[0] = (UINT8)count;
    buf[1] = (UINT8)(count >> 8);
    buf[2] = (UINT8)(count >> 16);
    buf[3] = (UINT8)(count >> 24);
    memcpy(buf + 4, nonce, 12);
    EncryptBlock(buf);
    memcpy(out, buf, 8);
}


VOID CAesGcmSiv::Encrypt(UINT8 * out, const UINT8 * in, SIZE_T len, UINT8 tag[16])
{
    FeedPolyval(in, len);
    m_polyval.Final(m_aadLen * 8, len * 8);

    UINT8 siv[16];

    m_polyval.Get(siv);
    for ( INT32 i = 0; i < sizeof(m_iv); i++ )
    {
        siv[i] ^= m_iv[i];
    }
    siv[15] &= 0x7f;
    CAesCtr<AesCtrSpec::LITTLE32>::SetKeys(m_encKey, m_keyLen);
    EncryptBlock(siv);
    memcpy(tag, siv, sizeof(siv));

    siv[15] |= 0x80;
    SetInitialVector(siv);

    Crypt(out, in, len);
}


BOOL CAesGcmSiv::Decrypt(UINT8 * out, const UINT8 * in, SIZE_T len, const UINT8 tag[16])
{
    UINT8 siv[16];

    CAesCtr<AesCtrSpec::LITTLE32>::SetKeys(m_encKey, m_keyLen);
    memcpy(siv, tag, sizeof(siv));
    siv[15] |= 0x80;
    SetInitialVector(siv);

    Crypt(out, in, len);

    FeedPolyval(out, len);
    m_polyval.Final(m_aadLen * 8, len * 8);

    m_polyval.Get(siv);
    for ( INT32 i = 0; i < sizeof(m_iv); i++ )
    {
        siv[i] ^= m_iv[i];
    }
    siv[15] &= 0x7f;
    EncryptBlock(siv);

    if ( !secure_equal(tag, siv, sizeof(siv)) )
    {
        secure_zero(out, len);
        return FALSE;
    }
    return TRUE;
}


VOID CAesGcmSiv::FeedPolyval(const UINT8 data[], SIZE_T len)
{
    while ( len >= 16 )
    {
        m_polyval.UpdateBlock(data);
        data += 16;
        len -= 16;
    }
    if ( len > 0 )
    {
        UINT8 block[16] = { 0 };
        memcpy(block, data, len);
        m_polyval.UpdateBlock(block);
    }
}

