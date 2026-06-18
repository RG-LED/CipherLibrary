/* ========================================================================== */
/**
 * @file    chacha20poly1305.cpp
 * @brief   ChaCha20-Poly1305 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "chacha20poly1305.h"
#include "secure.h"

CChacha20Poly1305::CChacha20Poly1305()
{
    m_aadLen = 0;
    m_dataLen = 0;
}


CChacha20Poly1305::~CChacha20Poly1305()
{
}


VOID CChacha20Poly1305::Initialize(const UINT8 key[32], const UINT8 nonce[12])
{
    UINT8 poly_key[32];

    m_chacha.Initialize(key, nonce, 0);
    m_chacha.Read(poly_key, 32);

    m_poly.Initialize(poly_key);

    m_chacha.Initialize(key, nonce, 1);
    m_aadLen = 0;
    m_dataLen = 0;
    m_state = ST_INIT;

    secure_zero(poly_key, sizeof(poly_key));
}


VOID CChacha20Poly1305::UpdateAad(const UINT8 * aad, SIZE_T len)
{
    m_poly.Update(aad, len);
    m_aadLen += len;

    m_state = ST_AAD;
}


VOID CChacha20Poly1305::Encrypt(UINT8 * out, const UINT8 * in, SIZE_T len)
{
    if ( m_state == ST_AAD )
    {
        Padding16(m_aadLen);
    }

    m_chacha.ReadXor(out, in, len);

    m_poly.Update(out, len);
    m_dataLen += len;

    m_state = ST_DATA;
}


VOID CChacha20Poly1305::Finish(UINT8 tag[16])
{
    Padding16(m_dataLen);

    UINT8 length[16];

    for ( INT32 i = 0; i < 8; i++ )
    {
        length[i] = (UINT8)(m_aadLen >> (i * 8));
        length[i + 8] = (UINT8)(m_dataLen >> (i * 8));
    }
    m_poly.Update(length, sizeof(length));

    m_poly.Finish(tag);

    m_state = ST_FINAL;
}


BOOL CChacha20Poly1305::VerifyAndDecrypt(UINT8 * out, const UINT8 * in, SIZE_T len, const UINT8 tag[16])
{
    if ( m_state == ST_AAD )
    {
        Padding16(m_aadLen);
    }

    m_poly.Update(in, len);
    m_dataLen += len;

    m_state = ST_DATA;

    UINT8 tag2[16];

    Finish(tag2);

    UINT8 diff = 0;
    for ( INT32 i = 0; i < 16; i++ )
    {
        diff |= tag[i] ^ tag2[i];
    }
    if ( diff )
    {
        return FALSE;
    }

    m_chacha.ReadXor(out, in, len);

    return TRUE;
}


VOID CChacha20Poly1305::Padding16(UINT64 len)
{
    static const UINT8 zero[16] = { 0 };
    m_poly.Update(zero, 16 - (len & 15));
}

