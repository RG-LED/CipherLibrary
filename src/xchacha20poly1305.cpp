/* ========================================================================== */
/**
 * @file    xchacha20poly1305.cpp
 * @brief   XChaCha20-Poly1305 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "xchacha20poly1305.h"
#include "secure.h"

CXChacha20Poly1305::CXChacha20Poly1305()
{
    m_aadLen = 0;
    m_dataLen = 0;
}


CXChacha20Poly1305::~CXChacha20Poly1305()
{
}


VOID CXChacha20Poly1305::Initialize(const UINT8 key[32], const UINT8 nonce[12])
{
    UINT8 poly_key[32];

    m_xchacha.Initialize(key, nonce, 0);
    m_xchacha.Read(poly_key, 32);

    m_poly.Initialize(poly_key);

    m_xchacha.Initialize(key, nonce, 1);
    m_aadLen = 0;
    m_dataLen = 0;
    m_state = ST_INIT;

    secure_zero(poly_key, sizeof(poly_key));
}


VOID CXChacha20Poly1305::UpdateAad(const UINT8 * aad, SIZE_T len)
{
    m_poly.Update(aad, len);
    m_aadLen += len;

    m_state = ST_AAD;
}


VOID CXChacha20Poly1305::Encrypt(UINT8 * out, const UINT8 * in, SIZE_T len)
{
    if ( m_state == ST_AAD )
    {
        Padding16(m_aadLen);
    }

    m_xchacha.ReadXor(out, in, len);

    m_poly.Update(out, len);
    m_dataLen += len;

    m_state = ST_DATA;
}


VOID CXChacha20Poly1305::Finish(UINT8 tag[16])
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


BOOL CXChacha20Poly1305::VerifyAndDecrypt(UINT8 * out, const UINT8 * in, SIZE_T len, const UINT8 tag[16])
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

    m_xchacha.ReadXor(out, in, len);

    return TRUE;
}


VOID CXChacha20Poly1305::Padding16(UINT64 len)
{
    static const UINT8 zero[16] = { 0 };
    m_poly.Update(zero, 16 - (len & 15));
}

