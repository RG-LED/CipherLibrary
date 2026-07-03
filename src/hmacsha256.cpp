/* ========================================================================== */
/**
 * @file    hmacsha256.cpp
 * @brief   HMAC-SHA256 MAC class for PBKDF2
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "hmacsha256.h"
#include "secure.h"


VOID CHmacSha256::Initialize(const UINT8 key[], SIZE_T len)
{
    UINT8 k_pad[64] = { 0 }; // work area of 64 bytes

    // 1. key
    if ( len > 64 )
    {
        m_iSha.Initialize();
        m_iSha.Update(key, len);
        m_iSha.Finish(k_pad); // store it to first 32 bytes, the rests are 0x00
    }
    else
    {
        memcpy(k_pad, key, len);
    }

    // 2. ipad
    m_iSha.Initialize();
    for ( INT32 i = 0; i < 64; i++ )
    {
        k_pad[i] ^= 0x36; // make it ipad temporarily
    }
    m_iSha.Update(k_pad, 64);

    // 3. opad
    m_oSha.Initialize();
    for ( INT32 i = 0; i < 64; i++ )
    {
        k_pad[i] ^= (0x36 ^ 0x5c); // switch it from ipad to opad
    }
    m_oSha.Update(k_pad, 64);

    secure_zero(k_pad, sizeof(k_pad));
}


VOID CHmacSha256::Update(const UINT8 * msg, SIZE_T len)
{
    m_iSha.Update(msg, len);
}


VOID CHmacSha256::Finish(UINT8 * hash)
{
    UINT8 digest[32];

    m_iSha.Finish(digest);

    m_oSha.Update(digest, sizeof(digest));
    m_oSha.Finish(hash);

    secure_zero(digest, sizeof(digest));
}

