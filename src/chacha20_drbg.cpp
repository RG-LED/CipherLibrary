/* ========================================================================== */
/**
 * @file    chacha20_drbg.cpp
 * @brief   ChaCha20 random generator class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "chacha20_drbg.h"
#include "secure.h"

#define LIMIT   0x000000016c85734dlu

CChacha20Drbg::CChacha20Drbg()
{
    Clear();
}

CChacha20Drbg::~CChacha20Drbg()
{
    Clear();
}

VOID CChacha20Drbg::Clear()
{
    m_Counter = 0;
}

VOID CChacha20Drbg::Initialize(const UINT8 seed[32])
{
    UINT8 nonce[12];
    memcpy(nonce, "Initialize00", 12);
    m_Counter = LIMIT;
    m_Chacha20.Initialize(seed, nonce, 1);
    secure_zero(nonce, sizeof(nonce));
}

VOID CChacha20Drbg::Fill(VOID * out, SIZE_T outlen)
{
    UINT8 * p = (UINT8 *)out;

    while ( outlen > 0 )
    {
        if ( m_Counter == 0 )
        {
            UINT8 seed[32];
            UINT8 nonce[12];
            m_Chacha20.Read(seed, sizeof(seed));
            m_Chacha20.Read(nonce, sizeof(nonce));
            m_Chacha20.Reseed(seed, nonce);
            secure_zero(seed, sizeof(seed));
            secure_zero(nonce, sizeof(nonce));
            m_Counter = LIMIT;
        }
        UINT64 len = (m_Counter < outlen) ? m_Counter : outlen;
        m_Chacha20.Read(p, (UINT32)len);
        m_Counter -= len;
        p += len;
        outlen -= (SIZE_T)len;
    }
}

