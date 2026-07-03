/* ========================================================================== */
/**
 * @file    blake2s_drbg.cpp
 * @brief   BLAKE2s random generator class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "blake2s_drbg.h"
#include "blake2s.h"
#include "secure.h"

CBlake2sDrbg::CBlake2sDrbg()
{
    Clear();
}

CBlake2sDrbg::~CBlake2sDrbg()
{
    Clear();
}

VOID CBlake2sDrbg::Clear()
{
    secure_zero(m_Key, sizeof(m_Key));
    m_Ctr = 0;
    secure_zero(m_Perso, sizeof(m_Perso));
    m_PersoLen = 0;
}

VOID CBlake2sDrbg::HashKeyed32(UINT8 out[32], const UINT8 key[32], const VOID * data, SIZE_T len)
{
    CBlake2s c;

    c.Initialize(key, 32);
    /* domain separation: "DRBG" as prefix */
    const CHAR8 tag[] = "DRBG";
    c.Update(tag, sizeof(tag)-1);
    c.Update(data, len);
    c.Finish(out);
}

VOID CBlake2sDrbg::Initialize(const UINT8 seed32[32], const VOID * personalization, SIZE_T perso_len)
{
    if ( perso_len > sizeof(m_Perso) )
    {
        perso_len = sizeof(m_Perso);
    }
    if ( perso_len && personalization )
    {
        memcpy(m_Perso, personalization, perso_len);
        m_PersoLen = (UINT8)perso_len;
    }
    /* key = BLAKE2s(seed || "INIT" || perso) */
    UINT8 tmp_in[32 + 4 + 16];
    SIZE_T off = 0;
    memcpy(tmp_in + off, seed32, 32);
    off += 32;
    memcpy(tmp_in + off, "INIT", 4);
    off += 4;
    memcpy(tmp_in + off, m_Perso, m_PersoLen);
    off += m_PersoLen;
    HashKeyed32(m_Key, seed32 /* self-key OK */, tmp_in, off);
    m_Ctr = 1; /* avoid 0 */
}

VOID CBlake2sDrbg::Fill(VOID * out, SIZE_T outlen)
{
    UINT8 * p = (UINT8 *)out;
    UINT8 in[3 + 8 + 16];
    UINT8 block[32];

    while ( outlen > 0 )
    {
        /* block = BLAKE2s(key, "OUT" || ctr || perso) */
        SIZE_T off = 0;
        memcpy(in + off, "OUT", 3);
        off += 3;
        memcpy(in + off, &m_Ctr, 8);
        off += 8;
        memcpy(in + off, m_Perso, m_PersoLen);
        off += m_PersoLen;

        HashKeyed32(block, m_Key, in, off);
        m_Ctr++;

        SIZE_T take = (outlen < 32) ? outlen : 32;
        memcpy(p, block, take);
        p += take;
        outlen -= take;

        /* optional: rotate key at some frequency */
        /* e.g.: rekey at every 256 blocks (8KB) */
        /* if ((m_Ctr & 0xFF) == 0) Reseed(NULL, 0); */
    }

    secure_zero(in, sizeof(in));
    secure_zero(block, sizeof(block));
}

VOID CBlake2sDrbg::Reseed(const VOID * extra, SIZE_T extra_len)
{
    /* newkey = BLAKE2s(key, "REKEY" || ctr || perso || extra) */
    UINT8 in[4 + 8 + 16];
    SIZE_T  off = 0;
    memcpy(in + off, "REKEY", 5);
    off += 5;
    memcpy(in + off, &m_Ctr, 8);
    off += 8;
    memcpy(in + off, m_Perso, m_PersoLen);
    off += m_PersoLen;

    UINT8 k1[32];
    HashKeyed32(k1, m_Key, in, off);

    if ( extra && extra_len )
    {
        UINT8 k2[32];
        HashKeyed32(k2, k1, extra, extra_len);
        memcpy(m_Key, k2, 32);
        secure_zero(k2, sizeof(k2));
    }
    else
    {
        memcpy(m_Key, k1, 32);
    }
    m_Ctr++;

    secure_zero(in, sizeof(in));
    secure_zero(k1, sizeof(k1));
}

