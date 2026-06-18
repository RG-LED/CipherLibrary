/* ========================================================================== */
/**
 * @file    blake2s_drbg.h
 * @brief   BLAKE2s random generation class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_BLAKE2S_DRBG_H_)
#define _BLAKE2S_DRBG_H_

#include "BasicDefs.h"

class CBlake2sDrbg
{
public:
    CBlake2sDrbg();
    ~CBlake2sDrbg();
    VOID Initialize(const UINT8 seed32[32], const VOID * personalization, SIZE_T perso_len);
    VOID Fill(VOID * out, SIZE_T outlen);
    VOID Reseed(const VOID * extra, SIZE_T extra_len);

private:
    VOID Clear();
    static VOID HashKeyed32(UINT8 out[32], const UINT8 key[32], const VOID * data, SIZE_T len);

    UINT8  m_Key[32];  /* secret key (derived from seed) */
    UINT64 m_Ctr;      /* 64-bit counter */
    UINT8  m_Perso[16];/* optional(usage ID / device ID; max 16 bytes) */
    UINT8  m_PersoLen;
};

#endif // !defined(_BLAKE2S_DRBG_H_)

