/* ========================================================================== */
/**
 * @file    Sha512.cpp
 * @brief   SHA-512 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "sha512.h"
#include "secure.h"

/* ========================================================================== */
/**
 * SHA-512 hash class
 */
/* ========================================================================== */

/* ========================================================================== */
/**
 * initialize instance
 *
 * prepare calculation
 * @param           none
 * @return          none
 */
/* ========================================================================== */
VOID CSha512::Initialize(VOID)
{
    static const UINT64 Initial_H[8] =
    {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    CSha512Base::Initialize(Initial_H);
}


/* ========================================================================== */
/**
 * finish calculation
 *
 * calculate last part to get hash value
 * @param[out]      hash        pointer to store result
 * @return          none
 */
/* ========================================================================== */
VOID CSha512::Finish(UINT8 hash[64])
{
    CSha512Base::Finish();

    for ( INT32 i = 0; i < 8; i++ )
    {
        hash[i * 8    ] = (UINT8)(m_H[i] >> 56);
        hash[i * 8 + 1] = (UINT8)(m_H[i] >> 48);
        hash[i * 8 + 2] = (UINT8)(m_H[i] >> 40);
        hash[i * 8 + 3] = (UINT8)(m_H[i] >> 32);
        hash[i * 8 + 4] = (UINT8)(m_H[i] >> 24);
        hash[i * 8 + 5] = (UINT8)(m_H[i] >> 16);
        hash[i * 8 + 6] = (UINT8)(m_H[i] >>  8);
        hash[i * 8 + 7] = (UINT8) m_H[i];
    }
}

