/* ========================================================================== */
/**
 * @file    Sha384.cpp
 * @brief   SHA-384 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "sha384.h"

/* ========================================================================== */
/**
 * SHA-384 hash class
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
VOID CSha384::Initialize(VOID)
{
    static const UINT64 Initial_H[8] =
    {
        0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
        0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
        0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
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
VOID CSha384::Finish(UINT8 hash[48])
{
    CSha512Base::Finish();

    for ( INT32 i = 0; i < 6; i++ )
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

