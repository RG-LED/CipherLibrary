/* ========================================================================== */
/**
 * @file    asconhasha.cpp
 * @brief   Ascon-HASHA hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconhasha.h"


VOID CAsconHasha::Initialize()
{
    CAsconHashBase::Initialize(0x00400c0400000100ull);
    m_round = 8;
}


VOID CAsconHasha::Finish(UINT8 hash[32])
{
    CAsconHashBase::Finish();

    Uint64ToBytes(hash, m_state[0], 8);
    Permutation(8);
    Uint64ToBytes(hash + 8, m_state[0], 8);
    Permutation(8);
    Uint64ToBytes(hash + 16, m_state[0], 8);
    Permutation(8);
    Uint64ToBytes(hash + 24, m_state[0], 8);
}

