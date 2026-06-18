/* ========================================================================== */
/**
 * @file    asconhash.cpp
 * @brief   Ascon hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconhash.h"


VOID CAsconHash::Initialize()
{
    CAsconHashBase::Initialize(0x00400c0000000100ull);
    m_round = 12;
}


VOID CAsconHash::Finish(UINT8 hash[32])
{
    CAsconHashBase::Finish();

    Uint64ToBytes(hash, m_state[0], 8);
    Permutation(12);
    Uint64ToBytes(hash + 8, m_state[0], 8);
    Permutation(12);
    Uint64ToBytes(hash + 16, m_state[0], 8);
    Permutation(12);
    Uint64ToBytes(hash + 24, m_state[0], 8);
}

