/* ========================================================================== */
/**
 * @file    asconaead.cpp
 * @brief   Ascon-AEAD base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconaead.h"
#include "secure.h"

CAsconAead::~CAsconAead()
{
    m_k0 = 0;
    m_k1 = 0;
}

VOID CAsconAead::Initialize(const UINT8 key[16], const UINT8 nonce[16], UINT64 iv)
{
    // 1. convert key and nonce into 64-bit data
    m_k0 = BytesToUint64(key);
    m_k1 = BytesToUint64(key + 8);
    UINT64 n0 = BytesToUint64(nonce);
    UINT64 n1 = BytesToUint64(nonce + 8);

    // 2. place them in 320-bit state
    m_state[0] = iv;
    m_state[1] = m_k0;
    m_state[2] = m_k1;
    m_state[3] = n0;
    m_state[4] = n1;

    // 3. first big scramble (replace 12 rounds)
    Permutation(12);

    // 4. XOR tail of state with key again to prevent brute force attack
    m_state[3] ^= m_k0;
    m_state[4] ^= m_k1;
}

