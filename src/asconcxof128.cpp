/* ========================================================================== */
/**
 * @file    asconcxof128.cpp
 * @brief   Ascon-CXOF128 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconcxof128.h"


VOID CAsconCxof128::Initialize(const UINT8 * custom, SIZE_T csmlen)
{
    m_state[0] = 0x0000080000cc0004ull;
    m_state[1] = 0;
    m_state[2] = 0;
    m_state[3] = 0;
    m_state[4] = 0;

    Permutation(12);

    Uint64ToBytes(m_buf, (UINT64)csmlen * 8);
    Absorb(m_buf);
    while ( csmlen >= 8 )
    {
        Absorb(custom);
        custom += 8;
        csmlen -= 8;
    }
    memcpy(m_buf, custom, csmlen);
    m_buf[csmlen++] = 0x01;
    while ( csmlen < 8 )
    {
        m_buf[csmlen++] = 0x00;
    }
    Absorb(m_buf);

    m_buflen = 0;
}

