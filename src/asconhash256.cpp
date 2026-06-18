/* ========================================================================== */
/**
 * @file    asconhash256.cpp
 * @brief   Ascon-HASH256 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconhash256.h"


VOID CAsconHash256::Initialize()
{
    m_state[0] = 0x0000080100cc0002ull;
    m_state[1] = 0;
    m_state[2] = 0;
    m_state[3] = 0;
    m_state[4] = 0;

    m_buflen = 0;

    Permutation(12);
}


VOID CAsconHash256::Update(const UINT8 * data, SIZE_T len)
{
    if ( m_buflen > 0 )
    {
        SIZE_T take = (len > 8 - m_buflen) ? 8 - m_buflen : len;
        memcpy(m_buf + m_buflen, data, take);
        m_buflen += take;
        data += take;
        len -= take;
        if ( m_buflen == 8 )
        {
            Absorb(m_buf);
            m_buflen = 0;
        }
    }
    while ( len >= 8 )
    {
        Absorb(data);
        data += 8;
        len -= 8;
    }
    if ( len > 0 )
    {
        memcpy(m_buf, data, len);
        m_buflen = len;
    }
}


VOID CAsconHash256::Absorb(const UINT8 data[8])
{
    m_state[0] ^= BytesToUint64(data);
    Permutation(12);
}


VOID CAsconHash256::Finish(UINT8 hash[32])
{
    // padding
    m_buf[m_buflen++] = 0x01;
    m_state[0] ^= BytesToUint64(m_buf, m_buflen);
    Permutation(12);

    Uint64ToBytes(hash, m_state[0], 8);
    Permutation(12);
    Uint64ToBytes(hash + 8, m_state[0], 8);
    Permutation(12);
    Uint64ToBytes(hash + 16, m_state[0], 8);
    Permutation(12);
    Uint64ToBytes(hash + 24, m_state[0], 8);
}

