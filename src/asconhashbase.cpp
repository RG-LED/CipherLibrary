/* ========================================================================== */
/**
 * @file    asconhashbase.cpp
 * @brief   Ascon hash base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconhashbase.h"


VOID CAsconHashBase::Initialize(UINT64 iv)
{
    m_state[0] = iv;
    m_state[1] = 0;
    m_state[2] = 0;
    m_state[3] = 0;
    m_state[4] = 0;

    m_buflen = 0;

    Permutation(12);
}


VOID CAsconHashBase::Finish()
{
    // padding
    m_buf[m_buflen++] = 0x80;
    m_state[0] ^= BytesToUint64(m_buf, m_buflen);
    Permutation(12);
}


VOID CAsconHashBase::Update(const UINT8 * data, SIZE_T len)
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


VOID CAsconHashBase::Absorb(const UINT8 data[8])
{
    m_state[0] ^= BytesToUint64(data);
    Permutation(m_round);
}

