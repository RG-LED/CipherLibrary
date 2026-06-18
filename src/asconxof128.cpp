/* ========================================================================== */
/**
 * @file    asconxof128.cpp
 * @brief   Ascon-XOF128 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconxof128.h"


VOID CAsconXof128::Initialize()
{
    m_state[0] = 0x0000080000cc0003ull;
    m_state[1] = 0;
    m_state[2] = 0;
    m_state[3] = 0;
    m_state[4] = 0;

    m_buflen = 0;

    Permutation(12);
}


VOID CAsconXof128::Update(const UINT8 * data, SIZE_T len)
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


VOID CAsconXof128::Absorb(const UINT8 data[8])
{
    m_state[0] ^= BytesToUint64(data);
    Permutation(12);
}


VOID CAsconXof128::Finish()
{
    // padding
    m_buf[m_buflen++] = 0x01;
    m_state[0] ^= BytesToUint64(m_buf, m_buflen);
    Permutation(12);
    m_buflen = 8;
}


VOID CAsconXof128::Squeeze(UINT8 * out, SIZE_T len)
{
    if ( m_buflen < 8 )
    {
        SIZE_T take = (len > 8 - m_buflen) ? 8 - m_buflen : len;
        memcpy(out, m_buf + m_buflen, take);
        m_buflen += take;
        out += take;
        len -= take;
    }
    while ( len >= 8 )
    {
        Uint64ToBytes(out, m_state[0], 8);
        Permutation(12);
        out += 8;
        len -= 8;
    }
    if ( len > 0 )
    {
        Uint64ToBytes(m_buf, m_state[0], 8);
        Permutation(12);
        memcpy(out, m_buf, len);
        m_buflen = len;
    }
}

