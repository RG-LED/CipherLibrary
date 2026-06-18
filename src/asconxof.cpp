/* ========================================================================== */
/**
 * @file    asconxof.cpp
 * @brief   Ascon-XOF hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconxof.h"


VOID CAsconXof::Initialize()
{
    CAsconHashBase::Initialize(0x00400c0000000000ull);
    m_round = 12;
}


VOID CAsconXof::Finish()
{
    CAsconHashBase::Finish();
    m_buflen = 8;
}


VOID CAsconXof::Squeeze(UINT8 * out, SIZE_T len)
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


