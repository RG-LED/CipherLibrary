/* ========================================================================== */
/**
 * @file    asn1decode.cpp
 * @brief   ASN.1 DER decode class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asn1decode.h"

CAsn1Decoder::CAsn1Decoder()
{
    m_depth = 0;
}


VOID CAsn1Decoder::Initialize(const UINT8 * top, SIZE_T len)
{
    m_depth = 0;
    m_top = m_content = top;
    m_tag = Null;
    m_size = 0;
    m_end[m_depth] = &top[len];
    m_position[m_depth] = -1;
}


BOOL CAsn1Decoder::Next(BOOL diveInner)
{
    if ( (m_tag & 0x20) != 0 || diveInner )  // Constructed
    {
        if ( m_tag == BitString )
        {
            if ( m_size == 0 )
            {
                return FALSE;
            }
            m_content++;
            m_size--;
        }
        m_top = m_content;
        if ( m_depth >= MAX_DEPTH - 1 )
        {
            return FALSE;
        }
        m_depth++;
        m_end[m_depth] = &m_top[m_size];
        m_position[m_depth] = 0;
        if ( m_size > 0 )
        {
            return FetchElement();
        }
        // empty
    }

    m_top = &m_content[m_size];
    while ( m_top >= m_end[m_depth] )
    {
        if ( m_depth <= 0 )
        {
            return FALSE;
        }
        m_depth--;
    }
    m_position[m_depth]++;

    return FetchElement();
}


BOOL CAsn1Decoder::GetContents(const UINT8 ** ptr, SIZE_T * len) const
{
    if ( (m_tag & 0x20) != 0 )  // Constructed
    {
        return FALSE;
    }
    *ptr = m_content;
    *len = m_size;
    return TRUE;
}


BOOL CAsn1Decoder::FetchElement()
{
    if ( &m_top[2] > m_end[m_depth] )
    {
        return FALSE;
    }

    m_tag = (Asn1Tag)m_top[0];

    m_size = m_top[1];
    if ( m_size & 0x80 )
    {
        INT32 n = (INT32)(m_size & 0x7f);
        m_content = &m_top[2 + n];
        if ( m_content > m_end[m_depth] )
        {
            return FALSE;
        }
        m_size = 0;
        for ( INT32 i = 0; i < n; i++ )
        {
            m_size = (m_size << 8) | m_top[2 + i];
        }
    }
    else
    {
        m_content = &m_top[2];
    }

    return &m_content[m_size] <= m_end[m_depth];
}


VOID CAsn1Decoder::GetPosition(CHAR8 pos[MAX_DEPTH + 1]) const
{
    CHAR8 * p = pos;
    for ( INT32 i = 0; i <= m_depth; i++ )
    {
        if ( m_position[i] <= 9 )
        {
            *p++ = CHAR8('0' + m_position[i]);
        }
        else
        {
            *p++ = CHAR8('A' + m_position[i] - 10);
        }
    }
    *p = '\0';
}

