/* ========================================================================== */
/**
 * @file    asn1encode.cpp
 * @brief   ASN.1 DER encode class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asn1encode.h"

#define CHECK_LIMIT(n)  if ( m_pointer + (n) > m_end ) return FALSE

CAsn1Encoder::CAsn1Encoder()
{
    m_depth = 0;
}


VOID CAsn1Encoder::Initialize(UINT8 * top, SIZE_T len)
{
    m_depth = 0;
    m_top = m_pointer = top;
    m_end = &top[len];
}


BOOL CAsn1Encoder::PutElement(Asn1Tag tag, const UINT8 * data, SIZE_T size)
{
    if ( (tag & 0x20) != 0 )
    {
        return FALSE;
    }

    CHECK_LIMIT(2);

    *m_pointer++ = (UINT8)tag;
    if ( !PutSize(m_pointer, size) )
    {
        return FALSE;
    }

    CHECK_LIMIT(size);

    memcpy(m_pointer, data, size);
    m_pointer += size;

    return TRUE;
}


BOOL CAsn1Encoder::StartConstructed(Asn1Tag tag)
{
    if ( m_depth >= MAX_DEPTH - 1 )
    {
        return FALSE;
    }

    CHECK_LIMIT(2);

    *m_pointer++ = (UINT8)tag;
    m_sizePtr[m_depth++] = m_pointer;
    *m_pointer++ = 0;   // size
    if ( tag == BitString )
    {
        CHECK_LIMIT(1);
        *m_pointer++ = 0;   // unused bits
    }

    return TRUE;
}


BOOL CAsn1Encoder::EndConstructed()
{
    if ( m_depth == 0 )
    {
        return FALSE;
    }

    UINT8 * p = m_sizePtr[--m_depth];
    SIZE_T size = m_pointer - (p + 1);
    SIZE_T n = SizeField(size);

    if ( n == 1 )
    {
        *p = (UINT8)size;
    }
    else
    {
        CHECK_LIMIT(n - 1);
        m_pointer += n - 1;

        for ( SIZE_T i = size; i > 0; i-- )
        {
            p[i + (n - 1)] = p[i];
        }
        if ( !PutSize(p, size) )
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL CAsn1Encoder::PutSize(UINT8 * & ptr, SIZE_T size)
{
    SIZE_T n = SizeField(size);

    CHECK_LIMIT(n);

    if ( n == 1 )
    {
        *ptr++ = (UINT8)size;
    }
    else
    {
        *ptr++ = (UINT8)(0x80 + n - 1);
        for ( SIZE_T i = 0; i < n - 1; i++ )
        {
            *ptr++ = (UINT8)(size >> (8 * (n - 2 - i)));
        }
    }

    return TRUE;
}


SIZE_T CAsn1Encoder::SizeField(SIZE_T size)
{
    if ( size < 0x80 )
    {
        return 1;
    }
    if ( size < 0x100 )
    {
        return 2;
    }
    if ( size < 0x10000 )
    {
        return 3;
    }
    if ( size < 0x1000000 )
    {
        return 4;
    }
    return 5;
}


SIZE_T CAsn1Encoder::Finish()
{
    while ( m_depth > 0 )
    {
        if ( !EndConstructed() )
        {
            return 0;
        }
    }
    return m_pointer - m_top;
}

