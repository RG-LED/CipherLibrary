/* ========================================================================== */
/**
 * @file    aesctr.cpp
 * @brief   AES-CTR cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aesctr.h"
#include "secure.h"


template<>
VOID CAesCtr<AesCtrSpec::BIG32>::IncrementVector()
{
    UINT32 acc = 1;
    for ( INT32 i = 15; i >= 12; i-- )
    {
        acc += m_vector[i];
        m_vector[i] = (UINT8)acc;
        acc >>= 8;
    }
}

template<>
VOID CAesCtr<AesCtrSpec::LITTLE32>::IncrementVector()
{
    UINT32 acc = 1;
    for ( INT32 i = 0; i < 4; i++ )
    {
        acc += m_vector[i];
        m_vector[i] = (UINT8)acc;
        acc >>= 8;
    }
}

template<>
VOID CAesCtr<AesCtrSpec::BIG128>::IncrementVector()
{
    UINT32 acc = 1;
    for ( INT32 i = 15; i >= 0; i-- )
    {
        acc += m_vector[i];
        m_vector[i] = (UINT8)acc;
        acc >>= 8;
    }
}

template<>
VOID CAesCtr<AesCtrSpec::LITTLE128>::IncrementVector()
{
    UINT32 acc = 1;
    for ( INT32 i = 0; i < 16; i++ )
    {
        acc += m_vector[i];
        m_vector[i] = (UINT8)acc;
        acc >>= 8;
    }
}

template<>
VOID CAesCtr<AesCtrSpec::XLITTLE128>::IncrementVector()
{
    UINT32 acc = 1;
    for ( INT32 i = 0; i < 16; i++ )
    {
        acc += m_ex.m_counter[i];
        m_ex.m_counter[i] = (UINT8)acc;
        m_vector[i] = m_ex.m_vectorbase[i] ^ m_ex.m_counter[i];
        acc >>= 8;
    }
}

