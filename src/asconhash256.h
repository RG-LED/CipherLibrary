/* ========================================================================== */
/**
 * @file    asconhash256.h
 * @brief   Ascon-HASH256 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONHASH256_H_)
#define _ASCONHASH256_H_

#include "asconlebase.h"

class CAsconHash256 : public CAsconLeBase
{
public:
    VOID Initialize();
    VOID Update(const UINT8 * data, SIZE_T len);
    VOID Finish(UINT8 hash[32]);

protected:
    VOID Absorb(const UINT8 data[8]);

    SIZE_T m_buflen;
    UINT8 m_buf[8];
};

#endif // #if !defined(_ASCONHASH256_H_)

