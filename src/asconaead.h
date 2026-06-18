/* ========================================================================== */
/**
 * @file    asconaead.h
 * @brief   Ascon-AEAD base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONAEAD_H_)
#define _ASCONAEAD_H_

#include "asconbebase.h"

class CAsconAead : public CAsconBeBase
{
public:
    ~CAsconAead();

protected:
    VOID Initialize(const UINT8 key[16], const UINT8 nonce[16], UINT64 iv);

    UINT64 m_k0;
    UINT64 m_k1;
};

#endif // #if !defined(_ASCONAEAD_H_)

