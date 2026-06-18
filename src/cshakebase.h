/* ========================================================================== */
/**
 * @file    cshakebase.h
 * @brief   cSHAKE128/256 hash base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_CSHAKEBASE_H_)
#define _CSHAKEBASE_H_

#include "shakebase.h"

#define CSHAKE_DSBYTE   0x04 /* domain separation for cSHAKE */

class CcShakeBase : protected CShakeBase
{
public:
    VOID Initialize(const UINT8 * func, SIZE_T funclen, const UINT8 * custom, SIZE_T customlen);
    VOID Update(const UINT8 * in, SIZE_T inlen)
    {
        Absorb(in, inlen);
    }
    VOID Finish(UINT8 * out, SIZE_T outlen);

protected:
    VOID DoPrefix(const UINT8 * func, SIZE_T funclen, const UINT8 * custom, SIZE_T customlen);
    VOID Padding(SIZE_T len);
    SIZE_T EncodeString(const UINT8 * str, SIZE_T len);
    SIZE_T EncodeInteger(SIZE_T len);

    BOOL m_cshake;
};

#endif // _CSHAKEBASE_H_


