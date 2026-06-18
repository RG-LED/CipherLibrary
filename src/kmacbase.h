/* ========================================================================== */
/**
 * @file    kmacbase.h
 * @brief   KMAC MAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_KMACBASE_H_)
#define _KMACBASE_H_

#include "cshakebase.h"


class CKmacBase : protected CcShakeBase
{
public:
    VOID Initialize(const UINT8 * key, SIZE_T keylen, const UINT8 * custom, SIZE_T customlen);
    VOID Update(const UINT8 * in, SIZE_T inlen)
    {
        CcShakeBase::Update(in, inlen);
    }
    VOID Finish(UINT8 * out, SIZE_T outlen);

protected:
    VOID RightEncode(SIZE_T len);
};

#endif // #if !defined(_KMACBASE_H_)

