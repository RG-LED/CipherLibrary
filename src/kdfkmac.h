/* ========================================================================== */
/**
 * @file    kdfkmac.h
 * @brief   KDF-KMAC class (counter mode)
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_KDFKMAC_H_)
#define _KDFKMAC_H_

#include "BasicDefs.h"


template<typename KMAC>
class CKdfKmac
{
public:
    CKdfKmac() { }

    BOOL DeriveKey(const UINT8 * key, SIZE_T keyLen,
                   const UINT8 * label, SIZE_T labelLen, // such as "KDF" or "KDF4X"
                   const UINT8 * context, SIZE_T contextLen,
                   UINT8 * out, SIZE_T outLen)
    {
        m_prf.Initialize(key, keyLen, label, labelLen);
        m_prf.Update(context, contextLen);
        m_prf.Finish(out, outLen);
        return TRUE;
    }

private:
    KMAC m_prf;
};

#endif // #if !defined(_KDFKMAC_H_)

