/* ========================================================================== */
/**
 * @file    kdfcmac.h
 * @brief   KDF-CMAC class (counter mode)
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_KDFCMAC_H_)
#define _KDFCMAC_H_

#include "aescmac.h"


class CKdfCmac
{
public:
    CKdfCmac() { }

    BOOL DeriveKey(const UINT8 * key, SIZE_T keyLen,
                   const UINT8 * label, SIZE_T labelLen,
                   const UINT8 * context, SIZE_T contextLen,
                   UINT8 * out, SIZE_T outLen)
    {
        SIZE_T block = NBb;
        SIZE_T loop = (outLen + block - 1) / block;
        if ( loop > 0xfffffffflu )
        {
            return FALSE;
        }

        UINT32 outBits = (UINT32)(outLen * 8);
        UINT8 num[4];
        UINT8 buf[NBb];

        for ( UINT32 i = 1; i <= loop; i++ )
        {
            m_prf.SetKeys(key, keyLen);

            num[0] = (UINT8)(i >> 24);
            num[1] = (UINT8)(i >> 16);
            num[2] = (UINT8)(i >> 8);
            num[3] = (UINT8)i;
            m_prf.Update(num, sizeof(num));

            m_prf.Update(label, labelLen);
            m_prf.Update((UINT8 *)"", 1);
            m_prf.Update(context, contextLen);

            num[0] = (UINT8)(outBits >> 24);
            num[1] = (UINT8)(outBits >> 16);
            num[2] = (UINT8)(outBits >> 8);
            num[3] = (UINT8)outBits;
            m_prf.Update(num, sizeof(num));

            SIZE_T take = (block > outLen) ? outLen : block;

            m_prf.Finish(buf);
            memcpy(out, buf, take);
            out += take;
            outLen -= take;
        }

        secure_zero(num, sizeof(num));
        secure_zero(buf, sizeof(buf));

        return TRUE;
    }

#ifdef NIST_TEST
    BOOL DeriveKeyRaw(const UINT8 * key, SIZE_T keyLen, const UINT8 * input, SIZE_T inputLen, UINT8 * out, SIZE_T outLen)
    {
        SIZE_T block = NBb;
        SIZE_T loop = (outLen + block - 1) / block;
        if ( loop > 0xfffffffflu )
        {
            return FALSE;
        }

        for ( UINT32 i = 1; i <= loop; i++ )
        {
            m_prf.SetKeys(key, keyLen);

            UINT8 num[4];

            num[0] = (UINT8)(i >> 24);
            num[1] = (UINT8)(i >> 16);
            num[2] = (UINT8)(i >> 8);
            num[3] = (UINT8)i;
            m_prf.Update(num, sizeof(num));

            m_prf.Update(input, inputLen);

            SIZE_T take = (block > outLen) ? outLen : block;
            UINT8 buf[NBb];

            m_prf.Finish(buf);
            memcpy(out, buf, take);
            out += take;
            outLen -= take;
        }

        return TRUE;
    }
#endif

private:
    CAesCmac m_prf;
};

#endif // #if !defined(_KDFCMAC_H_)

