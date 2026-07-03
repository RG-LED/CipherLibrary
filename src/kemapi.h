/* ========================================================================== */
/**
 * @file    kemapi.h
 * @brief   KEM API class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_KEMAPI_H_)
#define _KEMAPI_H_

#include "ecdh.h"


template<EcCurve C>
class CKemApi : public CEcdh<C>
{
public:
    using CEcdh<C>::SCALAR_SIZE;
    using CEcdh<C>::CScalar;

    // secret must be passed through KDF before use
    static BOOL Encap(UINT8 * enc, UINT8 * secret, const UINT8 * pub, VOID (*rand)(VOID * p, SIZE_T s))
    {
        UINT8 eph_priv[SCALAR_SIZE];
        UINT8 eph_pub[SCALAR_SIZE * 2 + 1];

        CScalar d;
        do
        {
            (*rand)(eph_priv, sizeof(eph_priv));
            d.fromBytesBE(eph_priv);
        }
        while ( d.IsZero() || d >= CScalar::N );

        if ( !CEcdh<C>::PrivateKeyToPublicKey(eph_pub, eph_priv) )
        {
            secure_zero(eph_priv, sizeof(eph_priv));
            secure_zero(eph_pub, sizeof(eph_pub));
            return FALSE;
        }

        if ( !CEcdh<C>::GetSharedSecret(secret, eph_priv, pub) )
        {
            secure_zero(eph_priv, sizeof(eph_priv));
            secure_zero(eph_pub, sizeof(eph_pub));
            return FALSE;
        }

        memcpy(enc, eph_pub, SCALAR_SIZE * 2 + 1);

        secure_zero(eph_priv, sizeof(eph_priv));
        secure_zero(eph_pub, sizeof(eph_pub));

        return TRUE;
    }

    static BOOL Decap(UINT8 * secret, const UINT8 * priv, const UINT8 * enc)
    {
        return CEcdh<C>::GetSharedSecret(secret, priv, enc);
    }
};

#endif /* #if !defined(_KEMAPI_H_) */


