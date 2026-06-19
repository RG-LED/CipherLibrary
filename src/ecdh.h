/* ========================================================================== */
/**
 * @file    ecdh.h
 * @brief   ECDH key exchange class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ECDH_H_)
#define _ECDH_H_

#include "ecbase.h"

/* ========================================================================== */
/**
 * ECDH key exchange class
 */
/* ========================================================================== */

template<EcCurve C>
class CEcdh : public CEcBase<C>
{
public:
    using CEcBase<C>::SCALAR_SIZE;
    using CEcBase<C>::CField;
    using CEcBase<C>::CScalar;
    using CEcBase<C>::CPrivateKey;
    using CEcBase<C>::CPublicKey;
    using CEcBase<C>::CPoint;

    // generate public key
    static BOOL PrivateKeyToPublicKey(UINT8 pub[SCALAR_SIZE * 2 + 1], const UINT8 priv[SCALAR_SIZE])
    {
        CScalar d;
        d.fromBytesBE(priv);

        if ( d.IsZero() || d >= CScalar::N )
        {
            return FALSE;
        }

        CPoint G;
        G.SetGenerator();

        CPoint Q;
        CPoint::ScalarMul(Q, G, d);

        if ( Q.IsInfinity() )
        {
            return FALSE;
        }

        CField x, y;
        Q.ToAffine(x, y);

        pub[0] = 0x04;
        x.toBytesBE(&pub[1]);
        y.toBytesBE(&pub[SCALAR_SIZE + 1]);

        return TRUE;
    }

    // generate shared secret key
    static BOOL GetSharedSecret(UINT8 secret[SCALAR_SIZE], const UINT8 priv[SCALAR_SIZE], const UINT8 pub[SCALAR_SIZE * 2 + 1])
    {
        // secret key
        CScalar d;
        d.fromBytesBE(priv);
        if ( d.IsZero() || d >= CScalar::N )
        {
            return FALSE;
        }

        // public key
        if ( pub[0] != 0x04 )
        {
            return FALSE;
        }

        CField x, y;
        x.fromBytesBE(&pub[1]);
        y.fromBytesBE(&pub[SCALAR_SIZE + 1]);
        if ( !CPoint::IsOnCurve(x, y) )
        {
            return FALSE;
        }

        CPoint P;
        P.FromAffine(x, y);

        CPoint check;
        CPoint::ScalarMul(check, P, CScalar::N);
        if ( !check.IsInfinity() )
        {
            return FALSE;
        }

        CPoint R;
        CPoint::ScalarMul(R, P, d);

        if ( R.IsInfinity() )
        {
            return FALSE;
        }

        R.ToAffine(x, y);

        x.toBytesBE(secret);

        return TRUE;
    }
};

#endif /* #if !defined(_ECDH_H_) */

