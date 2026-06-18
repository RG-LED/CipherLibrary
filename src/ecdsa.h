/* ========================================================================== */
/**
 * @file    ecdsa.h
 * @brief   ECDSA signature class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ECDSA_H_)
#define _ECDSA_H_

#include "ecbase.h"
#include "hmac.h"
#include "Sha256.h"
#include "Sha384.h"

/* ========================================================================== */
/**
 * helper data
 */
/* ========================================================================== */

template<EcCurve C>
struct EcdsaTraits;

// ---- P256 ----
template<>
struct EcdsaTraits<EcCurve::P256> {
    using CHmacHash = CHmac<CSha256>;
};

// ---- P384 ----
template<>
struct EcdsaTraits<EcCurve::P384> {
    using CHmacHash = CHmac<CSha384>;
};

/* ========================================================================== */
/**
 * ECDSA signature class
 */
/* ========================================================================== */

template<EcCurve C>
class CEcdsa : public CEcBase<C>
{
public:
    using CHmacHash = typename EcdsaTraits<C>::CHmacHash;

    using CEcBase<C>::SCALAR_SIZE;
    using CEcBase<C>::CField;
    using CEcBase<C>::CScalar;
    using CEcBase<C>::CPrivateKey;
    using CEcBase<C>::CPublicKey;
    using CEcBase<C>::CPoint;

    typedef UINT8 Signature[SCALAR_SIZE * 2];
    typedef UINT8 Digest[SCALAR_SIZE];

    // key generation
    static BOOL GenerateKeyPair(CPrivateKey & priv, CPublicKey & pub, const UINT8 * seed)
    {
        // 1. generate random
        priv.d.fromBytesBE(seed);

        // 2. limit within mod n
        priv.d.ReduceModN();

        // 3. zero check
        if ( priv.d.IsZero() )
        {
            return FALSE;
        }

        // 4. Q = d * G
        CPoint G;
        G.SetGenerator();

        CPoint Q;
        CPoint::ScalarMul(Q, G, priv.d);

        // 5. convert to affine
        Q.ToAffine(pub.x, pub.y);

        return TRUE;
    }

    // sign
    static BOOL SignDigest(const CPrivateKey & priv, const Digest digest, Signature sig, const UINT8 * kb = NULL)
    {
        CScalar e;
        e.fromBytesBE(digest);  // read first 32 bytes

        CScalar k;
        if ( !GenerateNonceRFC6979(priv, e, k) )
        {
            return FALSE;
        }
        if ( kb != NULL ) k.fromBytesBE(kb);

        CPoint G, R;
        G.SetGenerator();
        CPoint::ScalarMul(R, G, k);

        CField x, y;
        R.ToAffine(x, y);

        CScalar r(x);
        r.ReduceModN();

        if ( r.IsZero() )
        {
            return FALSE;
        }

        CScalar rd, sum, kinv, s;

        CScalar::Mul(rd, r, priv.d);
        CScalar::Add(sum, e, rd);
        CScalar::Inv(kinv, k);
        CScalar::Mul(s, sum, kinv); // s = inv(k) * (e + r * d)

        if ( s.IsZero() )
        {
            return FALSE;
        }

        s.Normalize();

        r.toBytesBE(sig);
        s.toBytesBE(sig + SCALAR_SIZE);

        return TRUE;
    }

    // verify
    static BOOL VerifyDigest(const CPublicKey & pub, const Digest digest, const Signature sig)
    {
        CScalar r, s;
        r.fromBytesBE(sig);
        s.fromBytesBE(sig + SCALAR_SIZE);

        // check range
        if ( r.IsZero() || s.IsZero() )
        {
            return FALSE;
        }

        if ( r >= CScalar::N || s >= CScalar::N )
        {
            return FALSE;
        }

        // e
        CScalar e;
        e.fromBytesBE(digest);  // read first 32 bytes

        // w = s^-1
        CScalar w;
        CScalar::Inv(w, s);

        // u1, u2
        CScalar u1, u2;
        CScalar::Mul(u1, e, w);

        CScalar::Mul(u2, r, w);

        // calculate point
        CPoint G, Q;
        G.SetGenerator();
        Q.FromAffine(pub.x, pub.y);

        CPoint P1, P2, X;
        CPoint::ScalarMul(P1, G, u1);
        CPoint::ScalarMul(P2, Q, u2);
        CPoint::Add(X, P1, P2);

        if ( X.IsInfinity() )
        {
            return FALSE;
        }

        // make it affine
        CField x, y;
        X.ToAffine(x, y);

        // v = x mod N
        CScalar v(x);
        v.ReduceModN();

        return (v == r);
    }

private:
    static BOOL GenerateNonceRFC6979(const CPrivateKey & priv, const CScalar & e, CScalar & k)
    {
        CHmacHash hmac;

        UINT8 K[SCALAR_SIZE] = {0};
        UINT8 V[SCALAR_SIZE];
        memset(V, 0x01, sizeof(V));

        UINT8 seed[SCALAR_SIZE * 2];

        priv.d.toBytesBE(seed);
        e.toBytesBE(seed + SCALAR_SIZE);

        // K = HMAC(K, V || 0x00 || seed)
        hmac.Initialize(K, sizeof(K));
        hmac.Update(V, sizeof(V));
        UINT8 zero = 0x00;
        hmac.Update(&zero, 1);
        hmac.Update(seed, sizeof(seed));
        hmac.Finish(K);

        // V = HMAC(K, V)
        hmac.Initialize(K, sizeof(K));
        hmac.Update(V, sizeof(V));
        hmac.Finish(V);

        // K = HMAC(K, V || 0x01 || seed)
        hmac.Initialize(K, sizeof(K));
        hmac.Update(V, sizeof(V));
        UINT8 one = 0x01;
        hmac.Update(&one, 1);
        hmac.Update(seed, sizeof(seed));
        hmac.Finish(K);

        // V = HMAC(K, V)
        hmac.Initialize(K, sizeof(K));
        hmac.Update(V, sizeof(V));
        hmac.Finish(V);

        while ( TRUE )
        {
            // V = HMAC(K, V)
            hmac.Initialize(K, sizeof(K));
            hmac.Update(V, sizeof(V));
            hmac.Finish(V);

            k.fromBytesBE(V);
            k.ReduceModN();

            if ( !k.IsZero() )
            {
                return TRUE;
            }

            // retry
            hmac.Initialize(K, sizeof(K));
            hmac.Update(V, sizeof(V));
            hmac.Update(&zero, 1);
            hmac.Finish(K);

            hmac.Initialize(K, sizeof(K));
            hmac.Update(V, sizeof(V));
            hmac.Finish(V);
        }
    }
};

#endif /* #if !defined(_ECDSA_H_) */

