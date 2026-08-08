/* ========================================================================== */
/**
 * @file    fesecp256k1.h
 * @brief   SECP256K1 finit field number class for ECDSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FESECP256K1_H_)
#define _FESECP256K1_H_

#include "fep256base.h"

// field element: F_p (p = 2^256 - 2^32 - 2^9 - 2^7 - 2^6 - 2^4 - 1)
class CFeSecp256k1 : public CFeP256Base
{
public:
    CFeSecp256k1() { }
    CFeSecp256k1(UINT32 n) : CFeP256Base(n) { }
    CFeSecp256k1(const UINT8 s[32]) : CFeP256Base(s) { }
    CFeSecp256k1(const CFeBigInt256 & n) : CFeP256Base(n) { }

    // basic operations (mod p)
    static VOID Add(CFeSecp256k1 & out, const CFeSecp256k1 & a, const CFeSecp256k1 & b);
    static VOID Sub(CFeSecp256k1 & out, const CFeSecp256k1 & a, const CFeSecp256k1 & b);
    static VOID Mul(CFeSecp256k1 & out, const CFeSecp256k1 & a, const CFeSecp256k1 & b);
    static VOID Neg(CFeSecp256k1 & out, const CFeSecp256k1 & a);
    static VOID Inv(CFeSecp256k1 & out, const CFeSecp256k1 & a); // inverse
    static VOID Pow(CFeSecp256k1 & out, const CFeSecp256k1 & a, const CFeSecp256k1 & b);

    static CFeSecp256k1 P;   // 2^256 - 2^32 - 2^9 - 2^7 - 2^6 - 2^4 - 1
    static CFeSecp256k1 P2;  // P - 2
    static CFeSecp256k1 A;
    static CFeSecp256k1 B;
    static CFeSecp256k1 Gx;
    static CFeSecp256k1 Gy;
    VOID ReduceModP() { ModP(*this, *this); }

private:
    static VOID Mul(FOLD_BUF & out, const FOLD_BUF & a, const CFeSecp256k1 & b);
    static VOID ModP(CFeSecp256k1 & out, const CFeSecp256k1 & a);
    static VOID ModP(CFeSecp256k1 & out, FOLD_BUF & buf);
    static VOID ModP(FOLD_BUF & buf);

    static VOID FoldP(FOLD_BUF & a);
};


class CScalarSecp256k1 : public CFeP256Base
{
public:
    CScalarSecp256k1();
    CScalarSecp256k1(UINT32 n) : CFeP256Base(n) { }
    CScalarSecp256k1(const UINT8 s[32]) : CFeP256Base(s) { }
    CScalarSecp256k1(const CFeBigInt256 & n) : CFeP256Base(n) { }

    static VOID Add(CScalarSecp256k1 & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b);
    static VOID Sub(CScalarSecp256k1 & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b);
    static VOID Mul(CScalarSecp256k1 & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b);
    static VOID Inv(CScalarSecp256k1 & out, const CScalarSecp256k1 & a); // inverse
    static VOID Pow(CScalarSecp256k1 & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b);

    VOID ReduceModN() { ModN(*this, *this); }
    VOID Normalize();

    static CScalarSecp256k1 N;       // N
    static CScalarSecp256k1 N2;      // N - 2
    static CScalarSecp256k1 Nhalf;   // N / 2

private:
    static VOID Mul(FOLD_BUF & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b);
    static VOID Mul(FOLD_BUF & out, const FOLD_BUF & a, const CScalarSecp256k1 & b);
    static VOID ModN(CScalarSecp256k1 & out, const CScalarSecp256k1 & a);
    static VOID ModN(CScalarSecp256k1 & out, FOLD_BUF & buf);
};

#endif // _FESECP256K1_H_

