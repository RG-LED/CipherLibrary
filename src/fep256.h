/* ========================================================================== */
/**
 * @file    fep258.h
 * @brief   P256 finit field number class for ECDSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FEP256_H_)
#define _FEP256_H_

#include "FeBigInt256.h"

class CFeP256Base : public CFeBigInt256
{
public:
    CFeP256Base() { }
    CFeP256Base(UINT32 n) : CFeBigInt256(n) { }
    CFeP256Base(const UINT8 s[32]) : CFeBigInt256(s) { }
    CFeP256Base(const CFeBigInt256 & n) : CFeBigInt256(n) { }

protected:
    typedef BASE_TYPE FOLD_BUF2[BI256_LIMBS + 1];

    static VOID Add(FOLD_BUF2 & out, const CFeP256Base & a, const CFeP256Base & b);
    static VOID Sub(FOLD_BUF2 & out, const CFeP256Base & a, const CFeP256Base & b);
    static VOID Extract2(CFeP256Base & out, const FOLD_BUF2 & buf);
    static VOID ConditionalAdd(FOLD_BUF2 & buf, const CFeP256Base & n);
    static VOID ConditionalSub(FOLD_BUF2 & buf, const CFeP256Base & n);
private:
    static inline BASE_TYPE MakeMask(INT32 n) { return (BASE_TYPE)((n) | -(n)); }
};

// field element: F_p (p = 2^256 - 2^224 + 2^192 + 2^96 - 1)
class CFeP256 : public CFeP256Base
{
public:
    CFeP256() { }
    CFeP256(UINT32 n) : CFeP256Base(n) { }
    CFeP256(const UINT8 s[32]) : CFeP256Base(s) { }
    CFeP256(const CFeBigInt256 & n) : CFeP256Base(n) { }

    // basic operations (mod p)
    static VOID Add(CFeP256 & out, const CFeP256 & a, const CFeP256 & b);
    static VOID Sub(CFeP256 & out, const CFeP256 & a, const CFeP256 & b);
    static VOID Mul(CFeP256 & out, const CFeP256 & a, const CFeP256 & b);
    static VOID Neg(CFeP256 & out, const CFeP256 & a);
    static VOID Inv(CFeP256 & out, const CFeP256 & a); // inverse
    static VOID Pow(CFeP256 & out, const CFeP256 & a, const CFeP256 & b);

    static CFeP256 P;   // 2^256 - 2^224 + 2^192 + 2^96 - 1
    static CFeP256 P2;  // P - 2
    static CFeP256 A;   // -3 = P - 3
    static CFeP256 B;
    static CFeP256 Gx;
    static CFeP256 Gy;
    VOID ReduceModP() { ModP(*this, *this); }

private:
    static VOID Mul(FOLD_BUF & out, const FOLD_BUF & a, const CFeP256 & b);
    static VOID ModP(CFeP256 & out, const CFeP256 & a);
    static VOID ModP(CFeP256 & out, FOLD_BUF & buf);
    static VOID ModP(FOLD_BUF & buf);

    static VOID FoldP(FOLD_BUF & a);
};


class CScalarN256 : public CFeP256Base
{
public:
    CScalarN256();
    CScalarN256(UINT32 n) : CFeP256Base(n) { }
    CScalarN256(const UINT8 s[32]) : CFeP256Base(s) { }
    CScalarN256(const CFeBigInt256 & n) : CFeP256Base(n) { }

    static VOID Add(CScalarN256 & out, const CScalarN256 & a, const CScalarN256 & b);
    static VOID Sub(CScalarN256 & out, const CScalarN256 & a, const CScalarN256 & b);
    static VOID Mul(CScalarN256 & out, const CScalarN256 & a, const CScalarN256 & b);
    static VOID Inv(CScalarN256 & out, const CScalarN256 & a); // inverse
    static VOID Pow(CScalarN256 & out, const CScalarN256 & a, const CScalarN256 & b);

    VOID ReduceModN() { ModN(*this, *this); }
    VOID Normalize();

    static CScalarN256 N;       // N
    static CScalarN256 N2;      // N - 2
    static CScalarN256 Nhalf;   // N / 2

private:
    static VOID Mul(FOLD_BUF & out, const CScalarN256 & a, const CScalarN256 & b);
    static VOID Mul(FOLD_BUF & out, const FOLD_BUF & a, const CScalarN256 & b);
    static VOID ModN(CScalarN256 & out, const CScalarN256 & a);
    static VOID ModN(CScalarN256 & out, FOLD_BUF & buf);
};

#endif // _FEP256_H_

