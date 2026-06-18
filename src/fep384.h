/* ========================================================================== */
/**
 * @file    fep384.h
 * @brief   P384 finit field number class for ECDSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FEP384_H_)
#define _FEP384_H_

#include "FeBigInt384.h"

class CFeP384Base : public CFeBigInt384
{
public:
    CFeP384Base() { }
    CFeP384Base(UINT32 n) : CFeBigInt384(n) { }
    CFeP384Base(const UINT8 s[48]) : CFeBigInt384(s) { }
    CFeP384Base(const CFeBigInt384 & n) : CFeBigInt384(n) { }

protected:
    typedef BASE_TYPE FOLD_BUF2[BI384_LIMBS + 1];

    static VOID Add(FOLD_BUF2 & out, const CFeP384Base & a, const CFeP384Base & b);
    static VOID Sub(FOLD_BUF2 & out, const CFeP384Base & a, const CFeP384Base & b);
    static VOID Extract2(CFeP384Base & out, const FOLD_BUF2 & buf);
    static VOID ConditionalAdd(FOLD_BUF2 & buf, const CFeP384Base & n);
    static VOID ConditionalSub(FOLD_BUF2 & buf, const CFeP384Base & n);
private:
    static inline BASE_TYPE MakeMask(INT32 n) { return (BASE_TYPE)((n) | -(n)); }
};

// field element: F_p (p = 2^384 - 2^128 - 2^96 + 2^32 - 1)
class CFeP384 : public CFeP384Base
{
public:
    CFeP384() { }
    CFeP384(UINT32 n) : CFeP384Base(n) { }
    CFeP384(const UINT8 s[48]) : CFeP384Base(s) { }
    CFeP384(const CFeBigInt384 & n) : CFeP384Base(n) { }

    // basic operations (mod p)
    static VOID Add(CFeP384 & out, const CFeP384 & a, const CFeP384 & b);
    static VOID Sub(CFeP384 & out, const CFeP384 & a, const CFeP384 & b);
    static VOID Mul(CFeP384 & out, const CFeP384 & a, const CFeP384 & b);
    static VOID Neg(CFeP384 & out, const CFeP384 & a);
    static VOID Inv(CFeP384 & out, const CFeP384 & a); // inverse
    static VOID Pow(CFeP384 & out, const CFeP384 & a, const CFeP384 & b);

    static CFeP384 P;   // 2^384 - 2^128 - 2^96 + 2^32 - 1
    static CFeP384 P2;  // P - 2
    static CFeP384 A;   // -3 = P - 3
    static CFeP384 B;
    static CFeP384 Gx;
    static CFeP384 Gy;
    VOID ReduceModP() { ModP(*this, *this); }

private:
    static VOID Mul(FOLD_BUF & out, const FOLD_BUF & a, const CFeP384 & b);
    static VOID ModP(CFeP384 & out, const CFeP384 & a);
    static VOID ModP(CFeP384 & out, FOLD_BUF & buf);
    static VOID ModP(FOLD_BUF & buf);

    static VOID FoldP(FOLD_BUF & a);
};


class CScalarN384 : public CFeP384Base
{
public:
    CScalarN384();
    CScalarN384(UINT32 n) : CFeP384Base(n) { }
    CScalarN384(const UINT8 s[32]) : CFeP384Base(s) { }
    CScalarN384(const CFeBigInt384 & n) : CFeP384Base(n) { }

    static VOID Add(CScalarN384 & out, const CScalarN384 & a, const CScalarN384 & b);
    static VOID Sub(CScalarN384 & out, const CScalarN384 & a, const CScalarN384 & b);
    static VOID Mul(CScalarN384 & out, const CScalarN384 & a, const CScalarN384 & b);
    static VOID Inv(CScalarN384 & out, const CScalarN384 & a); // inverse
    static VOID Pow(CScalarN384 & out, const CScalarN384 & a, const CScalarN384 & b);
 
    VOID ReduceModN() { ModN(*this, *this); }
    VOID Normalize();

    static CScalarN384 N;       // N
    static CScalarN384 N2;      // N - 2
    static CScalarN384 Nhalf;   // N / 2

private:
    static VOID Mul(FOLD_BUF & out, const CScalarN384 & a, const CScalarN384 & b);
    static VOID Mul(FOLD_BUF & out, const FOLD_BUF & a, const CScalarN384 & b);
    static VOID ModN(CScalarN384 & out, const CScalarN384 & a);
    static VOID ModN(CScalarN384 & out, FOLD_BUF & buf);
};

#endif // _FEP384_H_

