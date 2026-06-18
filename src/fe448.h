/* ========================================================================== */
/**
 * @file    fe448.h
 * @brief   Fe448 finit field class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FE448_H_)
#define _FE448_H_

#include "FeBigInt512.h"

// field element: F_p (p = 2^448 - 2^224 - 1)
class CFe448 : public CFeBigInt512
{
public:
    CFe448() { }
    CFe448(UINT32 n) : CFeBigInt512(n) { }
    CFe448(const UINT8 s[BI512_BYTES]) : CFeBigInt512(s) { }
    CFe448(CFeBigInt512 & n) : CFeBigInt512(n) { }

    // basic operation (mod p)
    static VOID Add(CFe448 & out, const CFe448 & a, const CFe448 & b);
    static VOID Sub(CFe448 & out, const CFe448 & a, const CFe448 & b);
    static VOID Mul(CFe448 & out, const CFe448 & a, const CFe448 & b);
    static VOID Neg(CFe448 & out, const CFe448 & a);
    static BOOL Inv(CFe448 & out, const CFe448 & a); // inverse
    static VOID Pow(CFe448 & out, const CFe448 & a, const CFe448 & b);
    static BOOL Sqrt(CFe448 & out, const CFe448 & a);
    static BOOL SqrtRatio(CFe448 &out, const CFe448 &a, const CFe448 &b);

    static CFe448 P;          // 2^448 - 2^224 - 1
    static CFe448 P2;         // P - 2
    static CFe448 P14;        // (P + 1) / 4
    static CFe448 D;
    VOID ReduceModP() { ModP(*this, *this); }

private:
    VOID ConditionalSubP();

    static VOID ModP(CFe448 & out, const CFe448 & a);
    static VOID ModP(CFe448 & out, FOLD_BUF & in);
};

// field element:L
class CScalarL512 : public CFeBigInt512
{
public:
    CScalarL512() { }
    CScalarL512(UINT32 n) : CFeBigInt512(n) { }
    CScalarL512(const UINT8 s[BI512_BYTES]) : CFeBigInt512(s) { }
    CScalarL512(CFeBigInt512 & n) : CFeBigInt512(n) { }

    // basic operation (mod L)
    static VOID Add(CScalarL512 & out, const CScalarL512 & a, const CScalarL512 & b);
    static VOID Mul(CScalarL512 & out, const CScalarL512 & a, const CScalarL512 & b);

    VOID fromBytesLEClamp(const UINT8 in[114]);
    VOID fromBytesLE114(const UINT8 in[114]);

    static CScalarL512 L;
    static CScalarL512 MU;
    static CScalarL512 R2;
    static CScalarL512 B16m;
    static CScalarL512 B32m;
    static const BASE_TYPE Ninv;  // -N0^{-1} mod 2^32
    VOID ReduceModL() { ModL(*this, *this); }
    VOID Clamping();

private:
    VOID ConditionalSubL();

    static VOID ModL(CScalarL512 & out, const CScalarL512 & a);
    static VOID ModL(CScalarL512 & out, FOLD_BUF & buf);
};

#endif // _FE448_H_

