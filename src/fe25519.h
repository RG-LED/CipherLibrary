/* ========================================================================== */
/**
 * @file    fe25519.h
 * @brief   Fe25519 finit field class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FE25519_H_)
#define _FE25519_H_

#include "FeBigInt256.h"

// field element: F_p (p = 2^255 - 19)
class CFe25519 : public CFeBigInt256
{
public:
    CFe25519() { }
    CFe25519(UINT32 n) : CFeBigInt256(n) { }
    CFe25519(const UINT8 s[32]) : CFeBigInt256(s) { }
    CFe25519(CFeBigInt256 & n) : CFeBigInt256(n) { }

    // basic operation (mod p)
    static VOID Add(CFe25519 & out, const CFe25519 & a, const CFe25519 & b);
    static VOID Sub(CFe25519 & out, const CFe25519 & a, const CFe25519 & b);
    static VOID Mul(CFe25519 & out, const CFe25519 & a, const CFe25519 & b);
    static VOID Neg(CFe25519 & out, const CFe25519 & a);
    static VOID Inv(CFe25519 & out, const CFe25519 & a); // inverse
    static VOID Pow(CFe25519 & out, const CFe25519 & a, const CFe25519 & b);

    static CFe25519 Nineteen;   // 19
    static CFe25519 P;          // 2^255 - 19
    static CFe25519 P2;         // P - 2
    static CFe25519 d;
    static CFe25519 d2;         // 2 * d
    static CFe25519 BX;
    static CFe25519 BY;
    static CFe25519 SqrtM1;     // sqrt(-1)
    static CFe25519 P58;        // (P-5)/8
    VOID ReduceModP() { ModP(*this, *this); }

private:
    static VOID Mul(FOLD_BUF & out, const FOLD_BUF & a, const CFe25519 & b);
    static VOID ModP(CFe25519 & out, const CFe25519 & a);
    static VOID ModP(CFe25519 & out, FOLD_BUF & buf);
    static VOID ModP(FOLD_BUF & buf);

    static VOID FoldP(FOLD_BUF & a);

    static VOID Expand(FOLD_BUF & buf, const CFe25519 & n);
    static VOID Extract(CFe25519 & out, const FOLD_BUF & buf);
};


// field element: L
class CScalarL25519 : public CFeBigInt256
{
public:
    CScalarL25519();
    CScalarL25519(UINT32 n) : CFeBigInt256(n) { }
    CScalarL25519(const UINT8 s[32]) : CFeBigInt256(s) { }
    CScalarL25519(CFeBigInt256 & n) : CFeBigInt256(n) { }

    // basic operation (mod L)
    static VOID Add(CScalarL25519 & out, const CScalarL25519 & a, const CScalarL25519 & b);
    static VOID Mul(CScalarL25519 & out, const CScalarL25519 & a, const CScalarL25519 & b);
 
    VOID fromBytesLE64(const UINT8 s[64]);
    VOID ReduceModL() { ModL(*this, *this); }
    VOID Clamping();
    static VOID Clamping(UINT8 s[32]);

    static CScalarL25519 L;  // L
    static CScalarL25519 Llow; // Low part of L

private:
    static VOID Add(FOLD_BUF & out, const CScalarL25519 & a, const CScalarL25519 & b);
    static VOID Mul(FOLD_BUF & out, const CScalarL25519 & a, const CScalarL25519 & b);
    static VOID Mul(FOLD_BUF & out, const FOLD_BUF & a, const CScalarL25519 & b);
    static VOID ModL(CScalarL25519 & out, const CScalarL25519 & a);
    static VOID ModL(CScalarL25519 & out, FOLD_BUF & buf);
    static VOID ModL(FOLD_BUF & buf);
    static VOID FoldL(FOLD_BUF & buf);
};

#endif // _FE25519_H_

