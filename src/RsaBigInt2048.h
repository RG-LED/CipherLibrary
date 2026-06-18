/* ========================================================================== */
/**
 * @file    RsaBigInt2048.h
 * @brief   2048-bit BigInt class for RSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_RSABIGINT2048_H_)
#define _RSABIGINT2048_H_

#include "FeBigInt2048.h"

struct CRsaMontCtx2048;

class CRsaBigInt2048 : public CFeBigInt2048
{
public:
    CRsaBigInt2048() { }
    CRsaBigInt2048(UINT32 n) : CFeBigInt2048(n) { }
    CRsaBigInt2048(const UINT8 s[BI2048_BYTES]) : CFeBigInt2048(s) { }
    CRsaBigInt2048(CFeBigInt2048 & n) : CFeBigInt2048(n) { }

    static BOOL PrepareContext(CRsaMontCtx2048 * ctx, const CRsaBigInt2048 & N, INT32 k = 32);

    VOID ToMont64(const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx);
    VOID ToMont32(const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx);
    VOID FromMont64(CRsaBigInt2048 & out, const CRsaMontCtx2048 * ctx);
    VOID FromMont32(CRsaBigInt2048 & out, const CRsaMontCtx2048 * ctx);

    VOID Reduce2048to1024(const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx);

    static VOID Mul64(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & b, const CRsaMontCtx2048 * ctx);
    static VOID Mul32(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & b, const CRsaMontCtx2048 * ctx);
    static VOID Sqr64(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx);
    static VOID Sqr32(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx);
    static VOID Add(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & b, const CRsaBigInt2048 & N);
    static VOID Sub(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & b, const CRsaBigInt2048 & N);
    static BOOL Inv(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & N);
//    static VOID Exp64(CRsaBigInt2048 & out, const CRsaBigInt2048 & base, const CRsaBigInt2048 & exp, const CRsaMontCtx2048 * ctx, INT32 bitlen);
    static VOID Exp32(CRsaBigInt2048 & out, const CRsaBigInt2048 & base, const CRsaBigInt2048 & exp, const CRsaMontCtx2048 * ctx);
    static VOID Exp64_e32(CRsaBigInt2048 & out, const CRsaBigInt2048 & base, BASE_TYPE e, const CRsaMontCtx2048 * ctx);

    VOID ToHexText(CHAR8 * buf) const;

private:
    static BASE_TYPE CalcN0Prime(BASE_TYPE n0);
    static VOID ConditionalSub(CRsaBigInt2048 & out, const CRsaBigInt2048 & N, BASE_TYPE optmask);
    static VOID CalcR2(CRsaBigInt2048 & R2, const CRsaBigInt2048 & N, INT32 k);
};

// parameters for RSA Montgomery
struct CRsaMontCtx2048 {
    CRsaBigInt2048 N;       // N (odd number)
    CRsaBigInt2048 R2;      // R^2 mod N  (R = 2^(32*64))
    CRsaBigInt2048 R3;      // R^3 mod N  (R = 2^(32*96))
    UINT32         n0prime; // n0' = -N^{-1} mod 2^32
};

#define RSA_ADD     CRsaBigInt2048::Add
#define RSA_SUB     CRsaBigInt2048::Sub
#define RSA_MUL64   CRsaBigInt2048::Mul64
#define RSA_MUL32   CRsaBigInt2048::Mul32
#define RSA_SQR64   CRsaBigInt2048::Sqr64
#define RSA_SQR32   CRsaBigInt2048::Sqr32
#define RSA_INV     CRsaBigInt2048::Inv
#define RSA_EXP64   CRsaBigInt2048::Exp64
#define RSA_EXP32   CRsaBigInt2048::Exp32

#endif // _RSABIGINT2048_H_

