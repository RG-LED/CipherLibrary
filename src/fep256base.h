/* ========================================================================== */
/**
 * @file    fep256base.h
 * @brief   P256 finit field number base class for ECDSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FEP256BASE_H_)
#define _FEP256BASE_H_

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

#endif // _FEP256BASE_H_

