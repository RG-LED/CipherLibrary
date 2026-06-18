/* ========================================================================== */
/**
 * @file    FeBigInt384.h
 * @brief   384-bit BigInt class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FEBIGINT384_H_)
#define _FEBIGINT384_H_

#include "BasicDefs.h"

class CFeBigInt384
{
public:
#define BI384_BASE_SIZE 4   /* 4 = dword */

    typedef UINT32  BASE_TYPE;
    typedef INT32   SBASE_TYPE;
    typedef UINT64  CALC_TYPE;
    typedef INT64   SCALC_TYPE;
#define BI384_BASE_SHIFT    32
#define BI384_CALC_SHIFT    64

#define BI384_BYTES     48
#define BI384_LIMBS     (BI384_BYTES / BI384_BASE_SIZE)   // number of limbs
#define BI384_FOLD_SIZE (BI384_LIMBS * 2 + 1)  // must satisfy BI384_FOLD_SIZE >= BI384_LIMBS * 2

#if BI384_LIMBS * 2 > BI384_FOLD_SIZE
#error "Invalid size order definition"
#endif

#define BI384_SHIFT_RIGHT_LIMB(n)   ((n) >>= BI384_BASE_SHIFT)
#define BI384_SHIFT_RIGHT_CARRY(c)  ((c) = ((c) >> (BI384_CALC_SHIFT - 1)) & 1)

public:
    CFeBigInt384();
    CFeBigInt384(UINT32 n);
    CFeBigInt384(const UINT8 s[48]);
    CFeBigInt384(const CFeBigInt384 & n) { copy(n); }
    ~CFeBigInt384();

    static VOID Add(CFeBigInt384 & out, const CFeBigInt384 & n, const CFeBigInt384 & m);
    static VOID Sub(CFeBigInt384 & out, const CFeBigInt384 & n, const CFeBigInt384 & m);
    static VOID Mod(CFeBigInt384 & out, const CFeBigInt384 & n, const CFeBigInt384 & m);
    // static VOID Neg(CFeBigInt384 & out, const CFeBigInt384 & n);

    INT32 GetBit(INT32 bit) const;

    BOOL operator==(const CFeBigInt384 & rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(const CFeBigInt384 & rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(const CFeBigInt384 & rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(const CFeBigInt384 & rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(const CFeBigInt384 & rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(const CFeBigInt384 & rhs) const { return Cmp(rhs) <= 0; }

    BOOL operator==(INT32 rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(INT32 rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(INT32 rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(INT32 rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(INT32 rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(INT32 rhs) const { return Cmp(rhs) <= 0; }

    BOOL IsOdd() const { return (m_Limbs[0] & 1) != 0; }
    BOOL IsEven() const { return (m_Limbs[0] & 1) == 0; }

    BOOL IsMinus() const { return (m_Limbs[BI384_LIMBS - 1] & ((BASE_TYPE)1 << (BI384_BASE_SHIFT - 1))) != 0; }
    // BOOL IsPlus() const;
    BOOL IsZero() const;

    VOID fromBytesLE(const UINT8 * s, SIZE_T size = BI384_BYTES);
    VOID toBytesLE(UINT8 * out, SIZE_T size = BI384_BYTES) const;

    VOID fromBytesBE(const UINT8 * s, SIZE_T size = BI384_BYTES);
    VOID toBytesBE(UINT8 * out, SIZE_T size = BI384_BYTES) const;

    VOID cmux(const CFeBigInt384 & other, BASE_TYPE mask);
    VOID cswap(CFeBigInt384 & other, BASE_TYPE mask);
    VOID copy(const CFeBigInt384 & n);

    static CFeBigInt384 Zero;      // 0
    static CFeBigInt384 One;       // 1
    static CFeBigInt384 Two;       // 2

#if 0
    VOID ToHexText(CHAR8 * buf) const;
    VOID ToHex(CHAR8 * buf) const;
    VOID ToText(CHAR8 * buf) const;
    VOID FromText(const CHAR8 * buf);
#endif

protected:
    typedef BASE_TYPE FOLD_BUF[BI384_FOLD_SIZE];

    INT32 Cmp(const CFeBigInt384 & a) const { return Compare(*this, a); }
    static VOID Expand(FOLD_BUF & buf, const CFeBigInt384 & n);
    static VOID Extract(CFeBigInt384 & out, const FOLD_BUF & buf);
    static VOID Sub(FOLD_BUF & out, const CFeBigInt384 & a);
    static VOID Mul(FOLD_BUF & buf, const CFeBigInt384 & a, const CFeBigInt384 & b);
    static VOID Mul(FOLD_BUF & buf, const FOLD_BUF & a, const CFeBigInt384 & b);
    static VOID Mod(FOLD_BUF & buf, const CFeBigInt384 & a);
    static INT32 Compare(const CFeBigInt384 & a, const CFeBigInt384 & b);
    static INT32 GreaterEqual(const FOLD_BUF & a, const CFeBigInt384 & b);
    VOID Init();

    BASE_TYPE m_Limbs[BI384_LIMBS];  // fixed precision version
};

#endif // _FEBIGINT384_H_

