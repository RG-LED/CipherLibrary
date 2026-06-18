/* ========================================================================== */
/**
 * @file    FeBigInt256.h
 * @brief   256-bit BigInt class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FEBIGINT256_H_)
#define _FEBIGINT256_H_

#include "BasicDefs.h"

class CFeBigInt256
{
public:
#define BI256_BASE_SIZE 4   /* 4 = dword */

    typedef UINT32  BASE_TYPE;
    typedef INT32   SBASE_TYPE;
    typedef UINT64  CALC_TYPE;
    typedef INT64   SCALC_TYPE;
#define BI256_BASE_SHIFT    32
#define BI256_CALC_SHIFT    64

#define BI256_BYTES     32
#define BI256_LIMBS     (BI256_BYTES / BI256_BASE_SIZE)   // number of limbs
#define BI256_FOLD_SIZE (BI256_LIMBS * 2 + 1)  // must satisfy BI256_FOLD_SIZE >= BI256_LIMBS * 2

#if BI256_LIMBS * 2 > BI256_FOLD_SIZE
#error "Invalid size order definition"
#endif

#define BI256_SHIFT_RIGHT_LIMB(n)   ((n) >>= BI256_BASE_SHIFT)
#define BI256_SHIFT_RIGHT_CARRY(c)  ((c) = ((c) >> (BI256_CALC_SHIFT - 1)) & 1)

public:
    CFeBigInt256();
    CFeBigInt256(UINT32 n);
    CFeBigInt256(const UINT8 s[32]);
    CFeBigInt256(const CFeBigInt256 & n) { copy(n); }
    ~CFeBigInt256();

    static VOID Add(CFeBigInt256 & out, const CFeBigInt256 & n, const CFeBigInt256 & m);
    static VOID Sub(CFeBigInt256 & out, const CFeBigInt256 & n, const CFeBigInt256 & m);
    static VOID Mod(CFeBigInt256 & out, const CFeBigInt256 & n, const CFeBigInt256 & m);
    // static VOID Neg(CFeBigInt256 & out, const CFeBigInt256 & n);

    INT32 GetBit(INT32 bit) const;

    BOOL operator==(const CFeBigInt256 & rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(const CFeBigInt256 & rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(const CFeBigInt256 & rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(const CFeBigInt256 & rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(const CFeBigInt256 & rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(const CFeBigInt256 & rhs) const { return Cmp(rhs) <= 0; }

    BOOL operator==(INT32 rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(INT32 rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(INT32 rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(INT32 rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(INT32 rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(INT32 rhs) const { return Cmp(rhs) <= 0; }

    BOOL IsOdd() const { return (m_Limbs[0] & 1) != 0; }
    BOOL IsEven() const { return (m_Limbs[0] & 1) == 0; }

    BOOL IsMinus() const { return (m_Limbs[BI256_LIMBS - 1] & ((BASE_TYPE)1 << (BI256_BASE_SHIFT - 1))) != 0; }
    // BOOL IsPlus() const;
    BOOL IsZero() const;

    VOID fromBytesLE(const UINT8 * s, SIZE_T size = 32);
    VOID toBytesLE(UINT8 * out, SIZE_T size = 32) const;

    VOID fromBytesBE(const UINT8 * s, SIZE_T size = 32);
    VOID toBytesBE(UINT8 * out, SIZE_T size = 32) const;

    VOID cmux(const CFeBigInt256 & other, BASE_TYPE mask);
    VOID cswap(CFeBigInt256 & other, BASE_TYPE mask);
    VOID copy(const CFeBigInt256 & n);


    static CFeBigInt256 Zero;      // 0
    static CFeBigInt256 One;       // 1
    static CFeBigInt256 Two;       // 2

#if 0
    VOID ToHexText(CHAR8 * buf) const;
    VOID ToHex(CHAR8 * buf) const;
    VOID ToText(CHAR8 * buf) const;
    VOID FromText(const CHAR8 * buf);
#endif

protected:
    typedef BASE_TYPE FOLD_BUF[BI256_FOLD_SIZE];

    INT32 Cmp(const CFeBigInt256 & a) const { return Compare(*this, a); }
    static VOID Expand(FOLD_BUF & buf, const CFeBigInt256 & n);
    static VOID Extract(CFeBigInt256 & out, const FOLD_BUF & buf);
    static VOID Sub(FOLD_BUF & out, const CFeBigInt256 & a);
    static VOID Mul(FOLD_BUF & buf, const CFeBigInt256 & a, const CFeBigInt256 & b);
    static VOID Mul(FOLD_BUF & buf, const FOLD_BUF & a, const CFeBigInt256 & b);
    static VOID Mod(FOLD_BUF & buf, const CFeBigInt256 & a);
    static INT32 Compare(const CFeBigInt256 & a, const CFeBigInt256 & b);
    static INT32 GreaterEqual(const FOLD_BUF & a, const CFeBigInt256 & b);
    VOID Init();

    BASE_TYPE m_Limbs[BI256_LIMBS];  // fixed precision version
};

#endif // _FEBIGINT256_H_

