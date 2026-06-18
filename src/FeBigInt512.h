/* ========================================================================== */
/**
 * @file    FeBigInt512.h
 * @brief   512-bit BigInt class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FEBIGINT512_H_)
#define _FEBIGINT512_H_

#include "BasicDefs.h"

class CFeBigInt512
{
public:
#define BI512_BASE_SIZE 4   /* 4 = dword */

    typedef UINT32  BASE_TYPE;
    typedef INT32   SBASE_TYPE;
    typedef UINT64  CALC_TYPE;
    typedef INT64   SCALC_TYPE;
#define BI512_BASE_SHIFT    32
#define BI512_CALC_SHIFT    64

#define BI512_BYTES         64                          // bytes for big number
#define BI512_LIMBS         (BI512_BYTES / BI512_BASE_SIZE)   // number of limbs
#define BI512_FOLD_SIZE     (BI512_LIMBS * 2 + 1)  // must satisfy BI512_FOLD_SIZE >= BI512_LIMBS * 2

#if BI512_LIMBS * 2 > BI512_FOLD_SIZE
#error "Invalid size order definition"
#endif

#define BI512_SHIFT_RIGHT_LIMB(n)   ((n) >>= BI512_BASE_SHIFT)
#define BI512_SHIFT_RIGHT_CARRY(n)  ((n) = ((n) >> (BI512_CALC_SHIFT - 1)) & 1)

public:
    CFeBigInt512();
    CFeBigInt512(UINT32 n);
    CFeBigInt512(const UINT8 s[BI512_BYTES]);
    CFeBigInt512(const CFeBigInt512 & n) { copy(n); }
    ~CFeBigInt512();

    static VOID Add(CFeBigInt512 & out, const CFeBigInt512 & n, const CFeBigInt512 & m);
    static VOID Sub(CFeBigInt512 & out, const CFeBigInt512 & n, const CFeBigInt512 & m);
    static VOID Mod(CFeBigInt512 & out, const CFeBigInt512 & n, const CFeBigInt512 & m);
    // static VOID Neg(CFeBigInt512 & out, const CFeBigInt512 & n);

    INT32 GetBit(INT32 bit) const;

    BOOL operator==(const CFeBigInt512 & rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(const CFeBigInt512 & rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(const CFeBigInt512 & rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(const CFeBigInt512 & rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(const CFeBigInt512 & rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(const CFeBigInt512 & rhs) const { return Cmp(rhs) <= 0; }

    BOOL operator==(INT32 rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(INT32 rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(INT32 rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(INT32 rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(INT32 rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(INT32 rhs) const { return Cmp(rhs) <= 0; }

    BOOL IsOdd() const { return (m_Limbs[0] & 1) != 0; }
    BOOL IsEven() const { return (m_Limbs[0] & 1) == 0; }

    BOOL IsMinus() const { return (m_Limbs[BI512_LIMBS - 1] & ((BASE_TYPE)1 << (BI512_BASE_SHIFT - 1))) != 0; }
    // BOOL IsPlus() const;
    BOOL IsZero() const;

    VOID fromBytesLE(const UINT8 s[], SIZE_T size = BI512_BYTES);
    VOID toBytesLE(UINT8 out[], SIZE_T size = BI512_BYTES) const;

    VOID fromBytesBE(const UINT8 s[], SIZE_T size = BI512_BYTES);
    VOID toBytesBE(UINT8 out[], SIZE_T size = BI512_BYTES) const;

    VOID cmux(const CFeBigInt512 & other, BASE_TYPE mask);
    VOID cswap(CFeBigInt512 &other, BASE_TYPE mask);
    VOID copy(const CFeBigInt512 & n);

    static CFeBigInt512 Zero;      // 0
    static CFeBigInt512 One;       // 1
    static CFeBigInt512 Two;       // 2

#if 0
    VOID ToHexText(CHAR8 * buf) const;
    VOID ToHex(CHAR8 * buf) const;
    VOID ToText(CHAR8 * buf) const;
    VOID FromText(const CHAR8 * buf);
#endif

protected:
    typedef BASE_TYPE FOLD_BUF[BI512_FOLD_SIZE];

    INT32 Cmp(const CFeBigInt512 & a) const { return Compare(*this, a); }
    static VOID Expand(FOLD_BUF & buf, const CFeBigInt512 & n);
    static VOID Extract(CFeBigInt512 & out, const FOLD_BUF & buf);
    static VOID Sub(FOLD_BUF & out, const CFeBigInt512 & a);
    static VOID Mul(FOLD_BUF & buf, const CFeBigInt512 & a, const CFeBigInt512 & b);
    static VOID Mul(FOLD_BUF & buf, const FOLD_BUF & a, const CFeBigInt512 & b);
    static VOID Mod(FOLD_BUF & buf, const CFeBigInt512 & a);
    static INT32 Compare(const CFeBigInt512 & a, const CFeBigInt512 & b);
    static INT32 GreaterEqual(const FOLD_BUF & a, const CFeBigInt512 & b);
    VOID Init();

    BASE_TYPE m_Limbs[BI512_LIMBS];  // fixed precision version
};

#endif // _FEBIGINT512_H_
