/* ========================================================================== */
/**
 * @file    FeBigInt2048.h
 * @brief   2048-bit BigInt class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FEBIGINT2048_H_)
#define _FEBIGINT2048_H_

#include "BasicDefs.h"

class CFeBigInt2048
{
public:
#define BI2048_BASE_SIZE    4   /* 4 = dword */

    typedef UINT32  BASE_TYPE;
    typedef INT32   SBASE_TYPE;
    typedef UINT64  CALC_TYPE;
    typedef INT64   SCALC_TYPE;
#define BI2048_BASE_SHIFT   32
#define BI2048_CALC_SHIFT   64

#define BI2048_BYTES        256 // bytes for big number
#define BI2048_LIMBS        (BI2048_BYTES / BI2048_BASE_SIZE) // number of limbs
#define BI2048_FOLD_SIZE    (BI2048_LIMBS * 2 + 1) // must satisfy BI2048_FOLD_SIZE >= BI2048_LIMBS * 2

#if BI2048_LIMBS * 2 > BI2048_FOLD_SIZE
#error "Invalid size order definition"
#endif

#define BI2048_SHIFT_RIGHT_LIMB(n)  ((n) >>= BI2048_BASE_SHIFT)
#define BI2048_SHIFT_RIGHT_CARRY(n) ((n) = ((n) >> (BI2048_CALC_SHIFT - 1)) & 1)

public:
    CFeBigInt2048();
    CFeBigInt2048(UINT32 n);
    CFeBigInt2048(const UINT8 s[BI2048_BYTES]);
    CFeBigInt2048(const CFeBigInt2048 & n) { copy(n); }
    ~CFeBigInt2048();

    static BASE_TYPE Add(CFeBigInt2048 & out, const CFeBigInt2048 & n, const CFeBigInt2048 & m);
    static BASE_TYPE Sub(CFeBigInt2048 & out, const CFeBigInt2048 & n, const CFeBigInt2048 & m);
    static VOID Mod(CFeBigInt2048 & out, const CFeBigInt2048 & n, const CFeBigInt2048 & m);
    static VOID Mul(CFeBigInt2048 & out, const CFeBigInt2048 & n, const CFeBigInt2048 & m) { FOLD_BUF buf; Mul(buf, n, m); Extract(out, buf);}
    // static VOID Neg(CFeBigInt2048 & out, const CFeBigInt2048 & n);

    UINT32 ModSmall(UINT32 n) const;

    VOID ShiftRight1();

    INT32 GetBit(INT32 bit) const;
    INT32 SearchMSB() const;

    BOOL operator==(const CFeBigInt2048 & rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(const CFeBigInt2048 & rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(const CFeBigInt2048 & rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(const CFeBigInt2048 & rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(const CFeBigInt2048 & rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(const CFeBigInt2048 & rhs) const { return Cmp(rhs) <= 0; }

    BOOL operator==(INT32 rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(INT32 rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(INT32 rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(INT32 rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(INT32 rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(INT32 rhs) const { return Cmp(rhs) <= 0; }

    BOOL IsOdd() const { return (m_Limbs[0] & 1) != 0; }
    BOOL IsEven() const { return (m_Limbs[0] & 1) == 0; }

    BOOL IsMinus() const { return (m_Limbs[BI2048_LIMBS - 1] & ((BASE_TYPE)1 << (BI2048_BASE_SHIFT - 1))) != 0; }
    // BOOL IsPlus() const;
    BOOL IsZero() const;

    VOID fromBytesLE(const UINT8 s[], SIZE_T size = BI2048_BYTES);
    VOID toBytesLE(UINT8 out[], SIZE_T size = BI2048_BYTES) const;

    VOID fromBytesBE(const UINT8 s[], SIZE_T size = BI2048_BYTES);
    VOID toBytesBE(UINT8 out[], SIZE_T size = BI2048_BYTES) const;

    VOID cmux(const CFeBigInt2048 & other, BASE_TYPE mask);
    VOID cswap(CFeBigInt2048 &other, BASE_TYPE mask);
    VOID copy(const CFeBigInt2048 & n);

    static CFeBigInt2048 Zero;      // 0
    static CFeBigInt2048 One;       // 1
    static CFeBigInt2048 Two;       // 2
    static CFeBigInt2048 Three;     // 3

#if 0
    VOID ToHexText(CHAR8 * buf) const;
    VOID ToHex(CHAR8 * buf) const;
    VOID ToText(CHAR8 * buf) const;
    VOID FromText(const CHAR8 * buf);
#endif

protected:
    typedef BASE_TYPE FOLD_BUF[BI2048_FOLD_SIZE];

    INT32 Cmp(const CFeBigInt2048 & a) const { return Compare(*this, a); }
    static VOID Expand(FOLD_BUF & buf, const CFeBigInt2048 & n);
    static VOID Extract(CFeBigInt2048 & out, const FOLD_BUF & buf);
    static VOID Sub(FOLD_BUF & out, const CFeBigInt2048 & a);
    static VOID Mul(FOLD_BUF & buf, const CFeBigInt2048 & a, const CFeBigInt2048 & b);
    static VOID Mul(FOLD_BUF & buf, const FOLD_BUF & a, const CFeBigInt2048 & b);
    static VOID Mod(FOLD_BUF & buf, const CFeBigInt2048 & a);
    static INT32 Compare(const CFeBigInt2048 & a, const CFeBigInt2048 & b);
    static INT32 GreaterEqual(const FOLD_BUF & a, const CFeBigInt2048 & b);
    VOID Init();

    CFeBigInt2048 AddAbs(CALC_TYPE num) const;
    CFeBigInt2048 MulAbs(CALC_TYPE num) const;
    CFeBigInt2048 DivModAbs(const CFeBigInt2048 & rhs, CFeBigInt2048 * remain = NULL) const;

    BASE_TYPE m_Limbs[BI2048_LIMBS];  // fixed precision version
};

#endif // _FEBIGINT2048_H_
