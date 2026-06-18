/* ========================================================================== */
/**
 * @file    gf128be.h
 * @brief   finit field class for GHASH of AES-GCM
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_GF128BE_H_)
#define _GF128BE_H_

#include "secure.h"

#define GF128BE_LIMBS 4

struct Gf128BE
{
    typedef UINT32 LIMB_TYPE;
    LIMB_TYPE limbs[GF128BE_LIMBS];  // Big-endian order
};

class CGf128BE : protected Gf128BE
{
public:
    CGf128BE() { Zero(); }
    VOID Zero() { secure_zero(limbs, sizeof(limbs)); }
    VOID Shr1();
    VOID Xor(const CGf128BE & a);
    VOID Mul(const CGf128BE & a);
    static VOID SetH(const CGf128BE & h);
    VOID MulH();
    VOID LoadBE(const UINT8 b[]);
    VOID StoreBE(UINT8 b[]) const;

protected:
    CGf128BE(const Gf128BE & v);
    static CGf128BE R;
    static CGf128BE hTable[16];
};

#endif // _GF128BE_H_

