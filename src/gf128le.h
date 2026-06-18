/* ========================================================================== */
/**
 * @file    gf128le.h
 * @brief   finit field class for POLYVAL of AES-GCM-SIV
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_GF128LE_H_)
#define _GF128LE_H_

#include "secure.h"

#define GF128LE_LIMBS 4

struct Gf128LE
{
    typedef UINT32 LIMB_TYPE;
    LIMB_TYPE limbs[GF128LE_LIMBS];  // Big-endian order
};

class CGf128LE : protected Gf128LE
{
public:
    CGf128LE() { Zero(); }
    VOID Zero() { secure_zero(limbs, sizeof(limbs)); }
    VOID Shr1();
    VOID Xor(const CGf128LE & a);
    VOID Mul(const CGf128LE & a);
    static VOID SetH(const CGf128LE & h);
    VOID MulH();
    VOID LoadLE(const UINT8 b[]);
    VOID StoreLE(UINT8 b[]) const;

    CGf128LE(const Gf128LE & v);
protected:
    static CGf128LE R;
    static CGf128LE hTable[16];
};

#endif // _GF128LE_H_

