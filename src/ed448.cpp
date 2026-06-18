/* ========================================================================== */
/**
 * @file    ed448.cpp
 * @brief   Ed448 signature class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

// ====== Ed448 Edwards curve ======

#include "ed448.h"
#include "fe448.h"
#include "shake256.h"
#include "secure.h"

// ---------- Edwards point (affine) ----------
struct Point448
{
    CFe448 x;
    CFe448 y;
    CFe448 z;
    CFe448 t;

    VOID cswap(Point448 & other, UINT32 mask);
    VOID cmux(const Point448 & other, UINT32 mask);
};

VOID Point448::cswap(Point448 & other, UINT32 mask)
{
    x.cswap(other.x, mask);
    y.cswap(other.y, mask);
    z.cswap(other.z, mask);
    t.cswap(other.t, mask);
}

VOID Point448::cmux(const Point448 & other, UINT32 mask)
{
    x.cmux(other.x, mask);
    y.cmux(other.y, mask);
    z.cmux(other.z, mask);
    t.cmux(other.t, mask);
}

#define NON_ZERO_MASK(n)    ((UINT32)(((INT32)(n) | -(INT32)(n)) >> 31))
#define IDENTITY    (*(Point448 *)&_IDENTITY)

static const struct {
    CFeBigInt512::BASE_TYPE x[BI512_LIMBS];
    CFeBigInt512::BASE_TYPE y[BI512_LIMBS];
    CFeBigInt512::BASE_TYPE z[BI512_LIMBS];
    CFeBigInt512::BASE_TYPE t[BI512_LIMBS];
} _IDENTITY = {
    { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
    { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
    { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
    { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, }
};

// --- Ed448 Fixed-base Comb Table (ROM: ~342 bytes) ---
// G
static const UINT8 COMB_X_G[57] = {
    0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26, 0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
    0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12, 0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
    0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e, 0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
    0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f, 0x00
};
static const UINT8 COMB_Y_G[57] = {
    0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
    0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a, 0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
    0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
    0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69, 0x00
};

// G224
static const UINT8 COMB_X_G224[57] = {
    0xc7, 0x80, 0x17, 0x99, 0x98, 0xea, 0xa7, 0xb6, 0x76, 0x24, 0xcd, 0xec, 0xe4, 0x04, 0x68, 0x4b,
    0x49, 0x8c, 0xf5, 0xf9, 0x0a, 0xfd, 0x64, 0xee, 0xfd, 0x69, 0xf2, 0xe0, 0x26, 0xbd, 0x21, 0x60,
    0x1f, 0xa6, 0x85, 0x4b, 0x28, 0x5d, 0x5b, 0xc3, 0x65, 0xc2, 0xfd, 0x5a, 0x77, 0xa3, 0x5e, 0x75,
    0x58, 0xc6, 0xf2, 0xec, 0x42, 0x17, 0x7f, 0x61, 0x00
};
static const UINT8 COMB_Y_G224[57] = {
    0x6a, 0x55, 0xec, 0x25, 0x9e, 0x10, 0x50, 0x39, 0x7e, 0xd5, 0xbf, 0x66, 0x53, 0x23, 0x2e, 0x6b,
    0x4b, 0x64, 0x97, 0x3c, 0x7b, 0x9c, 0x7b, 0x2b, 0x2b, 0xe8, 0xf9, 0xf7, 0x09, 0x64, 0xec, 0xb0,
    0x6a, 0x19, 0xb6, 0x9e, 0x0d, 0xa2, 0x60, 0xd1, 0xf1, 0x88, 0x61, 0xf7, 0x86, 0x45, 0x3b, 0xbe,
    0xe3, 0x5d, 0x39, 0x26, 0x6e, 0xc2, 0x83, 0x99, 0x00
};

// GSUM
static const UINT8 COMB_X_GSUM[57] = {
    0x47, 0x49, 0x7f, 0x66, 0xeb, 0xf4, 0xdb, 0xd9, 0x16, 0x87, 0xab, 0xa2, 0x06, 0x22, 0x5a, 0xad,
    0x7c, 0x0e, 0x8b, 0x14, 0x4a, 0x33, 0x31, 0x48, 0xde, 0x2c, 0xf1, 0xfb, 0xf7, 0x58, 0x64, 0xac,
    0xd5, 0x22, 0xe0, 0x9d, 0xe3, 0xb7, 0x61, 0xfe, 0x0a, 0xa6, 0x8c, 0x20, 0xa5, 0x85, 0x45, 0x2f,
    0xc6, 0x53, 0x15, 0x31, 0x33, 0x4c, 0x8a, 0xa0, 0x00
};
static const UINT8 COMB_Y_GSUM[57] = {
    0x56, 0x8e, 0xab, 0xef, 0x88, 0xd2, 0xde, 0xe6, 0x77, 0x72, 0xe5, 0xf4, 0xe6, 0xa4, 0x81, 0x96,
    0x94, 0xfe, 0xc4, 0xa4, 0xa2, 0xb3, 0xfd, 0x21, 0xc7, 0x46, 0x8a, 0x50, 0xe2, 0x4d, 0xb4, 0xef,
    0x49, 0x80, 0xf9, 0x31, 0x0f, 0xfb, 0x42, 0x72, 0xf3, 0x71, 0x63, 0x77, 0x06, 0x39, 0xbb, 0xfb,
    0xd3, 0xaa, 0xfa, 0x83, 0xaa, 0xc4, 0x6e, 0x69, 0x00
};

static VOID feed_dom(CShake256 & shake, const CHAR8 * context)
{
    static const UINT8 dom[8] = { 'S','i','g','E','d','4','4','8'}; // phflag=0
    SIZE_T len;

    shake.Absorb(dom, sizeof(dom));
    const CHAR8 * p = context;
    for ( len = 0; *p != 0; len++ )
    {
        p++;
    }
    if ( len > 0xff )
    {
        len = 0xff;
    }
    UINT8 phflag = 0;
    UINT8 blen = (UINT8)len;
    shake.Absorb(&phflag, sizeof(phflag));
    shake.Absorb(&blen, sizeof(blen));
    shake.Absorb((const UINT8 *)context, len);
}

static VOID load_comb(Point448 & out, INT32 index)
{
    const UINT8 * rx;
    const UINT8 * ry;

    if ( index == 1 )
    {
        rx = COMB_X_G;
        ry = COMB_Y_G;
    }
    else if ( index == 2 )
    {
        rx = COMB_X_G224;
        ry = COMB_Y_G224;
    }
    else
    {
        rx = COMB_X_GSUM;
        ry = COMB_Y_GSUM;
    }

    out.x.fromBytesLE(rx, 57);
    out.y.fromBytesLE(ry, 57);
    out.z = CFe448::One;
    CFe448::Mul(out.t, out.x, out.y);
}

static VOID finalize(Point448 & p)
{
    CFe448 invZ;

    CFe448::Inv(invZ, p.z);
    CFe448::Mul(p.x, p.x, invZ);
    CFe448::Mul(p.y, p.y, invZ);
    p.z = CFe448::One;
    CFe448::Mul(p.t, p.x, p.y);
}

static BOOL is_on_curve(Point448 & p)
{
    CFe448 t;
    CFe448 x2;
    CFe448 y2;
    CFe448 lhs;
    CFe448 rhs;
    CFe448 diff;

    CFe448::Mul(x2, p.x, p.x);
    CFe448::Mul(y2, p.y, p.y);
    CFe448::Add(lhs, x2, y2);
    CFe448::Mul(t, x2, y2);
    CFe448::Mul(t, CFe448::D, t);
    CFe448::Add(rhs, t, CFe448::One);
    return lhs == rhs;
}

static VOID addE(Point448 & out, const Point448 & p1, const Point448 & p2)
{
    CFe448 a;
    CFe448 b;
    CFe448 c;
    CFe448 d;
    CFe448 e;
    CFe448 f;
    CFe448 g;
    CFe448 h;
    CFe448 tmp1;
    CFe448 tmp2;

    // 1. A = X1 * X2
    CFe448::Mul(a, p1.x, p2.x);
    // 2. B = Y1 * Y2
    CFe448::Mul(b, p1.y, p2.y);
    // 3. C = d * T1 * T2 (d = -39081)
    CFe448::Mul(c, p1.t, p2.t);
    CFe448::Mul(c, c, CFe448::D); 
    // 4. D = Z1 * Z2
    CFe448::Mul(d, p1.z, p2.z);

    // 5. E = (X1 + Y1) * (X2 + Y2) - A - B
    CFe448::Add(tmp1, p1.x, p1.y);
    CFe448::Add(tmp2, p2.x, p2.y);
    CFe448::Mul(e, tmp1, tmp2);
    CFe448::Sub(e, e, a);
    CFe448::Sub(e, e, b);

    // 6. F = D - C
    CFe448::Sub(f, d, c);
    // 7. G = D + C
    CFe448::Add(g, d, c);
    // 8. H = B - A (a=1 なので B - A)
    CFe448::Sub(h, b, a);

    // store result
    CFe448::Mul(out.x, e, f); // X3 = E * F
    CFe448::Mul(out.y, g, h); // Y3 = G * H
    CFe448::Mul(out.z, f, g); // Z3 = F * G
    CFe448::Mul(out.t, e, h); // T3 = E * H
}

static VOID dblE(Point448 & out, const Point448 & p)
{
    addE(out, p, p);
}

// scalar multiply (constant-time ladder-ish double-and-add)
static Point448 scalarmult(CScalarL512 & k, Point448 & p)
{
    Point448 R0 = IDENTITY;
    Point448 R1 = p;
    UINT32 prev_mask = 0;

    for( INT32 i = 447; i >= 0; i-- )
    {
        UINT32 mask = (UINT32)-k.GetBit(i);
        UINT32 swap = mask ^ prev_mask; // swap only when bit changes

        // call cswap at each coordinate (x, y, z, t) within Point448
        R0.cswap(R1, swap);

        addE(R1, R0, R1);
        dblE(R0, R0);

        prev_mask = mask;
    }
    // swap at last to adjust
    R0.cswap(R1, prev_mask);

    finalize(R0);
    return R0;
}

static Point448 scalarmult_base_comb(CScalarL512 & k)
{
    Point448 res = IDENTITY; // (0, 1, 1, 0)
    Point448 id = IDENTITY;
    Point448 table_p;

    for( INT32 i = 223; i >= 0; i-- )
    {
        // 1. double
        dblE(res, res);

        // 2. extract window bits (b1: 0-223bit, b2: 224-447bit)
        INT32 b1 = k.GetBit(i);
        INT32 b2 = k.GetBit(i + 224);
        INT32 index = (b2 << 1) | b1; // one of 0, 1, 2, 3

        // 3. add from table if index is not 0
        // read X and Y by load_comb() and set Z=1, T=XY
#if 1
        load_comb(table_p, index); 
        table_p.cmux(id, ~NON_ZERO_MASK(index));
        addE(res, res, table_p);
#else
        if ( index > 0 )
        {
            load_comb(table_p, index); 
            addE(res, res, table_p);
        }
#endif
    }

    finalize(res);
    return res;
}

// ---------- Encoding / Decoding ----------
static INT32 is_negative(CFe448 x)
{
    return x.GetBit(0);
}

static BOOL points_equal(const Point448 & p, const Point448 & q)
{
    return p.x == q.x && p.y == q.y;
}

static VOID encode_point(Point448 & p, UINT8 out57[57])
{
    // y (455 bits) | signbit of x
    UINT8 y_le[57];
    p.y.toBytesLE(y_le, 57);
    y_le[56] &= 0x7f;
    if ( is_negative(p.x) )
    {
        y_le[56] |= 0x80; // set MSB
    }
    memcpy(out57, y_le, 57);

    secure_zero(y_le, sizeof(y_le));
}

static BOOL decode_point(const UINT8 in57[57], Point448 * p)
{
    UINT8 y_le[57];
    memcpy(y_le, in57, sizeof(y_le));
    INT32 sign = (y_le[56] >> 7) & 1;
    y_le[56] &= 0x7F;
    p->y.fromBytesLE(y_le, sizeof(y_le));

    secure_zero(y_le, sizeof(y_le));

    if ( p->y >= CFe448::P )
    {
        return 0;
    }
    // x^2 = (y^2 - 1) / (d*y^2 + 1)

    CFe448 y2;
    CFe448 num;
    CFe448 den;
    CFe448 x2;
    CFe448 x;
    CFe448 t;

    CFe448::Mul(y2, p->y, p->y);
    CFe448::Sub(num, y2, CFe448::One);
    CFe448::Mul(t, CFe448::D, y2);
    CFe448::Sub(den, t, CFe448::One);
    if ( !CFe448::Inv(t, den) )
    {
        return 0;
    }
    CFe448::Mul(x2, num, t);
    if ( !CFe448::Sqrt(x, x2) )
    {
        return 0; // no square root
    }
    // choose sign to match encoding
    if ( is_negative(x) != sign )
    {
        CFe448::Neg(x, x); // x = -x mod P
        if ( is_negative(x) != sign )
        {
            return 0;
        }
    }
    p->x = x;
    p->z = CFe448::One;
    CFe448::Mul(p->t, p->x, p->y);

    return is_on_curve(*p);
}

// ---------- Ed448 keygen / sign / verify ----------
VOID ed448_keygen(const UINT8 seed[57], UINT8 pk_out[57])
{
    UINT8 h[114];

    CShake256 shake;
    shake.Absorb(seed, 57);
    shake.Finish();
    shake.Squeeze(h, 114);

    // clamp to scalar s per RFC 8032 (c=2)
    CScalarL512 s;
    s.fromBytesLEClamp(h);
    Point448 A = scalarmult_base_comb(s);
    encode_point(A, pk_out);

    secure_zero(h, sizeof(h));
}

VOID ed448_sign(const UINT8 seed[57], const UINT8 pk[57], const CHAR8 * context, const UINT8 * m, SIZE_T mlen, UINT8 sig[114])
{
    // 1) H(k)
    UINT8 h[114];

    CShake256 shake;
    shake.Absorb(seed, 57);
    shake.Finish();
    shake.Squeeze(h, 114);

    CScalarL512 s;
    s.fromBytesLEClamp(h);

    // 2) r = H(h[b..2b-1] || M)
    UINT8 rbuf[114];
    shake.Clear();
    feed_dom(shake, context);
    shake.Absorb(&h[57], 57); // use upper 57B as prefix
    shake.Absorb(m, mlen);
    shake.Finish();
    shake.Squeeze(rbuf, 114);
    CScalarL512 r;
    r.fromBytesLE114(rbuf);

    // 3) R = [r]B
    Point448 R = scalarmult_base_comb(r);
    UINT8 Renc[57];
    encode_point(R, Renc);

    // 4) h' = H(ENC(R) || ENC(A) || PH(M))  (Pure: PH(M)=M)
    UINT8 cbuf[114];
    shake.Clear();
    feed_dom(shake, context);
    shake.Absorb(Renc, sizeof(Renc));
    shake.Absorb(pk, 57);
    shake.Absorb(m, mlen);
    shake.Finish();
    shake.Squeeze(cbuf, 114);
    CScalarL512 hprime;
    hprime.fromBytesLE114(cbuf);

    // 5) S = (r + h' * s) mod L
    // TODO scalarL
    CScalarL512 S;
    CScalarL512 t;
    CScalarL512::Mul(t, hprime, s);
    CScalarL512::Add(S, t, r);

    // 6) encode signature
    memcpy(sig, Renc, 57);
    S.toBytesLE(sig + 57, 57);

    secure_zero(h, sizeof(h));
    secure_zero(rbuf, sizeof(rbuf));
    secure_zero(Renc, sizeof(Renc));
    secure_zero(cbuf, sizeof(cbuf));
}

INT32 ed448_verify(const UINT8 pk[57], const CHAR8 * context, const UINT8 * m, SIZE_T mlen, const UINT8 sig[114])
{
    Point448 A;
    if ( !decode_point(pk, &A) )
    {
        return 0;
    }
    Point448 R;
    if ( !decode_point(sig, &R) )
    {
        return 0;
    }
    CScalarL512 S;
    S.fromBytesLE(sig + 57, 57);
    if ( S >= CScalarL512::L )
    {
        return 0;
    }

    // h' = H(ENC(R)||ENC(A)||PH(M))
    UINT8 hbuf[114];
    CShake256 shake;
    feed_dom(shake, context);
    shake.Absorb(sig, 57);
    shake.Absorb(pk, 57);
    shake.Absorb(m, mlen);
    shake.Finish();
    shake.Squeeze(hbuf, sizeof(hbuf));
    CScalarL512 hprime;
    hprime.fromBytesLE114(hbuf);

    // check [2^c S]B == 2^c R + [2^c h']A  (c=2)
    // 1. calculate [S]B
    Point448 SB = scalarmult_base_comb(S);

    // 2. Rh = R + [h']A
    Point448 Rh;
    addE(Rh, R, scalarmult(hprime, A));

    // 3. quadruple both side
    dblE(SB, SB); dblE(SB, SB); // SB = 4 * SB
    dblE(Rh, Rh); dblE(Rh, Rh); // Rh = 4 * Rh

    // 4. Return to affine at last and compare them
    finalize(SB);
    finalize(Rh);

    secure_zero(hbuf, sizeof(hbuf));

    return points_equal(SB, Rh);
}

