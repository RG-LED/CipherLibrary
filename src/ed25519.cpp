/* ========================================================================== */
/**
 * @file    ed25519.cpp
 * @brief   Ed25519 signature class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "ed25519.h"
#include "fe25519.h"
#include "sha512.h"
#include "secure.h"

struct Point25519
{
    CFe25519 x;
    CFe25519 y;
    CFe25519 z;
    CFe25519 t;
};

#define M           ((const Point25519 *)_M)
#define Identity    (*(const Point25519 *)&_M[0])
#define B           (*(const Point25519 *)&_M[1])

static const struct {
    CFeBigInt256::BASE_TYPE x[BI256_LIMBS];
    CFeBigInt256::BASE_TYPE y[BI256_LIMBS];
    CFeBigInt256::BASE_TYPE z[BI256_LIMBS];
    CFeBigInt256::BASE_TYPE t[BI256_LIMBS];
} _M[16] = {
    {   // 0
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
        { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
        { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, }
    },
    {   // 1
        { 0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760, 0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3, },
        { 0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, },
        { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, },
        { 0xa5b7dda3, 0x6dde8ab3, 0x775152f5, 0x20f09f80, 0x64abe37d, 0x66ea4e8e, 0xd78b7665, 0x67875f0f, }
    },
    {   // 2
        { 0x9f3fd67e, 0x1515e6cf, 0x163a7692, 0xde44f888, 0x213c1bd9, 0x5776d1e1, 0x960f6ad4, 0x3b6f8891, },
        { 0x874a007e, 0xb6d34c9a, 0x5107378d, 0xd6e15667, 0x14dab827, 0x5921f40f, 0x4cdb3092, 0x336d9ece, },
        { 0xf61c8608, 0x722d5b0b, 0x31b598ba, 0x50b27bff, 0x12f675b4, 0xfd9cb817, 0x52a20ea2, 0x59e4ea1a, },
        { 0x92cad989, 0xc532c7e3, 0x483d139b, 0x72749500, 0xdd5e07c1, 0xfc6ea6fe, 0x2d298daa, 0x1f6e08da, }
    },
    {   // 3
        { 0xc90df8e0, 0x594156cf, 0xb6af56b3, 0xdb062ccc, 0x1d35e449, 0xf8f205b0, 0xbe5fea71, 0x7c79bd81, },
        { 0x50735ca7, 0xd374c07f, 0x1653a9c9, 0x586d1bf2, 0xe0361d1a, 0x60cdc34f, 0xeba89914, 0x1eebd8c6, },
        { 0xfba69efe, 0xf9bc59d9, 0x9d523275, 0x8cf3c044, 0xa2402c95, 0x94e0c159, 0x83ace42b, 0x0101f450, },
        { 0x8aa004bb, 0x270156e4, 0xc0865f3d, 0x1ffa6f28, 0x949fa15b, 0xbf0d879f, 0x665df81d, 0x1217d7af, }
    },
    {   // 4
        { 0xde8526bf, 0x190363fc, 0xb45152fd, 0x026efc0e, 0x19a8bcb2, 0x992dcb58, 0x8ff7f1dd, 0x3349374b, },
        { 0x0a55f002, 0x08877c9e, 0x242c2966, 0x4f429b8d, 0xebae9743, 0x44727563, 0x155e7f79, 0x7b444d3f, },
        { 0xdc80e4cd, 0xc8f193b1, 0xc0ae6252, 0x2484a2d4, 0x5363bf11, 0x2a54b8b7, 0xe83c105d, 0x045be850, },
        { 0x28269de7, 0x1589fd8f, 0x3832aaed, 0x47cd629a, 0x5dd5e6a0, 0xeeba22a9, 0xd006395d, 0x59a06515, }
    },
    {   // 5
        { 0xe2986bd1, 0x091674db, 0x44e5cb41, 0xea1ef5b5, 0x94ab9b48, 0x98dee11e, 0xda2f30b0, 0x2ab2a5b6, },
        { 0x7c6e9b73, 0xd1a5c358, 0x0b33a957, 0x06f9d269, 0xf81dc498, 0xbe632753, 0x20ccd8f4, 0x69bae0f2, },
        { 0xada5c85d, 0x1d106417, 0x824e2b8b, 0xf9ca4e45, 0x882552b1, 0x73516c8e, 0x033fb147, 0x5699f014, },
        { 0xcd7b5be4, 0x72e1a7ce, 0xe898eaa0, 0x8576d38f, 0x2522f3f8, 0x70dff65e, 0x9aec9e66, 0x5102c2e9, }
    },
    {   // 6
        { 0x3589c7fb, 0x4c7fad5c, 0x2e202b31, 0x9d12c35e, 0xedcc1707, 0x891f67e5, 0x94d860d6, 0x1bdf6170, },
        { 0x04cf5337, 0x6216255d, 0x00ae18f8, 0x5e31820c, 0xf0784ddb, 0x9104272a, 0x39c5189c, 0x29013ddf, },
        { 0x806a5d9d, 0x860d5220, 0xbc58c0eb, 0xd377c309, 0x1dddf6c3, 0x453e3b54, 0xfa7d2efb, 0x4e9738d2, },
        { 0xca97e1db, 0xabdfd6b4, 0xf1ac589a, 0x3e9631fb, 0xc6027537, 0xccc05767, 0x9379ab67, 0x2a53f297, }
    },
    {   // 7
        { 0xc1ac2631, 0x0c8e15be, 0x9cebd618, 0x9661844a, 0xee93875b, 0xf1adee87, 0x2e2895c6, 0x1d378124, },
        { 0x6d655b61, 0x1fd1a762, 0xb7ca283d, 0xa76f353c, 0x05c21e8e, 0x9190c7d5, 0xf5ceb881, 0x536fd5af, },
        { 0x01d1a6a4, 0x11d4c368, 0x71f70d02, 0x317776f3, 0xd2e5a1df, 0x098aa999, 0x71acd7dc, 0x4ef4533a, },
        { 0x321a6f9c, 0xd7e9e56a, 0x3cc3ed09, 0xe00d0f61, 0xbc2d3ab9, 0xbe4e6555, 0x998b2376, 0x66b8aa0d, }
    },
    {   // 8
        { 0x824cd1d9, 0x1add7970, 0xfa3233c8, 0x51104cfa, 0xc55b6cc5, 0xd93b0000, 0x7f38d967, 0x592a134f, },
        { 0x6d78fafc, 0xbc44ee68, 0x9c23ad74, 0xe5ac62f9, 0x2b3d8c4d, 0x5469c3ea, 0xafb4e5d4, 0x1d8fdfa3, },
        { 0xb78555f5, 0x2f4729e8, 0x0a47cb5f, 0x82ffd12d, 0x203de1e0, 0xb3101315, 0xcba0db22, 0x70e6708d, },
        { 0xf0a2a9ed, 0xbd79f7cb, 0x151169a2, 0x579f84de, 0x9801fe0f, 0x0f1d3f5b, 0xe8207fbf, 0x6850e0db, }
    },
    {   // 9
        { 0x17869f29, 0x577615e8, 0xe7b8a0a0, 0x919b611c, 0x2a851888, 0xa34c7b7a, 0x57aaff06, 0x7f41cdc8, },
        { 0x78f88310, 0x57486e48, 0x13db90fa, 0x53ca5318, 0xc2303273, 0xf5319ae0, 0x8cca520a, 0x77458428, },
        { 0x4dd2ef61, 0x5322fb21, 0xa6902d57, 0x1ebca9c9, 0x7d45d0be, 0xa9efb6ee, 0x1052b3bd, 0x34fa437f, },
        { 0x1e02ebf7, 0x21deb1be, 0xb2bb07e8, 0xe1e09905, 0x7652cda8, 0x4c97747f, 0xf813d3ae, 0x3db50ba8, }
    },
    {   // 10
        { 0x5eebea57, 0x5fe80e94, 0x30fa98aa, 0x57a8d311, 0x7f81775b, 0x6a2eb04d, 0xfc9da38b, 0x7ca8c99d, },
        { 0x31d260d3, 0x1c060fe8, 0xeb5f1ae8, 0x35b7c2f0, 0x84ba9d69, 0xfd0244ac, 0xe41e38a3, 0x015c96f0, },
        { 0x7c761dab, 0x72dde80c, 0x78bbed73, 0x237aaf70, 0xdbbd2e76, 0xef8d2ba6, 0xe0f41873, 0x6612ceea, },
        { 0x288b3d66, 0x74c60221, 0x06bfce47, 0x0a70c008, 0xca68af1e, 0xfd23768a, 0x937b9073, 0x1ab3f536, }
    },
    {   // 11
        { 0x35fc6914, 0xfa7a9b36, 0x7b0464f6, 0xa7854693, 0x34f95b54, 0xa9d60294, 0xba964842, 0x3a08c55d, },
        { 0xab8b3bad, 0x0b444dff, 0x6d14e959, 0x9660ccd1, 0xf4fe2a38, 0x7a17bd0c, 0x45da2546, 0x54577a6f, },
        { 0xbcd30d0a, 0x835b5919, 0x2661388c, 0x8c014ca9, 0x846f44fb, 0x30135451, 0x6907002a, 0x24dc1434, },
        { 0x3b408934, 0x5bb2ca5a, 0x17182f4c, 0xa3b9cc87, 0x0c26c417, 0x91120e9d, 0xc246f261, 0x531ba123, }
    },
    {   // 12
        { 0x894eefe8, 0x9a2bda9f, 0x41bbb397, 0xb5b319d8, 0x7c310fea, 0xb2117f9d, 0xdcfc9df7, 0x4cb58f88, },
        { 0x7df66147, 0x81627756, 0x753aa21b, 0x67413858, 0x690c067f, 0x50dcb3df, 0x46ad9bbe, 0x7843d5e4, },
        { 0x82c10e88, 0x5c459a75, 0xce492652, 0x1bcea0de, 0xf5922b55, 0xe9eff01a, 0x5d0bfc57, 0x0dfc907e, },
        { 0x3800b442, 0x7fd20d02, 0x20b77ebe, 0xdf84858a, 0x6f74a591, 0xa2be2dee, 0xa99ad196, 0x1ac0064b, }
    },
    {   // 13
        { 0xc6469094, 0x8480149c, 0xf47d8c4b, 0x8b276ed0, 0x4652cbf1, 0x2bb14287, 0x7c947007, 0x0622e879, },
        { 0xa259c979, 0x87568ca0, 0x350e450b, 0xc09631ae, 0xaf4d5ca4, 0x3ff15a11, 0xc1494769, 0x11a559bb, },
        { 0x956d28d4, 0x4aa059a3, 0x576155d4, 0x93e53d44, 0xb23afb7c, 0x58dd9d96, 0x6049b5e2, 0x59a225da, },
        { 0xbc6dfff6, 0x9abc28e6, 0x287348a5, 0x0f29d66d, 0x40dfe908, 0x5f6d5d4e, 0x4974c81c, 0x2e013bdb, }
    },
    {   // 14
        { 0xd4065f0f, 0x0b2eadb3, 0xb8f2abab, 0xbd1208c5, 0x42f55f3c, 0x419325f6, 0x6969277a, 0x627471a9, },
        { 0xa5c35e7d, 0x88977ac0, 0x51d79fcf, 0x655e8553, 0x397dea5e, 0xaf555f28, 0x79989c0c, 0x1c5b41b2, },
        { 0xc42fec91, 0xa70e58dc, 0x7c248f0f, 0x8082122f, 0xa81ad15a, 0x09770889, 0xd7ae22e6, 0x309488be, },
        { 0xe87d52f5, 0x494d0576, 0x21261257, 0xaa9aa708, 0x531285b5, 0x2c5e4ce5, 0x7d464347, 0x3e5a47e8, }
    },
    {   // 15
        { 0x671ae865, 0x4f2e8748, 0x2b953524, 0xa9f9880f, 0x5b749832, 0x29b2a59d, 0x8b2d7a2c, 0x3aea74f0, },
        { 0x5da74113, 0xca116373, 0x989aa4a2, 0x733cda36, 0xf27b8f99, 0x9d6896fb, 0xdc49f496, 0x7f9d6c35, },
        { 0xc9d90a24, 0x076d826c, 0x5be8c947, 0x9a679046, 0xa7300bd4, 0xca3509a0, 0x7f39f912, 0x533552e0, },
        { 0xfd6ea971, 0xfbcf5b37, 0x151d8146, 0x58e13da2, 0xdc3e2021, 0x72f06465, 0xcddb7d4f, 0x32a3f803, }
    }
};

static VOID point_add(Point25519 & r, const Point25519 & P, const Point25519 & Q)
{
    CFe25519 a;
    CFe25519 b;
    CFe25519 c;
    CFe25519 d;

    CFe25519::Sub(a, P.y, P.x); CFe25519::Sub(b, Q.y, Q.x); CFe25519::Mul(a, a, b);
    CFe25519::Add(b, P.y, P.x); CFe25519::Add(c, Q.y, Q.x); CFe25519::Mul(b, b, c);
    CFe25519::Mul(c, P.t, Q.t); CFe25519::Mul(c, c, CFe25519::d2);
    CFe25519::Mul(d, P.z, Q.z); CFe25519::Mul(d, d, CFe25519::Two);

    CFe25519 e;
    CFe25519 fv;
    CFe25519 g;
    CFe25519 h;

    CFe25519::Sub(e, b, a);
    CFe25519::Sub(fv, d, c);
    CFe25519::Add(g, d, c);
    CFe25519::Add(h, b, a);

    CFe25519::Mul(r.x, e, fv);
    CFe25519::Mul(r.y, g, h);
    CFe25519::Mul(r.z, fv, g);
    CFe25519::Mul(r.t, e, h);
}

static VOID point_double(Point25519 & r, const Point25519 & P)
{
    CFe25519 a;
    CFe25519 b;
    CFe25519 c;
    CFe25519 d;
    CFe25519 e;
    CFe25519 g;
    CFe25519 fv;
    CFe25519 h;

    CFe25519::Mul(a, P.x, P.x);
    CFe25519::Mul(b, P.y, P.y);
    CFe25519::Mul(c, P.z, P.z); CFe25519::Mul(c, c, CFe25519::Two);
    CFe25519::Neg(d, a);
    CFe25519::Add(e, P.x, P.y); CFe25519::Add(g, P.x, P.y); CFe25519::Mul(e, e, g); CFe25519::Sub(e, e, a); CFe25519::Sub(e, e, b);
    CFe25519::Add(g, d, b);
    CFe25519::Sub(fv, g, c);
    CFe25519::Sub(h, d, b);

    CFe25519::Mul(r.x, e, fv);
    CFe25519::Mul(r.y, g, h);
    CFe25519::Mul(r.z, fv, g);
    CFe25519::Mul(r.t, e, h);
}

static VOID conditional_move(Point25519 & p, const Point25519 & q, INT32 bit) // constant-time
{
    // 'bit' must be 0 or 1
    UINT32 mask = -bit; // bit=1 -> 0xFFFFFFFF, bit=0 -> 0x00000000
    p.x.cmux(q.x, mask);
    p.y.cmux(q.y, mask);
    p.z.cmux(q.z, mask);
    p.t.cmux(q.t, mask);
}

static VOID scalar_mult(Point25519 & r, const CFe25519 & k, const Point25519 & p)
{
    Point25519 q = p;
    Point25519 addend;

    r = Identity;

    for ( INT32 i = 0; i < 256; i++ )
    {
        INT32 bit = k.GetBit(i);
        addend = Identity;
        conditional_move(addend, q, bit);
        point_add(r, r, addend);
        point_double(q, q);
    }

#if 0
// what above code does is as follows:
    CFe25519 n = k;
    while (n.IsPlus())
    {
        if (n.IsOdd())
        {
            point_add(r, r, q);
        }
        point_double(q, q);
        n.ShiftRight();
    }
#endif
}

static VOID scalar_mult_base(UINT8 out[32], const UINT8 scalar[32])
{
    // 1. convert scalar to FE25519
    CFe25519 a(scalar);

    // 2. calculate a * B
    Point25519 r;
    scalar_mult(r, a, B);

    // 3. encode y coordinate and sign (Ed25519 format)
    //    public key consists of y coordinate + sign of x
    CFe25519 iz;
    CFe25519 x;
    CFe25519 y;

    CFe25519::Inv(iz, r.z);
    CFe25519::Mul(x, r.x, iz);
    CFe25519::Mul(y, r.y, iz);
    y.toBytesLE(out);

    out[31] &= 0x7f;
    if (x.IsOdd())
    {
        out[31] |= 0x80;
    }
}

// s: 32-byte LE scalar, out: R = s*B
static VOID scalar_mult_base(Point25519 & p, const UINT8 s_le[32])
{
    // spit scalar into 4-bit nibbles from low to high
    UINT8 nib[64] = { 0 };
    for ( INT32 i = 0; i < 32; i++ )
    {
        nib[i * 2]     =  s_le[i] & 0x0F;
        nib[i * 2 + 1] = (s_le[i] >> 4) & 0x0F;
    }

    // scan nibbles from upper one
    p = Identity;
    for ( INT32 i = 63; i >= 0; i-- )
    {
        // double 4 times
        for ( INT32 k = 0; k < 4; k++ )
        {
            point_double(p, p);
        }
        // if nibble is 0, add origin
        INT32 j = (nib[i] != 0) ? nib[i] : 0;
        point_add(p, p, M[j]);
    }

    secure_zero(nib, sizeof(nib));
}

static BOOL point_equal(const Point25519 & p, const Point25519 & q)
{
    // X1*Z2 == X2*Z1 && Y1*Z2 == Y2*Z1
    CFe25519 a;
    CFe25519 b;
    CFe25519 c;
    CFe25519 d;

    CFe25519::Mul(a, p.x, q.z);
    CFe25519::Mul(b, q.x, p.z);
    CFe25519::Mul(c, p.y, q.z);
    CFe25519::Mul(d, q.y, p.z);

    return (a == b) && (c == d);
}

static BOOL decode_point(Point25519 & out, const UINT8 enc[32])
{
    // extract y and x_sign
    UINT8 yb[32];
    memcpy(yb, enc, 32);
    UINT8 x_sign = (yb[31] >> 7) & 1;
    yb[31] &= 0x7F; // clear MSB of y

    CFe25519 y;
    y.fromBytesLE(yb);
    if ( y >= CFe25519::P )
    {
        return FALSE; // refuse unnormalized (y>=p)
    }

    // u = y^2 - 1, v = d*y^2 + 1
    CFe25519 y2;
    CFe25519 u;
    CFe25519 v;

    CFe25519::Mul(y2, y, y);
    CFe25519::Sub(u, y2, CFe25519::One);
    CFe25519::Mul(v, y2, CFe25519::d); CFe25519::Add(v, v, CFe25519::One);

    // x = (u*v^3) * (u*v^7)^((p-5)/8)
    CFe25519 v3;
    CFe25519 uv7;

    CFe25519::Mul(v3, v, v); CFe25519::Mul(v3, v3, v);
    CFe25519::Mul(uv7, u, v3); CFe25519::Mul(uv7, uv7, v3); CFe25519::Mul(uv7, uv7, v);

    // exp = (p-5)/8
    CFe25519 x;
    CFe25519::Pow(x, uv7, CFe25519::P58); CFe25519::Mul(x, x, u); CFe25519::Mul(x, x, v3);

    // check: v*x^2 == u ?
    CFe25519 vx2;
    CFe25519::Mul(vx2, v, x); CFe25519::Mul(vx2, vx2, x);

    if ( vx2 != u )
    {
        CFe25519::Neg(u, u);
        if ( vx2 != u )
        {
            return FALSE; // no square root means invalid
        }
        // alternative square root: x <- x * sqrt(-1)
        CFe25519::Mul(x, x, CFe25519::SqrtM1);
    }

    // check sign: if LSB(x) is not x_sign then x <- p - x
    UINT8 x_odd = x.IsOdd() ? 1 : 0;
    if ( (x_odd ^ x_sign) != 0 )
    {
        CFe25519::Neg(x, x);
    }
    // x==0 and x_sign==1 means invalid
    if ( x.IsZero() && x_sign )
    {
        return FALSE;
    }

    // output
    Point25519 Q;
    Q.x = x;
    Q.y = y;
    Q.z = CFe25519::One;
    CFe25519::Mul(Q.t, x, y);

    Point25519 Q8;
    point_double(Q8, Q);
    point_double(Q8, Q8);
    point_double(Q8, Q8);

    if ( point_equal(Q8, Identity) )
    {
        return FALSE;
    }

    out = Q;

    return TRUE;
}

VOID ed25519_keygen(const UINT8 seed[32], UINT8 pk[32], UINT8 hash[64])
{
    CSha512 sha;
    UINT8 h[64];

    sha.Update(seed, 32);
    sha.Finish(h);
    memcpy(hash, h, 64);
    CScalarL25519::Clamping(h);
    scalar_mult_base(pk, h);

    secure_zero(h, sizeof(h));
}

// seed    : private key 32 bytes
// pk      : public key 32 bytes
// msg     : message
// msg_len : message length
// sig     : signature 64 bytes (R || S)
VOID ed25519_sign(const UINT8 seed[32], const UINT8 pk[32], const UINT8 * msg, UINT32 msg_len, UINT8 sig[64])
{
    CSha512 sha;

    // 1. hash = SHA512(seed)
    UINT8 hash[64];
    sha.Initialize();
    sha.Update(seed, 32);
    sha.Finish(hash);

    // 2. handle 'a' as scalar of mod L
    CScalarL25519 a;
    a.fromBytesLE(hash);
    a.Clamping();

    // 3. r = SHA512(prefix || M) mod L
    UINT8 r_hash[64];
    sha.Initialize();
    sha.Update(&hash[32], 32);
    sha.Update(msg, msg_len);
    sha.Finish(r_hash);

    CScalarL25519 r;
    r.fromBytesLE64(r_hash);  // reduce 64 bytes -> mod L

    // 4. calculate: R = r * B, and encode
    UINT8 r_bytes[32];
    r.toBytesLE(r_bytes);               // make value of mod L into LE 32 bytes
    UINT8 * R_enc = &sig[0];
    scalar_mult_base(R_enc, r_bytes);

    // 5. k = SHA512(R || A || M) mod L
    UINT8 k_hash[64];
    sha.Initialize();
    sha.Update(R_enc, 32);
    sha.Update(pk, 32);
    sha.Update(msg, msg_len);
    sha.Finish(k_hash);

    CScalarL25519 k;
    k.fromBytesLE64(k_hash);

    // 6. S = (r + k * a) mod L
    CScalarL25519 S;
    CScalarL25519::Mul(S, k, a);
    CScalarL25519::Add(S, S, r);

    // 7. output signature: sig = R || S
    UINT8 * S_bytes = &sig[32];
    S.toBytesLE(S_bytes);

    secure_zero(hash, sizeof(hash));
    secure_zero(r_hash, sizeof(r_hash));
    secure_zero(r_bytes, sizeof(r_bytes));
    secure_zero(k_hash, sizeof(k_hash));
}

// pub     : public key 32 bytes
// msg     : message
// msg_len : message length
// sig     : signature 64bytes (R || S)
BOOL ed25519_verify(const UINT8 pub[32], const UINT8 * msg, UINT32 msg_len, const UINT8 sig[64])
{
    const UINT8 * R_bytes = &sig[0];
    const UINT8 * S_bytes = &sig[32];

    // 1) decode and check integrity
    Point25519 A, R;
    CScalarL25519 S;

    if (!decode_point(A, pub)) return FALSE;     // on curve, encode integrity, and so on
    if (!decode_point(R, R_bytes)) return FALSE;
    S.fromBytesLE(S_bytes); // little-endian -> integer
    if (S >= CScalarL25519::L) return FALSE;     // S must be less than L

    // 2) hash (R || A || M)
    UINT8 hbuf[64];
    CSha512 sha;
    sha.Initialize();
    sha.Update(R_bytes, 32);
    sha.Update(pub, 32);
    sha.Update(msg, msg_len);
    sha.Finish(hbuf);

    CScalarL25519 h;
    h.fromBytesLE64(hbuf);  // reduce it within L by Ed25519 rule

    // 3) verify: S*B == R + h*A
    Point25519 left;
    Point25519 right;
    Point25519 p;
    scalar_mult_base(left, S_bytes);
    scalar_mult(p, h, A);
    point_add(right, R, p);

    return point_equal(left, right);
}

