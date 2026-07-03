/* ========================================================================== */
/**
 * @file    aescbc2s.cpp
 * @brief   AES-CBC cipher class (2-share version)
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aescbc2s.h"
#include "secure.h"

#define ROR8(x)     (((x) >>  8) | ((x) << 24))
#define ROR16(x)    (((x) >> 16) | ((x) << 16))
#define ROR24(x)    (((x) >> 24) | ((x) <<  8))

/************************************************************/
CAesCbc2s::CAesCbc2s()
{
    m_Nk = 4;
    m_Nr = m_Nk + 6;
    ClearVector();
}

CAesCbc2s::~CAesCbc2s()
{
    secure_zero(m_KeyExpansion, sizeof(m_KeyExpansion));
    secure_zero(m_Data, sizeof(m_Data));
    ClearVector();
}

/************************************************************/
BOOL CAesCbc2s::SetKeys(const UINT8 keys[], SIZE_T len)
{
    switch ( len )
    {
    case 16: case 24: case 32:
        m_Nk = (INT32)(len / 4);    // key length 16,24,32(128,192,256 bit)
        m_Nr = m_Nk + 6;            // rounds 10,12,14
        KeyExpansion(keys);
        ClearVector();
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

VOID CAesCbc2s::SetRandomSeed(const UINT8 seed[32], const UINT8 nonce[12])
{
    m_Random.Initialize(seed, nonce);
}

VOID CAesCbc2s::ClearVector(VOID)
{
    secure_zero(m_Vector, sizeof(m_Vector));
}

VOID CAesCbc2s::ShareData(UINT8 x0[], UINT8 x1[], const UINT8 x[])
{
    UINT32 * p0 = (UINT32 *)x0;
    UINT32 * p1 = (UINT32 *)x1;
    const UINT32 * p = (const UINT32 *)x;

    for ( INT32 i = 0; i < NB; i++ )
    {
        p0[i] = random32();
        p1[i] = p[i] ^ p0[i];
    }
}

VOID CAesCbc2s::CombineData(UINT8 x[], const UINT8 x0[], const UINT8 x1[])
{
    UINT32 * p = (UINT32 *)x;
    const UINT32 * p0 = (const UINT32 *)x0;
    const UINT32 * p1 = (const UINT32 *)x1;

    for ( INT32 i = 0; i < NB; i++ )
    {
        p[i] = p0[i] ^ p1[i];
    }
}

/************************************************************/
/* FIPS 197  P.15 Figure 5 */
VOID CAesCbc2s::Encrypt(UINT8 out[], const UINT8 in[])
{
    ShareData(m_Data[0], m_Data[1], in);

    AddVector();

    AddRoundKey(0);

    for ( INT32 i = 1; i < m_Nr; i++ )
    {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(i);
    }

    SubBytes();
    ShiftRows();
    AddRoundKey(m_Nr);

    memcpy(m_Vector[0], m_Data[0], NBb);
    memcpy(m_Vector[1], m_Data[1], NBb);
    CombineData(out, m_Data[0], m_Data[1]);
}

/************************************************************/
/* FIPS 197  P.21 Figure 12 */
VOID CAesCbc2s::Decrypt(UINT8 out[], const UINT8 in[])
{
    UINT8 nextVector[2][NBb];

    ShareData(m_Data[0], m_Data[1], in);
    memcpy(nextVector, m_Data, sizeof(nextVector));

    AddRoundKey(m_Nr);

    for ( INT32 i = m_Nr - 1; i > 0; i-- )
    {
        invShiftRows();
        invSubBytes();
        AddRoundKey(i);
        invMixColumns();
    }

    invShiftRows();
    invSubBytes();
    AddRoundKey(0);

    AddVector();

    memcpy(m_Vector, nextVector, sizeof(m_Vector));
    CombineData(out, m_Data[0], m_Data[1]);

    secure_zero(nextVector, sizeof(nextVector));
}

/************************************************************/
VOID CAesCbc2s::AddVector(VOID)
{
    for ( INT32 i = 0; i < 2; i++ )
    {
        UINT32 * d = (UINT32 *)m_Data[i];
        UINT32 * v = (UINT32 *)m_Vector[i];
        for ( INT32 j = 0; j < NB; j++ )
        {
            d[j] ^= v[j];
        }
    }
}

/************************************************************/
/* FIPS 197  P.16 Figure 6 */
VOID CAesCbc2s::SubBytes()
{
    sbox_masked_bs16((UINT8 *)m_Data[0], (UINT8 *)m_Data[1]);
}

/************************************************************/
/* FIPS 197  P.22 5.3.2 */
VOID CAesCbc2s::invSubBytes()
{
    inv_sbox_masked_bs16((UINT8 *)m_Data[0], (UINT8 *)m_Data[1]);
}

/************************************************************/
/* FIPS 197  P.17 Figure 8 */
VOID CAesCbc2s::ShiftRows()
{
    for ( INT32 j = 0; j < 2; j++ )
    {
        UINT8 * cb = &m_Data[j][0];
        UINT8 t;

        t      = cb[ 1];
        cb[ 1] = cb[ 5];
        cb[ 5] = cb[ 9];
        cb[ 9] = cb[13];
        cb[13] = t;

        t      = cb[ 2];
        cb[ 2] = cb[10];
        cb[10] = t;

        t      = cb[ 3];
        cb[ 3] = cb[15];
        cb[15] = cb[11];
        cb[11] = cb[ 7];
        cb[ 7] = t;

        t      = cb[ 6];
        cb[ 6] = cb[14];
        cb[14] = t;
    }
}

/************************************************************/
/* FIPS 197  P.22 Figure 13 */
VOID CAesCbc2s::invShiftRows()
{
    for ( INT32 j = 0; j < 2; j++ )
    {
        UINT8 * cb = &m_Data[j][0];
        UINT8 t;

        t      = cb[ 1];
        cb[ 1] = cb[13];
        cb[13] = cb[ 9];
        cb[ 9] = cb[ 5];
        cb[ 5] = t;

        t      = cb[ 2];
        cb[ 2] = cb[10];
        cb[10] = t;

        t      = cb[ 3];
        cb[ 3] = cb[ 7];
        cb[ 7] = cb[11];
        cb[11] = cb[15];
        cb[15] = t;

        t      = cb[ 6];
        cb[ 6] = cb[14];
        cb[14] = t;
    }
}

/************************************************************/
/* FIPS 197  P.18 Figure 9 */
VOID CAesCbc2s::MixColumns()
{
    for ( INT32 j = 0; j < 2; j++ )
    {
        for ( INT32 i = 0; i < NBb; i += 4 )
        {
            UINT8 * cb = &m_Data[j][i];
            UINT8 t = (UINT8)(cb[0] ^ cb[1] ^ cb[2] ^ cb[3]);
            UINT32 t32 = t | (t << 8);
            t32 |= t32 << 16;
            UINT32 cb32 = *(UINT32 *)cb;
            UINT32 cs32 = ROR8(cb32);
            *(UINT32 *)&m_Data[j][i] = cb32 ^ t32 ^ xtime32(cb32 ^ cs32);
        }
    }
}

/************************************************************/
/* FIPS 197  P.23 5.3.3 */
VOID CAesCbc2s::invMixColumns()
{
    for ( INT32 j = 0; j < 2; j++ )
    {
        for ( INT32 i = 0; i < NBb; i += 4 )
        {
            UINT32 w = *(UINT32 *)&m_Data[j][i];

            // preparing x2,x4,x8
            UINT32 x2 = xtime32(w);
            UINT32 x4 = xtime32(x2);
            UINT32 x8 = xtime32(x4);

            UINT32 w8    = ROR8(w);
            UINT32 w16   = ROR16(w);
            UINT32 w24   = ROR24(w);
            UINT32 x2_8  = ROR8(x2);
            UINT32 x4_16 = ROR16(x4);
            UINT32 x8_8  = ROR8(x8);
            UINT32 x8_16 = ROR16(x8);
            UINT32 x8_24 = ROR24(x8);

            // mul0e(w)   = x8 ^ x4 ^ x2
            // mul0b(w8)  = x8_8 ^ x2_8 ^ w8
            // mul0d(w16) = x8_16 ^ x4_16 ^ w16
            // mul09(w24) = x8_24 ^ w24
            *(UINT32 *)&m_Data[j][i] = (x8 ^ x4 ^ x2) ^ (x8_8 ^ x2_8 ^ w8) ^ (x8_16 ^ x4_16 ^ w16) ^ (x8_24 ^ w24);
        }
    }
}

/************************************************************/
/* FIPS 197  P.19 Figure 10 */
VOID CAesCbc2s::AddRoundKey(INT32 n)
{
    for ( INT32 i = 0; i < 2; i++ )
    {
        UINT32 * p = (UINT32 *)&m_KeyExpansion[i][NB * n];
        for ( INT32 j = 0; j < NB; j++ )
        {
            *(UINT32 *)&m_Data[i][j * 4] ^= p[j];
        }
    }
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
VOID CAesCbc2s::SubWord(UINT32 & t0, UINT32 & t1)
{
    UINT8 p0[16] = { 0 };
    UINT8 p1[16] = { 0 };

    p0[0] = (UINT8)t0;
    p0[1] = (UINT8)(t0 >> 8);
    p0[2] = (UINT8)(t0 >> 16);
    p0[3] = (UINT8)(t0 >> 24);

    p1[0] = (UINT8)t1;
    p1[1] = (UINT8)(t1 >> 8);
    p1[2] = (UINT8)(t1 >> 16);
    p1[3] = (UINT8)(t1 >> 24);

    sbox_masked_bs16(p0, p1);

    t0 = (p0[0] | (p0[1] << 8) | (p0[2] << 16) | (p0[3] << 24));
    t1 = (p1[0] | (p1[1] << 8) | (p1[2] << 16) | (p1[3] << 24));

    secure_zero(p0, sizeof(p0));
    secure_zero(p1, sizeof(p1));
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
INT32 CAesCbc2s::RotWord(INT32 in)
{
    INT32 out;
    UINT8 * cin = (UINT8 *)&in;
    UINT8 * cout = (UINT8 *)&out;

    cout[0] = cin[1];
    cout[1] = cin[2];
    cout[2] = cin[3];
    cout[3] = cin[0];

    return(out);
}

/************************************************************/
/* FIPS 197  P.20 Figure 11 */
VOID CAesCbc2s::KeyExpansion(const UINT8 * keys)
{
    /* FIPS 197  P.27 Appendix A.1 Rcon[i/Nk] */
    static const UINT8 Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    const UINT8 * kp = keys;

    for ( INT32 i = 0; i < m_Nk; i++, kp += 4 )
    {
        UINT32 k = kp[0] | (kp[1] << 8) | (kp[2] << 16) | (kp[3] << 24);
        m_KeyExpansion[0][i] = random32();
        m_KeyExpansion[1][i] = k ^ m_KeyExpansion[0][i];
    }

    for ( INT32 i = m_Nk; i < NB * (m_Nr + 1); i++ )
    {
        UINT32 t0 = m_KeyExpansion[0][i - 1];
        UINT32 t1 = m_KeyExpansion[1][i - 1];

        if ( (i % m_Nk) == 0 )
        {
            t0 = RotWord(t0);
            t1 = RotWord(t1);
            SubWord(t0, t1);
            UINT8 * pt = (UINT8 *)&t0;
            *pt ^= Rcon[(i / m_Nk) - 1]; // for the 1st byte
        }
        else if ( m_Nk > 6 && (i % m_Nk) == 4 )
        {
            SubWord(t0, t1);
        }

        m_KeyExpansion[0][i] = m_KeyExpansion[0][i - m_Nk] ^ t0;
        m_KeyExpansion[1][i] = m_KeyExpansion[1][i - m_Nk] ^ t1;
    }
}

UINT32 CAesCbc2s::xtime32(UINT32 x)
{
    UINT32 msb = x & 0x80808080u;
    UINT32 poly = (msb >> 3) | (msb >> 4); poly |= poly >> 3; // poly = msb * 0x1b;
    return ((x & 0x7f7f7f7fu) << 1) ^ poly;
}

/* ===== Pack / Unpack 16 bytes <-> 8 bit-planes ===== */
VOID CAesCbc2s::pack_bitslice16(const UINT8 in[16], UINT16 q[8])
{
    for ( INT32 b = 0; b < 8; b++ )
    {
        UINT16 w = 0;
        for ( INT32 i = 0; i < 16; i++ )
        {
            w |= (UINT16)(((in[i] >> b) & 1u) << i);
        }
        q[b] = w;
    }
}

VOID CAesCbc2s::unpack_bitslice16(const UINT16 q[8], UINT8 out[16])
{
    for ( INT32 i = 0; i < 16; i++ )
    {
        UINT8 v = 0;
        for ( INT32 b = 0; b < 8; b++ )
        {
            v |= (UINT8)(((q[b] >> i) & 1u) << b);
        }
        out[i] = v;
    }
}


/* =========================================================================
 * 2-share masked, 16-lane bitsliced AES S-box
 * ========================================================================= */
/* ===== masked XOR / NOT (linear) ===== */
#define LANE_MASK  ((UINT16)0xffff)   /* all-ones for 16 lanes */
#define XORw(z, x, y)       { (z.a) = (UINT16)((x.a) ^ (y.a)); (z.b) = (UINT16)((x.b) ^ (y.b)); }
#define XOR3(z, w, x, y)    { (z.a) = (UINT16)((w.a) ^ (x.a) ^ (y.a)); (z.b) = (UINT16)((w.b) ^ (x.b) ^ (y.b)); }
#define NOTw(z, x)          { (z.a) = (UINT16)((x.a) ^ LANE_MASK); (z.b) = (x.b); }
#if ENABLE_MASKING
#define ANDm(z, x, y)       isw_and_word((x.a), (x.b), (y.a), (y.b), random16(), &(z.a), &(z.b))
#else
#define ANDm(z, x, y)       { (z.a) = (UINT16)(((x.a) & (y.a)) ^ ((x.a) & (y.b))); \
                              (z.b) = (UINT16)(((x.b) & (y.a)) ^ ((x.b) & (y.b))); }
#endif

struct LANE16 {
    UINT16 a;
    UINT16 b;
};

VOID CAesCbc2s::sbox_masked_planes16(UINT16 q0[8], UINT16 q1[8])
{
    /* 2) Boyar-Peralta circuit on shares (variable names follow BearSSL closely)
       x0..x7 are input planes but BearSSL uses reversed order (x0 = high bit) [1] */
    LANE16 x00, x01, x02, x03, x04, x05, x06, x07;

    x00.a = q0[7];
    x01.a = q0[6];
    x02.a = q0[5];
    x03.a = q0[4];
    x04.a = q0[3];
    x05.a = q0[2];
    x06.a = q0[1];
    x07.a = q0[0];
    x00.b = q1[7];
    x01.b = q1[6];
    x02.b = q1[5];
    x03.b = q1[4];
    x04.b = q1[3];
    x05.b = q1[2];
    x06.b = q1[1];
    x07.b = q1[0];

    /* ---- Top linear transformation (all XORs) [1] ---- */
    LANE16 t00;
    LANE16 t01;
    LANE16 y01;
    LANE16 y02;
    LANE16 y03;
    LANE16 y04;
    LANE16 y05;
    LANE16 y06;
    LANE16 y07;
    LANE16 y08;
    LANE16 y09;
    LANE16 y10;
    LANE16 y11;
    LANE16 y12;
    LANE16 y13;
    LANE16 y14;
    LANE16 y15;
    LANE16 y16;
    LANE16 y17;
    LANE16 y18;
    LANE16 y19;
    LANE16 y20;
    LANE16 y21;

    XORw(y14, x03, x05);
    XORw(y13, x00, x06);
    XORw(y09, x00, x03);
    XORw(y08, x00, x05);
    XORw(t00, x01, x02);
    XORw(y01, t00, x07);
    XORw(y04, y01, x03);
    XORw(y12, y13, y14);
    XORw(y02, y01, x00);
    XORw(y05, y01, x06);
    XORw(y03, y05, y08);
    XORw(t01, x04, y12);
    XORw(y15, t01, x05);
    XORw(y20, t01, x01);
    XORw(y06, y15, x07);
    XORw(y10, y15, t00);
    XORw(y11, y20, y09);
    XORw(y07, x07, y11);
    XORw(y17, y10, y11);
    XORw(y19, y10, y08);
    XORw(y16, t00, y11);
    XORw(y21, y13, y16);
    XORw(y18, x00, y16);

    /* ---- Nonlinear section (AND/XOR). Replace every AND with ISW) [1] ---- */
    /* For brevity we macro-ize masked AND on words, drawing r each time. */

    LANE16 t02;
    LANE16 t03;
    LANE16 t04;
    LANE16 t05;
    LANE16 t06;
    LANE16 t07;
    LANE16 t08;
    LANE16 t09;
    LANE16 t10;
    LANE16 t11;
    LANE16 t12;
    LANE16 t13;
    LANE16 t14;
    LANE16 t15;
    LANE16 t16;
    LANE16 t17;
    LANE16 t18;
    LANE16 t19;
    LANE16 t20;
    LANE16 t21;
    LANE16 t22;
    LANE16 t23;
    LANE16 t24;

    ANDm(t02, y12, y15);
    ANDm(t03, y03, y06);
    XORw(t04, t03, t02);
    ANDm(t05, y04, x07);
    XORw(t06, t05, t02);
    ANDm(t07, y13, y16);
    ANDm(t08, y05, y01);
    XORw(t09, t08, t07);
    ANDm(t10, y02, y07);
    XORw(t11, t10, t07);
    ANDm(t12, y09, y11);
    ANDm(t13, y14, y17);
    XORw(t14, t13, t12);
    ANDm(t15, y08, y10);
    XORw(t16, t15, t12);
    XORw(t17, t04, t14);
    XORw(t18, t06, t16);
    XORw(t19, t09, t14);
    XORw(t20, t11, t16);
    XORw(t21, t17, y20);
    XORw(t22, t18, y19);
    XORw(t23, t19, y21);
    XORw(t24, t20, y18);

    LANE16 t25;
    LANE16 t26;
    LANE16 t27;
    LANE16 t28;
    LANE16 t29;
    LANE16 t30;
    LANE16 t31;
    LANE16 t32;
    LANE16 t33;
    LANE16 t34;
    LANE16 t35;
    LANE16 t36;
    LANE16 t37;
    LANE16 t38;
    LANE16 t39;
    LANE16 t40;
    LANE16 t41;
    LANE16 t42;
    LANE16 t43;
    LANE16 t44;
    LANE16 t45;

    XORw(t25, t21, t22);
    ANDm(t26, t21, t23);
    XORw(t27, t24, t26);
    ANDm(t28, t25, t27);
    XORw(t29, t28, t22);
    XORw(t30, t23, t24);
    XORw(t31, t22, t26);
    ANDm(t32, t31, t30);
    XORw(t33, t32, t24);
    XORw(t34, t23, t33);
    XORw(t35, t27, t33);
    ANDm(t36, t24, t35);
    XORw(t37, t36, t34);
    XORw(t38, t27, t36);
    ANDm(t39, t29, t38);
    XORw(t40, t25, t39);
    XORw(t41, t40, t37);
    XORw(t42, t29, t33);
    XORw(t43, t29, t40);
    XORw(t44, t33, t37);
    XORw(t45, t42, t41);

    /* z0..z17 = t* & y*  (masked AND) */
    LANE16 z00;
    LANE16 z01;
    LANE16 z02;
    LANE16 z03;
    LANE16 z04;
    LANE16 z05;
    LANE16 z06;
    LANE16 z07;
    LANE16 z08;
    LANE16 z09;
    LANE16 z10;
    LANE16 z11;
    LANE16 z12;
    LANE16 z13;
    LANE16 z14;
    LANE16 z15;
    LANE16 z16;
    LANE16 z17;

    ANDm(z00, t44, y15);
    ANDm(z01, t37, y06);
    ANDm(z02, t33, x07);
    ANDm(z03, t43, y16);
    ANDm(z04, t40, y01);
    ANDm(z05, t29, y07);
    ANDm(z06, t42, y11);
    ANDm(z07, t45, y17);
    ANDm(z08, t41, y10);
    ANDm(z09, t44, y12);
    ANDm(z10, t37, y03);
    ANDm(z11, t33, y04);
    ANDm(z12, t43, y13);
    ANDm(z13, t40, y05);
    ANDm(z14, t29, y02);
    ANDm(z15, t42, y09);
    ANDm(z16, t45, y14);
    ANDm(z17, t41, y08);

    /* ---- Bottom linear transformation (XOR + a few NOT) [1] ---- */
    LANE16 t46;
    LANE16 t47;
    LANE16 t48;
    LANE16 t49;
    LANE16 t50;
    LANE16 t51;
    LANE16 t52;
    LANE16 t53;
    LANE16 t54;
    LANE16 t55;
    LANE16 t56;
    LANE16 t57;
    LANE16 t58;
    LANE16 t59;
    LANE16 t60;
    LANE16 t61;
    LANE16 t62;
    LANE16 t63;
    LANE16 t64;
    LANE16 t65;
    LANE16 t66;
    LANE16 t67;
    LANE16 s00;
    LANE16 s01;
    LANE16 s02;
    LANE16 s03;
    LANE16 s04;
    LANE16 s05;
    LANE16 s06;
    LANE16 s07;

    XORw(t46, z15, z16);
    XORw(t47, z10, z11);
    XORw(t48, z05, z13);
    XORw(t49, z09, z10);
    XORw(t50, z02, z12);
    XORw(t51, z02, z05);
    XORw(t52, z07, z08);
    XORw(t53, z00, z03);
    XORw(t54, z06, z07);
    XORw(t55, z16, z17);
    XORw(t56, z12, t48);
    XORw(t57, t50, t53);
    XORw(t58, z04, t46);
    XORw(t59, z03, t54);
    XORw(t60, t46, t57);
    XORw(t61, z14, t57);
    XORw(t62, t52, t58);
    XORw(t63, t49, t58);
    XORw(t64, z04, t59);
    XORw(t65, t61, t62);
    XORw(t66, z01, t63);

    XORw(s00, t59, t63);            /* s0 = t59 ^ t63 */
    /* s6 = t56 ^ ~t62 */
    {
        LANE16 u;
        NOTw(u, t62);
        XORw(s06, t56, u);
    }
    /* s7 = t48 ^ ~t60 */
    {
        LANE16 u;
        NOTw(u, t60);
        XORw(s07, t48, u);
    }

    XORw(t67, t64, t65);
    XORw(s03, t53, t66);
    XORw(s04, t51, t66);
    XORw(s05, t47, t65);

    /* s1 = t64 ^ ~s3 */
    {
        LANE16 u;
        NOTw(u, s03);
        XORw(s01, t64, u);
    }
    /* s2 = t55 ^ ~t67 */
    {
        LANE16 u;
        NOTw(u, t67);
        XORw(s02, t55, u);
    }

    /* 3) outputs -> q (reverse order back) */
    q0[7] = s00.a;
    q0[6] = s01.a;
    q0[5] = s02.a;
    q0[4] = s03.a;
    q0[3] = s04.a;
    q0[2] = s05.a;
    q0[1] = s06.a;
    q0[0] = s07.a;
    q1[7] = s00.b;
    q1[6] = s01.b;
    q1[5] = s02.b;
    q1[4] = s03.b;
    q1[3] = s04.b;
    q1[2] = s05.b;
    q1[1] = s06.b;
    q1[0] = s07.b;
}

/* ===== Linear map B used by BearSSL inverse S-box (applied pre/post)  [3]
   This is a bitsliced linear transform on planes with some ~ (NOT).
   Since NOT is linear over GF(2), we flip bits on ONE share only (XOR with all-ones).
*/
VOID CAesCbc2s::B_linear_map_inplace(UINT16 q0[8], UINT16 q1[8])
{
    /* Make temporaries of original planes. q[0..7] will be overwritten. */
    LANE16 p0;
    LANE16 p1;
    LANE16 p2;
    LANE16 p3;
    LANE16 p4;
    LANE16 p5;
    LANE16 p6;
    LANE16 p7;

    p0.a = q0[0];
    p1.a = q0[1];
    p2.a = q0[2];
    p3.a = q0[3];
    p4.a = q0[4];
    p5.a = q0[5];
    p6.a = q0[6];
    p7.a = q0[7];
    p0.b = q1[0];
    p1.b = q1[1];
    p2.b = q1[2];
    p3.b = q1[3];
    p4.b = q1[4];
    p5.b = q1[5];
    p6.b = q1[6];
    p7.b = q1[7];

    /* emulate ~ on planes 0,1,5,6 by flipping one share */
    p0.b ^= LANE_MASK;  /* ~q[0] */
    p1.b ^= LANE_MASK;  /* ~q[1] */
    p5.b ^= LANE_MASK;  /* ~q[5] */
    p6.b ^= LANE_MASK;  /* ~q[6] */

    /* new q[7]..q[0] as in BearSSL (XOR only) */
    LANE16 n7;
    LANE16 n6;
    LANE16 n5;
    LANE16 n4;
    LANE16 n3;
    LANE16 n2;
    LANE16 n1;
    LANE16 n0;

    XOR3(n7, p1, p4, p6);
    XOR3(n6, p0, p3, p5);
    XOR3(n5, p7, p2, p4);
    XOR3(n4, p6, p1, p3);
    XOR3(n3, p5, p0, p2);
    XOR3(n2, p4, p7, p1);
    XOR3(n1, p3, p6, p0);
    XOR3(n0, p2, p5, p7);

    q0[7] = n7.a;
    q0[6] = n6.a;
    q0[5] = n5.a;
    q0[4] = n4.a;
    q0[3] = n3.a;
    q0[2] = n2.a;
    q0[1] = n1.a;
    q0[0] = n0.a;
    q1[7] = n7.b;
    q1[6] = n6.b;
    q1[5] = n5.b;
    q1[4] = n4.b;
    q1[3] = n3.b;
    q1[2] = n2.b;
    q1[1] = n1.b;
    q1[0] = n0.b;
}

VOID CAesCbc2s::sbox_masked_bs16(UINT8 data0[16], UINT8 data1[16])
{
    /* 1) pack to bit-planes (two shares) */
    UINT16 q0[8];
    UINT16 q1[8];
    pack_bitslice16(data0, q0);
    pack_bitslice16(data1, q1);

    /* forward BP S-box */
    sbox_masked_planes16(q0, q1);

    /* 4) unpack to bytes */
    unpack_bitslice16(q0, data0);
    unpack_bitslice16(q1, data1);

    secure_zero(q0, sizeof(q0));
    secure_zero(q1, sizeof(q1));
}

/* ===== Public API: InvSubBytes ===== */
VOID CAesCbc2s::inv_sbox_masked_bs16(UINT8 data0[16], UINT8 data1[16])
{
    UINT16 q0[8];
    UINT16 q1[8];
    pack_bitslice16(data0, q0);
    pack_bitslice16(data1, q1);

    /* pre B (includes the x ^ 0x63 effect as per BearSSL mapping) */
    B_linear_map_inplace(q0, q1);

    /* forward BP S-box */
    sbox_masked_planes16(q0, q1);

    /* post B */
    B_linear_map_inplace(q0, q1);

    unpack_bitslice16(q0, data0);
    unpack_bitslice16(q1, data1);

    secure_zero(q0, sizeof(q0));
    secure_zero(q1, sizeof(q1));
}

