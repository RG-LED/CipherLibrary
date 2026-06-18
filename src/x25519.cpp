/* ========================================================================== */
/**
 * @file    x25519.cpp
 * @brief   X25519 key exchange class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "x25519.h"
#include "secure.h"

const CFe25519 CX25519::A24(121665);

const UINT8 CX25519::BasePoint[] = {
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

VOID CX25519::ScalarMult(UINT8 out[32], const UINT8 scalar_in[32], const UINT8 u_in[32])
{
    UINT8 k[32];

    memcpy(k, scalar_in, 32);
    k[0]  &= 0xf8; // 248
    k[31] &= 0x7f; // 127
    k[31] |= 0x40; // 64

    CFe25519 x_1(u_in);
    CFe25519 x_2 = CFe25519::One;
    CFe25519 z_2 = CFe25519::Zero;
    CFe25519 x_3 = x_1;
    CFe25519 z_3 = CFe25519::One;

    CFe25519 A, AA, B, BB, E, C, D, DA, CB;
    INT32 swap = 0;
    CFe25519::BASE_TYPE mask;

    for ( INT32 t = 254; t >= 0; t-- )
    {
        INT32 k_t = (k[t / 8] >> (t & 7)) & 1;
        swap ^= k_t;
        mask = 0 - swap;

        x_2.cswap(x_3, mask);
        z_2.cswap(z_3, mask);
        swap = k_t;

        // Montgomery ladder step
        CFe25519::Add(A, x_2, z_2);     // A = x_2 + z_2
        CFe25519::Mul(AA, A, A);        // AA = A^2
        CFe25519::Sub(B, x_2, z_2);     // B = x_2 - z_2
        CFe25519::Mul(BB, B, B);        // BB = B^2
        CFe25519::Sub(E, AA, BB);       // E = AA - BB

        CFe25519::Add(C, x_3, z_3);     // C = x_3 + z_3
        CFe25519::Sub(D, x_3, z_3);     // D = x_3 - z_3
        CFe25519::Mul(DA, D, A);        // DA = D * A
        CFe25519::Mul(CB, C, B);        // CB = C * B

        CFe25519::Add(A, DA, CB);       // x_3 = (DA + CB)^2
        CFe25519::Mul(x_3, A, A);
        CFe25519::Sub(z_3, DA, CB);     // z_3 = x_1 * (DA - CB)^2
        CFe25519::Mul(A, z_3, z_3);
        CFe25519::Mul(z_3, x_1, A);
        CFe25519::Mul(x_2, AA, BB);     // x_2 = AA * BB
        CFe25519::Mul(z_2, A24, E);     // z_2 = E * (AA + a24 * E)
        CFe25519::Add(A, AA, z_2);
        CFe25519::Mul(z_2, E, A);
    }

    mask = 0 - swap;
    x_2.cswap(x_3, mask);
    z_2.cswap(z_3, mask);

    CFe25519::Inv(A, z_2);
    CFe25519::Mul(B, x_2, A);

    B.toBytesLE(out);
    secure_zero(k, sizeof(k));
}

