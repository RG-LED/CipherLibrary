/* ========================================================================== */
/**
 * @file    x448.cpp
 * @brief   X448 key exchange class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "x448.h"
#include "secure.h"

const CFe448 CX448::A24(39081);

const UINT8 CX448::BasePoint[] = {
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void CX448::ScalarMult(UINT8 out[56], const UINT8 scalar_in[56], const UINT8 u_in[56])
{
    UINT8 k[56];

    memcpy(k, scalar_in, 56);
    k[0]  &= 0xfc; // 252
    k[55] |= 0x80; // 128

    CFe448 x_1;
    CFe448 x_2 = CFe448::One;
    CFe448 z_2 = CFe448::Zero;
    CFe448 x_3;
    CFe448 z_3 = CFe448::One;
    x_1.fromBytesLE(u_in, 56);
    x_3 = x_1;

    CFe448 A, AA, B, BB, E, C, D, DA, CB;
    INT32 swap = 0;
    CFe448::BASE_TYPE mask;

    for ( INT32 t = 447; t >= 0; t-- )
    {
        INT32 k_t = (k[t / 8] >> (t & 7)) & 1;
        swap ^= k_t;
        mask = 0 - swap;

        x_2.cswap(x_3, mask);
        z_2.cswap(z_3, mask);
        swap = k_t;

        // Montgomery ladder step
        CFe448::Add(A, x_2, z_2);     // A = x_2 + z_2
        CFe448::Mul(AA, A, A);        // AA = A^2
        CFe448::Sub(B, x_2, z_2);     // B = x_2 - z_2
        CFe448::Mul(BB, B, B);        // BB = B^2
        CFe448::Sub(E, AA, BB);       // E = AA - BB

        CFe448::Add(C, x_3, z_3);     // C = x_3 + z_3
        CFe448::Sub(D, x_3, z_3);     // D = x_3 - z_3
        CFe448::Mul(DA, D, A);        // DA = D * A
        CFe448::Mul(CB, C, B);        // CB = C * B

        CFe448::Add(A, DA, CB);       // x_3 = (DA + CB)^2
        CFe448::Mul(x_3, A, A);
        CFe448::Sub(z_3, DA, CB);     // z_3 = x_1 * (DA - CB)^2
        CFe448::Mul(A, z_3, z_3);
        CFe448::Mul(z_3, x_1, A);
        CFe448::Mul(x_2, AA, BB);     // x_2 = AA * BB
        CFe448::Mul(z_2, A24, E);     // z_2 = E * (AA + a24 * E)
        CFe448::Add(A, AA, z_2);
        CFe448::Mul(z_2, E, A);
    }

    mask = 0 - swap;
    x_2.cswap(x_3, mask);
    z_2.cswap(z_3, mask);

    CFe448::Inv(A, z_2);
    CFe448::Mul(B, x_2, A);

    B.toBytesLE(out, 56);
    secure_zero(k, sizeof(k));
}

