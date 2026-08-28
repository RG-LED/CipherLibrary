/* ========================================================================== */
/**
 * @file    ecbase.cpp
 * @brief   EC base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "ecbase.h"

template<>
VOID CEcPoint<EcCurve::SECP256K1>::Double(CEcPoint<EcCurve::SECP256K1> & out, const CEcPoint<EcCurve::SECP256K1> & p1)
{
    if ( p1.IsInfinity() || p1.y.IsZero() )
    {
        out.SetInfinity();
        return;
    }
    CField a, b, c, d, e, f, tmp;

    CField::Mul(a, p1.x, p1.x);         // a = X1^2
    CField::Mul(b, p1.y, p1.y);         // b = Y1^2
    CField::Mul(c, b, b);               // c = b^2

    CField::Add(tmp, p1.x, b);
    CField::Mul(tmp, tmp, tmp);
    CField::Sub(tmp, tmp, a);
    CField::Sub(tmp, tmp, c);
    CField::Add(d, tmp, tmp);           // d = 2*(...)

    CField::Mul(a, p1.x, p1.x);
    CField::Add(tmp, a, a);
    CField::Add(e, tmp, a);             // e = 3*(X1^2)

    CField::Mul(f, e, e);               // f = e^2

    CField xout, yout, zout;

    CField::Add(tmp, d, d);
    CField::Sub(xout, f, tmp);          // X3

    CField::Sub(tmp, d, xout);
    CField::Mul(tmp, e, tmp);
    CField::Add(c, c, c);               // 2c
    CField::Add(c, c, c);               // 4c
    CField::Add(c, c, c);               // 8c
    CField::Sub(yout, tmp, c);          // Y3

    CField::Mul(tmp, p1.y, p1.z);
    CField::Add(zout, tmp, tmp);        // Z3 = 2Y1Z1

    out.x = xout;
    out.y = yout;
    out.z = zout;
}

template VOID CEcPoint<EcCurve::SECP256K1>::Double(CEcPoint<EcCurve::SECP256K1> & out, const CEcPoint<EcCurve::SECP256K1> & p1);

