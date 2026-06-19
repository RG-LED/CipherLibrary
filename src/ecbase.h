/* ========================================================================== */
/**
 * @file    ecbase.h
 * @brief   EC base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ECBASE_H_)
#define _ECBASE_H_

#include "fep256.h"
#include "fep384.h"

/* ========================================================================== */
/**
 * helper data
 */
/* ========================================================================== */

enum class EcCurve {
    P256,
    P384
};

template<EcCurve C>
struct EcTraits;

// ---- P256 ----
template<>
struct EcTraits<EcCurve::P256> {
    static constexpr SIZE_T SCALAR_SIZE = 32;

    using CField = CFeP256;
    using CScalar = CScalarN256;
};

// ---- P384 ----
template<>
struct EcTraits<EcCurve::P384> {
    static constexpr SIZE_T SCALAR_SIZE = 48;

    using CField = CFeP384;
    using CScalar = CScalarN384;
};

/* ========================================================================== */
/**
 * EC base class
 */
/* ========================================================================== */

template<EcCurve C>
class CEcBase
{
public:
    using Traits = EcTraits<C>;

    using CField  = typename EcTraits<C>::CField;
    using CScalar = typename EcTraits<C>::CScalar;

    static constexpr SIZE_T SCALAR_SIZE = EcTraits<C>::SCALAR_SIZE;

    class CPublicKey
    {
    public:
        CField x;
        CField y;
    };

    class CPrivateKey
    {
    public:
        CScalar d;
    };

    class CPoint
    {
    public:
        CField x;
        CField y;
        CField z;

        VOID SetInfinity()
        {
            z = CField::Zero;
        }
        VOID SetGenerator()
        {
            x = CField::Gx;
            y = CField::Gy;
            z = CField::One;
        }

        VOID cswap(CPoint & other, BOOL swap)
        {
            typename CField::BASE_TYPE mask = (CField::BASE_TYPE)(-(INT32)swap);
            x.CField::cswap(other.x, mask);
            y.CField::cswap(other.y, mask);
            z.CField::cswap(other.z, mask);
        }

        VOID FromAffine(const CField & xin, const CField & yin)
        {
            x = xin;
            y = yin;
            z = CField::One;
        }

        VOID ToAffine(CField & xout, CField & yout) const
        {
            if ( IsInfinity() )
            {
                xout = CField::Zero;
                yout = CField::Zero;
                return;
            }

            CField t0;
            CField::Inv(t0, z);

            CField t1;
            CField::Mul(t1, t0, t0);
            CField::Mul(t0, t1, t0);

            CField::Mul(xout, x, t1);
            CField::Mul(yout, y, t0);
        }

        BOOL IsInfinity() const
        {
            return z.IsZero();
        }

        static VOID Double(CPoint & out, const CPoint & p1)
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

            CField::Mul(tmp, p1.z, p1.z);
            CField::Mul(tmp, tmp, tmp);
            CField::Sub(tmp, a, tmp);
            CField::Add(e, tmp, tmp);
            CField::Add(e, e, tmp);             // e = 3*(a-Z^4)

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

        static VOID Add(CPoint & out, const CPoint & p1, const CPoint & p2)
        {
            if ( p1.IsInfinity() )
            {
                out = p2;
                return;
            }
            if ( p2.IsInfinity() )
            {
                out = p1;
                return;
            }
            CField U1, U2, S1, S2;
            CField H, R, H2, H3, U1H2;
            CField tmp1, tmp2;

            // Z1^2, Z2^2
            CField Z1Z1, Z2Z2;
            CField::Mul(Z1Z1, p1.z, p1.z);
            CField::Mul(Z2Z2, p2.z, p2.z);

            // U1, U2
            CField::Mul(U1, p1.x, Z2Z2);
            CField::Mul(U2, p2.x, Z1Z1);

            // Z1^3, Z2^3
            CField::Mul(tmp1, p1.z, Z1Z1);
            CField::Mul(tmp2, p2.z, Z2Z2);

            // S1, S2
            CField::Mul(S1, p1.y, tmp2);
            CField::Mul(S2, p2.y, tmp1);

            // H, R
            CField::Sub(H, U2, U1);
            CField::Sub(R, S2, S1);

            if ( H.IsZero() )
            {
                if ( R.IsZero() )
                {
                    Double(out, p1);
                }
                else
                {
                    out.SetInfinity();
                }
                return;
            }

            // H22 = H^2
            CField::Mul(H2, H, H);

            // H3 = H * I
            CField::Mul(H3, H2, H);

            // U1H2 = U1 * I
            CField::Mul(U1H2, U1, H2);

            CField xout, yout, zout;

            // X3
            CField::Mul(tmp1, R, R);
            CField::Sub(tmp1, tmp1, H3);
            CField::Add(tmp2, U1H2, U1H2);
            CField::Sub(xout, tmp1, tmp2);

            // Y3
            CField::Sub(tmp1, U1H2, xout);
            CField::Mul(tmp1, R, tmp1);
            CField::Mul(tmp2, S1, H3);
            CField::Sub(yout, tmp1, tmp2);

            // Z3
            CField::Mul(tmp1, p1.z, p2.z);
            CField::Mul(zout, tmp1, H);

            out.x = xout;
            out.y = yout;
            out.z = zout;
        }

        static BOOL IsOnCurve(const CField & x, const CField & y)
        {
            // 2. left hand side calculation: y^2 (mod p)
            CField lhs;
            CField::Mul(lhs, y, y); // lhs = y * y

            // 3. right hand side calculation: x^3 + ax + b (mod p)
            CField x2, x3, ax, rhs;
            CField::Mul(x2, x, x);       // x^2
            CField::Mul(x3, x2, x);      // x^3
            CField::Mul(ax, x, CField::A); // ax = a * x
            CField::Add(rhs, x3, ax);    // rhs = x^3 + ax
            CField::Add(rhs, rhs, CField::B); // rhs = x^3 + ax + b

            // 4. compare both side
            return (lhs == rhs);
        }

        static VOID ScalarMul(CPoint & out, const CPoint & p, const CScalar & k)
        {
            CPoint R0;
            CPoint R1;
            R0.SetInfinity();
            R1 = p;
            for ( INT32 i = SCALAR_SIZE * 8 - 1; i >= 0; i-- )
            {
                BOOL swap = k.GetBit(i);
                R0.cswap(R1, swap);
                CPoint::Add(R1, R0, R1);
                CPoint::Double(R0, R0);
                R0.cswap(R1, swap);
            }
            out = R0;
        }
    };
};

#endif /* #if !defined(_ECBASE_H_) */

