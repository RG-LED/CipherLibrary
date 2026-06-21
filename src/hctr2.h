/* ========================================================================== */
/**
 * @file    hctr2.h
 * @brief   HCTR2 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_HCTR2_H_)
#define _HCTR2_H_

#include "aesctr.h"
#include "polyval.h"
#include "aescmac.h"
#include "secure.h"


/************************************************************/

class CPolyvalEx : public CPolyval
{
public:
    ~CPolyvalEx()
    {
        secure_zero(m_buf, sizeof(m_buf));
    }
    VOID Init(const CGf128LE & h);
    VOID Update(const UINT8 * in, SIZE_T len);
    VOID Flush();
    VOID Final(UINT64 aad_bits, UINT64 c_bits);
private:
    UINT8 m_buf[16];
    SIZE_T m_buflen;
};

/************************************************************/

enum class Hctr2Spec {
    POLYVAL,
    AESCMAC
};

template<Hctr2Spec HASH>
struct Hctr2Traits;

template<>
struct Hctr2Traits<Hctr2Spec::POLYVAL> {
    using CHash = CPolyvalEx;
};

template<>
struct Hctr2Traits<Hctr2Spec::AESCMAC> {
    using CHash = CAesCmac;
};

/************************************************************/

template<Hctr2Spec HASH>
class CHctr2 : public CAesCtr<AesCtrSpec::XLITTLE128>
{
public:
    using Traits = Hctr2Traits<HASH>;
    using CHash = typename Traits::CHash;

    CHctr2()
    {
        Clear();
    }

    ~CHctr2()
    {
        Clear();
    }

    BOOL SetKeys(const UINT8 keys[], SIZE_T len)
    {
        BOOL ret = CAesCtr::SetKeys(keys, len);
        if ( ret )
        {
            secure_zero(m_h, sizeof(m_h));
            EncryptBlock(m_h);
            secure_zero(m_L, sizeof(m_L));
            m_L[0] = 0x01;  // little endian
            EncryptBlock(m_L);
        }
        return ret;
    }

    BOOL Seal(UINT8 * out,
              const UINT8 * nonce, SIZE_T noncelen,
              const UINT8 * aad, SIZE_T aadlen,
              const UINT8 * in, SIZE_T inlen)
    {
        UINT8 tweak[16];
        MakeTweak(tweak, aad, aadlen, nonce, noncelen);
        BOOL ret = SealRaw(out, tweak, sizeof(tweak), in, inlen);
        secure_zero(tweak, sizeof(tweak));
        return ret;
    }

    BOOL Open(UINT8 * out,
              const UINT8 * nonce, SIZE_T noncelen,
              const UINT8 * aad, SIZE_T aadlen,
              const UINT8 * in, SIZE_T inlen)
    {
        UINT8 tweak[16];
        MakeTweak(tweak, aad, aadlen, nonce, noncelen);
        BOOL ret = OpenRaw(out, tweak, sizeof(tweak), in, inlen);
        secure_zero(tweak, sizeof(tweak));
        return ret;
    }

    BOOL SealRaw(UINT8 * out, const UINT8 tweak[16], SIZE_T twlen, const UINT8 * in, SIZE_T inlen)
    {
        if ( inlen < 16 )
        {
            return FALSE;
        }

        const UINT8 * m = in;
        const UINT8 * n = in + 16;
        SIZE_T nlen = inlen - 16;
        UINT8 hash[16];

        Hash(hash, n, nlen, tweak, twlen);

        UINT8 mm[16];   // mm = m ^ hash
        memcpy(mm, m, sizeof(mm));
        Xor(mm, hash);

        UINT8 * uu = out;   // uu(=u) = E(mm)
        memcpy(uu, mm, sizeof(mm));
        EncryptBlock(uu);

        UINT8 s[16];    // s = mm ^ uu ^ L
        memcpy(s, mm, sizeof(s));
        Xor(s, uu);
        Xor(s, m_L);

        UINT8 * v = out + 16;   // v = CTR(s, n)
        SetInitialVector(s);
        IncrementVector();  // start from 1
        Crypt(v, n, nlen);

        Hash(hash, v, nlen, tweak, twlen);
        Xor(uu, hash);

        secure_zero(hash, sizeof(hash));
        secure_zero(mm, sizeof(mm));
        secure_zero(s, sizeof(s));

        return TRUE;
    }

    BOOL OpenRaw(UINT8 * out, const UINT8 tweak[16], SIZE_T twlen, const UINT8 * in, SIZE_T inlen)
    {
        if ( inlen < 16 )
        {
            return FALSE;
        }

        const UINT8 * u = in;
        const UINT8 * v = in + 16;
        SIZE_T vlen = inlen - 16;
        UINT8 hash[16];

        Hash(hash, v, vlen, tweak, twlen);

        UINT8 uu[16];   // uu = u ^ hash
        memcpy(uu, u, sizeof(uu));
        Xor(uu, hash);

        UINT8 * mm = out;   // mm(=m) = E(uu)
        memcpy(mm, uu, sizeof(uu));
        DecryptBlock(mm);

        UINT8 s[16];    // s = mm ^ uu ^ L
        memcpy(s, mm, sizeof(s));
        Xor(s, uu);
        Xor(s, m_L);

        UINT8 * n = out + 16;   // v = CTR(s, n)
        SetInitialVector(s);
        IncrementVector();  // start from 1
        Crypt(n, v, vlen);

        Hash(hash, n, vlen, tweak, twlen);
        Xor(mm, hash);

        secure_zero(hash, sizeof(hash));
        secure_zero(uu, sizeof(uu));
        secure_zero(s, sizeof(s));

        return TRUE;
    }

private:
    VOID MakeTweak(UINT8 tweak[16],
                   const UINT8 * nonce, SIZE_T noncelen,
                   const UINT8 * aad, SIZE_T aadlen);
    VOID Hash(UINT8 out[16], const UINT8 * n, SIZE_T nlen, const UINT8 * tweak, SIZE_T twlen);
    static VOID Xor(UINT8 * a, const UINT8 * b)
    {
        for ( INT32 i = 0; i < NBb; i++ )
        {
            a[i] ^= b[i];
        }
    }

    VOID Clear()
    {
        secure_zero(m_h, sizeof(m_h));
        secure_zero(m_L, sizeof(m_L));
    }

    UINT8 m_h[16];
    UINT8 m_L[16];
};

#endif // #if !defined(_HCTR2_H_)

