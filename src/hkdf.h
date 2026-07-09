/* ========================================================================== */
/**
 * @file    hkdf.h
 * @brief   HKDF key derivation class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_HKDF_H_)
#define _HKDF_H_

#include "hmac.h"
#include "sha256.h"
#include "secure.h"


template<typename HASH>
class CHkdf
{
public:
    static constexpr SIZE_T HashSize = HASH::OutputSize;

    CHkdf() { secure_zero(m_prk, sizeof(m_prk)); };
    ~CHkdf() { secure_zero(m_prk, sizeof(m_prk)); };
    CHkdf(const UINT8 * salt, SIZE_T saltlen, const UINT8 * ikm, SIZE_T ikmlen) { Initialize(salt, saltlen, ikm, ikmlen); }

    VOID SetPrk(const UINT8 * prk) { memcpy(m_prk, prk, sizeof(m_prk)); }

    VOID Initialize(const UINT8 * salt, SIZE_T saltlen, const UINT8 * ikm, SIZE_T ikmlen)
    {
        Extract(salt, saltlen, ikm, ikmlen);
    }

    BOOL DeriveKey(const UINT8 * info, SIZE_T infolen, UINT8 * key, SIZE_T keylen)
    {
        return Expand(info, infolen, key, keylen);
    }

private:
    VOID Extract(const UINT8 * salt, SIZE_T saltlen, const UINT8 * ikm, SIZE_T ikmlen)
    {
        CHmac<HASH> h;
        if ( salt == NULL || saltlen == 0 )
        {
            UINT8 zero[HashSize] = { 0 };
            h.Initialize(zero, sizeof(zero));
        }
        else
        {
            h.Initialize(salt, saltlen);
        }
        h.Update(ikm, ikmlen);
        h.Finish(m_prk);
    }

    BOOL Expand(const UINT8 * info, SIZE_T infolen, UINT8 * okm, SIZE_T okmlen)
    {
        if ( okmlen > 255 * HashSize )
        {
            return FALSE; // too large
        }

        UINT8 buf[HashSize];
        SIZE_T buflen = 0;

        SIZE_T pos = 0;
        UINT8 counter = 1;

        while ( pos < okmlen )
        {
            CHmac<HASH> h;
            h.Initialize(m_prk, HashSize);

            if ( buflen > 0 )
            {
                h.Update(buf, buflen);
            }

            h.Update(info, infolen);
            h.Update(&counter, 1);

            h.Finish(buf);
            buflen = HashSize;

            SIZE_T copy_len = okmlen - pos;
            if ( copy_len > HashSize )
            {
                copy_len = HashSize;
            }
            memcpy(okm + pos, buf, copy_len);

            pos += copy_len;
            counter++;
        }
        secure_zero(buf, sizeof(buf));
        return TRUE;
    }

    UINT8 m_prk[HashSize];
};

class CHkdfSha256 : public CHkdf<CSha256> { };

#endif // _HKDF_H_

