/* ========================================================================== */
/**
 * @file    hmac.h
 * @brief   HMAC MAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_HMAC_H_)
#define _HMAC_H_

#include "BasicDefs.h"
#include "secure.h"


template<typename HASH>
class CHmac
{
public:
    static constexpr SIZE_T BlockSize = HASH::BlockSize;
    static constexpr SIZE_T HashSize = HASH::OutputSize;

    VOID Initialize(const UINT8 * key, SIZE_T len)
    {
        UINT8 k_pad[BlockSize] = { 0 };

        if ( len > BlockSize )
        {
            HASH hash;
            hash.Initialize();
            hash.Update(key, len);
            hash.Finish(k_pad);
        }
        else
        {
            memcpy(k_pad, key, len);
        }

        // ipad
        m_iHash.Initialize();
        for ( SIZE_T i = 0; i < BlockSize; i++ )
        {
            k_pad[i] ^= 0x36;
        }
        m_iHash.Update(k_pad, BlockSize);

        // opad
        m_oHash.Initialize();
        for ( SIZE_T i = 0; i < BlockSize; i++ )
        {
            k_pad[i] ^= (0x36 ^ 0x5c);
        }
        m_oHash.Update(k_pad, BlockSize);

        secure_zero(k_pad, sizeof(k_pad));
    }

    VOID Update(const UINT8 * data, SIZE_T len)
    {
        m_iHash.Update(data, len);
    }

    VOID Finish(UINT8 * out)
    {
        UINT8 digest[HashSize];

        m_iHash.Finish(digest);
        m_oHash.Update(digest, HashSize);
        m_oHash.Finish(out);

        secure_zero(digest, sizeof(digest));
    }

private:
    HASH m_iHash;
    HASH m_oHash;
};

#endif // _HMAC_H_

