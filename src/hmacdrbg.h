/* ========================================================================== */
/**
 * @file    hmacdrbg.h
 * @brief   HMAC-DRBG random generator class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_HMACDRBG_H_)
#define _HMACDRBG_H_

#include "hmac.h"
#include "secure.h"


template<typename HASH>
class CHmacDrbg
{
public:
    static constexpr SIZE_T BlockSize = HASH::BlockSize;
    static constexpr SIZE_T HashSize = HASH::OutputSize;

    VOID Initialize(const UINT8 * key, SIZE_T len)
    {
        for ( INT32 i = 0; i < HashSize; i++ )
        {
            m_k[i] = 0x00;
            m_v[i] = 0x01;
        }
        Reseed(key, len);
    }

    VOID Generate(UINT8 * out, SIZE_T len)
    {
        GenerateCore(out, len);
        UpdateState(NULL, 0);
    }

    VOID Generate(UINT8 * out, SIZE_T len, const UINT8 * add, SIZE_T addlen)
    {
        if ( addlen > 0 )
        {
            UpdateState(add, addlen);
        }
        GenerateCore(out, len);
        UpdateState(add, addlen);
    }

    VOID Reseed(const UINT8 * seed, SIZE_T len)
    {
        UpdateState(seed, len);
    }

    VOID UpdateState(const UINT8 * seed, SIZE_T len)
    {
        CHmac<HASH> hash;
        UINT8 phase = 0x00;

        hash.Initialize(m_k, HashSize);
        hash.Update(m_v, HashSize);
        hash.Update(&phase, 1);
        hash.Update(seed, len);
        hash.Finish(m_k);

        hash.Initialize(m_k, HashSize);
        hash.Update(m_v, HashSize);
        hash.Finish(m_v);

        if ( len > 0 )
        {
            phase = 0x01;
            hash.Initialize(m_k, HashSize);
            hash.Update(m_v, HashSize);
            hash.Update(&phase, 1);
            hash.Update(seed, len);
            hash.Finish(m_k);

            hash.Initialize(m_k, HashSize);
            hash.Update(m_v, HashSize);
            hash.Finish(m_v);
        }
    }

private:
    VOID GenerateCore(UINT8 * out, SIZE_T len)
    {
        CHmac<HASH> hash;
        while ( len > 0 )
        {
            hash.Initialize(m_k, HashSize);
            hash.Update(m_v, HashSize);
            hash.Finish(m_v);
            SIZE_T take = (len < HashSize) ? len : HashSize;
            memcpy(out, m_v, take);
            out += take;
            len -= take;
        }
    }

    UINT8 m_k[HashSize];
    UINT8 m_v[HashSize];
};

#endif // _HMACDRBG_H_

