/* ========================================================================== */
/**
 * @file    aesctr.h
 * @brief   AES-CTR cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESCTR_H_)
#define _AESCTR_H_

#include "aesbase.h"
#include "secure.h"

enum AesCtrSpec {
    BIG32,
    LITTLE32,
    BIG128,
    LITTLE128,
    XLITTLE128
};

/************************************************************/

template<AesCtrSpec C>
struct ExtraMember {
};

template<>
struct ExtraMember<AesCtrSpec::XLITTLE128> {
    UINT8 m_counter[NBb];
    UINT8 m_vectorbase[NBb];
};

/************************************************************/

template<AesCtrSpec C>
class CAesCtr : public CAesBase
{
public:
    CAesCtr()
    {
        ClearVector();
    }

    ~CAesCtr()
    {
        ClearVector();
    }

    VOID SetInitialVector(const UINT8 iv[])
    {
        ClearVector();
        memcpy(m_vector, iv, sizeof(m_vector));
    }

    VOID Crypt(UINT8 out[], const UINT8 in[], SIZE_T len)
    {
        while ( len > 0 )
        {
            if ( m_streamLen > 0 )
            {
                SIZE_T n = (m_streamLen >= len) ? len : m_streamLen;
                SIZE_T pos = NBb - m_streamLen;
                for ( UINT32 i = 0; i < n; i++ )
                {
                    out[i] = in[i] ^ m_stream[pos + i];
                }
                in += n;
                out += n;
                len -= n;
                m_streamLen -= n;
                continue;
            }

            memcpy(m_stream, m_vector, sizeof(m_stream));
            EncryptBlock(m_stream);
            IncrementVector();
            m_streamLen = NBb;
        }
    }

protected:
    VOID ClearVector()
    {
        m_streamLen = 0;
        secure_zero(m_vector, sizeof(m_vector));
        secure_zero(m_stream, sizeof(m_stream));
    }
    VOID IncrementVector();

    UINT8 m_vector[NBb];
    UINT8 m_stream[NBb];
    SIZE_T m_streamLen;
    ExtraMember<C> m_ex;
};

/************************************************************/

template<>
inline VOID CAesCtr<AesCtrSpec::XLITTLE128>::SetInitialVector(const UINT8 iv[])
{
    ClearVector();
    memcpy(m_ex.m_vectorbase, iv, sizeof(m_ex.m_vectorbase));
    secure_zero(m_ex.m_counter, sizeof(m_ex.m_counter));
    memcpy(m_vector, iv, sizeof(m_vector));
}

#endif // #if !defined(_AESCTR_H_)

