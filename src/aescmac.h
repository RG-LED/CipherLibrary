/* ========================================================================== */
/**
 * @file    aescmac.h
 * @brief   AES-CMAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESCMAC_H_)
#define _AESCMAC_H_

#include "aesbase.h"

/************************************************************/
class CAesCmac : public CAesBase
{
public:
    CAesCmac()
    {
        Clear();
    }

    ~CAesCmac()
    {
        Clear();
    }

    BOOL SetKeys(const UINT8 key[], SIZE_T keylen);
    VOID Update(const UINT8 in[], SIZE_T len);
    VOID Finish(UINT8 mac[16]);
    BOOL Verify(const UINT8 mac[16]);

    VOID Reset();

protected:
    VOID Clear();
    VOID ProcessBuffer();
    VOID Finalize();
    static VOID MakeSubkey(UINT8 key[16], const UINT8 in[16]);
    static VOID Xor(UINT8 a[16], const UINT8 b[16])
    {
        for ( INT32 i = 0; i < 16; i++ )
        {
            a[i] ^= b[i];
        }
    }

    UINT8 m_k1[16];
    UINT8 m_k2[16];
    UINT8 m_mac[16];
    UINT8 m_buffer[16];
    SIZE_T m_buflen;
};

#endif // #if !defined(_AESCMAC_H_)

