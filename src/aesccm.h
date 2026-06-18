/* ========================================================================== */
/**
 * @file    aesccm.h
 * @brief   AES-CCM cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESCCM_H_)
#define _AESCCM_H_

#include "aesbase.h"

/************************************************************/
class CAesCcm : public CAesBase
{
public:
    CAesCcm();
    ~CAesCcm();

    BOOL Encrypt(UINT8 * cipher, const UINT8 * msg, SIZE_T mlen,
                 const UINT8 * nonce, SIZE_T nlen,
                 const UINT8 * aad, SIZE_T alen,
                 const UINT8 * key, SIZE_T klen, SIZE_T tlen);

    BOOL Decrypt(UINT8 * msg, const UINT8 * cipher, SIZE_T clen,
                 const UINT8 * nonce, SIZE_T nlen,
                 const UINT8 * aad, SIZE_T alen,
                 const UINT8 * key, SIZE_T klen, SIZE_T tlen);

protected:
    SIZE_T m_M;
    SIZE_T m_L;
    SIZE_T m_keyLen;
    UINT8 m_block[16];
    UINT8 m_counter[16];
    UINT8 m_tag[16];

    VOID Initialize();
    BOOL SetParameter(SIZE_T mlen, SIZE_T nlen, SIZE_T klen, SIZE_T tlen);
    VOID FirstBlock(const UINT8 * nonce, SIZE_T alen, SIZE_T mlen);
    VOID FeedAad(const UINT8 * aad, SIZE_T alen);
    VOID FeedMessage(const UINT8 * msg, SIZE_T mlen);
    VOID FeedBlock(const UINT8 block[16]);
    VOID BuildCounterBlock(const UINT8 * nonce);
    VOID MakeTag(UINT8 tag[16]);
    VOID IncrementCounter();
    VOID ConvertMessage(UINT8 * out, const UINT8 * msg, SIZE_T mlen);
    VOID ConvertBlock(UINT8 * out, const UINT8 * msg, SIZE_T mlen);
};

#endif // #if !defined(_AESCCM_H_)

