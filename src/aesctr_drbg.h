/* ========================================================================== */
/**
 * @file    aesctr_drbg.h
 * @brief   AES-CTR random generator class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESCTR_DRBG_H_)
#define _AESCTR_DRBG_H_

#include "aesctr.h"

class CAesCtrDrbg : public CAesCtr<AesCtrSpec::BIG128>
{
public:
    ~CAesCtrDrbg() { secure_zero(m_key, sizeof(m_key)); }
    BOOL Setup(INT32 keyLen, BOOL useDf);
    BOOL Instantiate(const UINT8 * entropy, SIZE_T eLen,
                     const UINT8 * nonce, SIZE_T nLen,
                     const UINT8 * personal, SIZE_T pLen);

    BOOL Reseed(const UINT8 * entropy, SIZE_T eLen,
                const UINT8 * additional, SIZE_T aLen);

    BOOL Generate(UINT8 * out, SIZE_T oLen,
                  const UINT8 * additional, SIZE_T aLen);

private:
    class CDerivation;

    VOID Update(const UINT8 * data);
    UINT8 m_key[32];
    UINT32 m_keyLen;
    UINT32 m_seedLen;
    BOOL m_useDf;
    UINT64 m_reseedCounter;
};

#endif // #if !defined(_AESCTR_DRBG_H_)

