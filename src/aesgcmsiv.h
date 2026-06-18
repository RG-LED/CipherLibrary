/* ========================================================================== */
/**
 * @file    aesgcmsiv.h
 * @brief   AES-GCM cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESGCMSIV_H_)
#define _AESGCMSIV_H_

#include "aesctr.h"
#include "polyval.h"


class CAesGcmSiv : public CAesCtr<AesCtrSpec::LITTLE32>
{
public:
    CAesGcmSiv();
    ~CAesGcmSiv();

public:
    BOOL Initialize(const UINT8 * key, SIZE_T keyLen, const UINT8 nonce[12], const UINT8 * aad = NULL, SIZE_T aadLen = 0);

    VOID Encrypt(UINT8 * out, const UINT8 * in, SIZE_T len, UINT8 tag[16]);
    BOOL Decrypt(UINT8 * out, const UINT8 * in, SIZE_T len, const UINT8 tag[16]);

    UINT8 m_macKey[16];
    UINT8 m_encKey[32];
private:
    VOID MakeKeyPart(UINT8 out[8], const UINT8 nonce[12], INT32 count);
    VOID FeedPolyval(const UINT8 data[], SIZE_T len);

    CPolyval m_polyval;
    CGf128LE m_H;       // POLYVAL subkey
    SIZE_T m_keyLen;
    SIZE_T m_aadLen;

    UINT8 m_iv[12];
};

#endif // #if !defined(_AESGCMSIV_H_)

