/* ========================================================================== */
/**
 * @file    aesgcm.h
 * @brief   AES-GCM cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESGCM_H_)
#define _AESGCM_H_

#include "aesctr.h"
#include "ghash.h"

/************************************************************/
class CAesGcm : public CAesCtr<AesCtrSpec::BIG32>
{
public:
    CAesGcm();
    ~CAesGcm();

public:
    // * For usability reasons, this is intentionally implemented as a streaming-type API.
    //   Therefore, if CheckTag() fails during decryption, you must always discard the decryption result.

    BOOL SetKeys(const UINT8 * key, SIZE_T key_len);

    VOID Init(const UINT8 iv[], SIZE_T ivLen, const UINT8 * aad = NULL, SIZE_T aadLen = 0);

    VOID SetTag(const UINT8 tag[16]); // call before Decrypt

    VOID Encrypt(UINT8 * out, const UINT8 * in, SIZE_T len);

    VOID Decrypt(UINT8 * out, const UINT8 * in, SIZE_T len);

    VOID Finalize();

    VOID GetTag(UINT8 tag[16]) const; // call after Encrypt

    BOOL CheckTag() const;

private:
    CGHash m_gHash;
    CGf128BE m_H;       // GHASH subkey
    CGf128BE m_Y;       // GHASH accumulator

    SIZE_T m_aadLen;
    SIZE_T m_dataLen;

    UINT8 m_buffer[16];
    SIZE_T m_bufLen;

    UINT8 m_S[16];   // AES(K, J0) tag mask
    UINT8 m_tag[16];
};

#endif // #if !defined(_AESGCM_H_)

