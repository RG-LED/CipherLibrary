/* ========================================================================== */
/**
 * @file    aesxts.h
 * @brief   AES-XTS cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESXTS_H_)
#define _AESXTS_H_

#include "aesbase.h"

/************************************************************/
class CAesXts : public CAesBase
{
public:
    ~CAesXts();

    BOOL SetKeys(const UINT8 keys[], SIZE_T len);

    BOOL Encrypt(UINT8 out[], const UINT8 in[], SIZE_T len, UINT64 unitnum);
    BOOL Decrypt(UINT8 out[], const UINT8 in[], SIZE_T len, UINT64 unitnum);

    BOOL Encrypt(UINT8 out[], const UINT8 in[], SIZE_T len, const UINT8 unitnum[16]);
    BOOL Decrypt(UINT8 out[], const UINT8 in[], SIZE_T len, const UINT8 unitnum[16]);

private:
    VOID MakeTweak(const UINT8 unitnum[16]);
    VOID EncryptOneBlock(UINT8 out[], const UINT8 in[]);
    VOID DecryptOneBlock(UINT8 out[], const UINT8 in[]);
    static VOID Xor(UINT8 a[NBb], const UINT8 b[NBb]);
    VOID NextTweak();
    CAesBase m_aestweak;
    UINT8 m_tweak[NBb];
};

#endif // #if !defined(_AESXTS_H_)

