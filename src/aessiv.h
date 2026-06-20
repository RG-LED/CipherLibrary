/* ========================================================================== */
/**
 * @file    aessiv.h
 * @brief   AES-SIV cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESSIV_H_)
#define _AESSIV_H_

#include "aescmac.h"

/************************************************************/
class CAesSiv : public CAesCmac
{
public:
    CAesSiv();
    ~CAesSiv();

    BOOL SetKeys(const UINT8 keys[], SIZE_T len);
    VOID AddAad(const UINT8 * aad, SIZE_T len);
    VOID Seal(UINT8 * out, SIZE_T & outlen, const UINT8 * in, SIZE_T inlen);
    BOOL Open(UINT8 * out, SIZE_T & outlen, const UINT8 * in, SIZE_T inlen);

private:
    VOID ClearWork();
    VOID FinishS2V(UINT8 out[NBb], const UINT8 * in, SIZE_T len);
    static VOID Double(UINT8 data[NBb]);
    static VOID Increment(UINT8 data[NBb]);
    UINT8 m_v[NBb];
    UINT8 m_d[NBb];
    UINT8 m_ctrkey[64];
    SIZE_T m_keylen;
    SIZE_T m_lastaadlen;
};

#endif // #if !defined(_AESSIV_H_)

