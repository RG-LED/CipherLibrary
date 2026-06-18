/* ========================================================================== */
/**
 * @file    aesKeyWrap.h
 * @brief   AES Key Wrap class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESKEYWRAP_H_)
#define _AESKEYWRAP_H_

#include "aesbase.h"

class CAesKeyWrap : public CAesBase
{
public:
    CAesKeyWrap();
    ~CAesKeyWrap();

    BOOL SetKeys(const UINT8 key[], SIZE_T keylen);
    VOID SwitchToKwp();
    BOOL KeyWrap(UINT8 * data, SIZE_T & len, UINT8 tag[8]);
    BOOL KeyUnwrap(UINT8 * data, SIZE_T & len, const UINT8 tag[8]);

private:
    BOOL m_kwp;
    UINT8 m_a[8];
};

#endif // #if !defined(_AESKEYWRAP_H_)

