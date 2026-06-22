/* ========================================================================== */
/**
 * @file    aescbc.h
 * @brief   AES-CBC cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESCBC_H_)
#define _AESCBC_H_

#include "aesbase.h"

/************************************************************/
class CAesCbc : public CAesBase
{
public:
    CAesCbc();
    ~CAesCbc();

    BOOL SetKeys(const UINT8 keys[], SIZE_T len);
    VOID SetInitialVector(const UINT8 iv[16]);
    VOID ClearVector(VOID);

    VOID Encrypt(UINT8 out[], const UINT8 in[]);    /* FIPS 197  P.15 Figure  5 */
    VOID Decrypt(UINT8 out[], const UINT8 in[]);    /* FIPS 197  P.21 Figure 12 */

private:
    INT32 m_Vector[NB];
    INT32 m_Data[NB];

    VOID AddVector(VOID);
};

#endif // #if !defined(_AESCBC_H_)

