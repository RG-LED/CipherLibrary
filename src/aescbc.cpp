/* ========================================================================== */
/**
 * @file    aescbc.cpp
 * @brief   AES-CBC cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aescbc.h"
#include "secure.h"

/************************************************************/
CAesCbc::CAesCbc()
{
    ClearVector();
}

/************************************************************/
CAesCbc::~CAesCbc()
{
    ClearVector();
}

BOOL CAesCbc::SetKeys(const UINT8 keys[], SIZE_T len)
{
    BOOL ret = CAesBase::SetKeys(keys, len);
    ClearVector();
    return ret;
}

VOID CAesCbc::SetInitialVector(const UINT8 iv[NB])
{
    memcpy(m_Vector, iv, sizeof(m_Vector));
}

VOID CAesCbc::ClearVector(VOID)
{
    secure_zero(m_Vector, sizeof(m_Vector));
}

/************************************************************/
/* FIPS 197  P.15 Figure 5 */
VOID CAesCbc::Encrypt(UINT8 out[], const UINT8 in[])
{
    memcpy(m_Data, in, NBb);

    AddVector();

    EncryptBlock((UINT8 *)m_Data);

    memcpy(m_Vector, m_Data, NBb);
    memcpy(out, m_Data, NBb);
}

/************************************************************/
/* FIPS 197  P.21 Figure 12 */
VOID CAesCbc::Decrypt(UINT8 out[], const UINT8 in[])
{
    INT32 nextVector[NB];

    memcpy(m_Data, in, NBb);
    memcpy(nextVector, m_Data, NBb);

    DecryptBlock((UINT8 *)m_Data);

    AddVector();

    memcpy(m_Vector, nextVector, NBb);
    memcpy(out, m_Data, NBb);
}

/************************************************************/
inline VOID CAesCbc::AddVector(VOID)
{
    m_Data[0] ^= m_Vector[0];
    m_Data[1] ^= m_Vector[1];
    m_Data[2] ^= m_Vector[2];
    m_Data[3] ^= m_Vector[3];
}

