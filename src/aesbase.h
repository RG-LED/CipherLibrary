/* ========================================================================== */
/**
 * @file    aesbase.h
 * @brief   AES cipher base calss
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESBASE_H_)
#define _AESBASE_H_

#include "BasicDefs.h"

#define NB  4                          /* 128bit */
#define NBb 16

/************************************************************/
class CAesBase
{
public:
    CAesBase();
    ~CAesBase();

    BOOL SetKeys(const UINT8 keys[], SIZE_T len);

    VOID EncryptBlock(UINT8 data[]);
    VOID DecryptBlock(UINT8 data[]);

private:
    UINT32 m_KeyExpansion[60];      /* FIPS 197 P.19 5.2 Key Expansion */
    UINT32 * m_pData;
    INT32 m_Nk;                     /* 4,6,8(128,192,256 bit) key length */
    INT32 m_Nr;                     /* 10,12,14 rounds */

    VOID KeyExpansion(const UINT8 * keys); /* FIPS 197  P.20 Figure 11 */

    VOID SubBytes(VOID);            /* FIPS 197  P.16 Figure  6 */
    VOID ShiftRows(VOID);           /* FIPS 197  P.17 Figure  8 */
    VOID MixColumns(VOID);          /* FIPS 197  P.18 Figure  9 */
    VOID AddRoundKey(INT32 n);      /* FIPS 197  P.19 Figure 10 */

    VOID invShiftRows(VOID);        /* FIPS 197  P.22 Figure 13 */
    VOID invSubBytes(VOID);         /* FIPS 197  P.22 5.3.2 */
    VOID invMixColumns(VOID);       /* FIPS 197  P.23 5.3.3 */

    static UINT32 SubWord(UINT32 in); /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
    static UINT32 RotWord(UINT32 in); /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
    static UINT32 mul(UINT32 dt, UINT32 n);

    static const UINT8 m_Sbox[256];
    static const UINT8 m_invSbox[256];
    static const INT32 m_ShiftTable[16];
    static const UINT8 m_mul_1[256];
    static const UINT8 m_mul_2[256];
    static const UINT8 m_mul_3[256];
    static const UINT8 m_mul_9[256];
    static const UINT8 m_mul_b[256];
    static const UINT8 m_mul_d[256];
    static const UINT8 m_mul_e[256];
};

#endif // #if !defined(_AESBASE_H_)

