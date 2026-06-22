/* ========================================================================== */
/**
 * @file    aescbc2s.h
 * @brief   AES cipher class (2-share version)
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_AESCBC2S_H_)
#define _AESCBC2S_H_

#include "chacha20.h"

#define NB  4                          /* 128bit */
#define NBb 16

#define ENABLE_MASKING  0

/************************************************************/
class CAesCbc2s
{
public:
    CAesCbc2s();
    ~CAesCbc2s();

    BOOL SetKeys(const UINT8 keys[], SIZE_T len);
    VOID SetRandomSeed(const UINT8 seed[32], const UINT8 nonce[12]);
    VOID ClearVector(VOID);

    VOID Encrypt(UINT8 out[], const UINT8 in[]);    /* FIPS 197  P.15 Figure  5 */
    VOID Decrypt(UINT8 out[], const UINT8 in[]);    /* FIPS 197  P.21 Figure 12 */

private:
    UINT32 m_KeyExpansion[2][60];       /* FIPS 197 P.19 5.2 Key Expansion */
    UINT8 m_Data[2][NBb];
    UINT8 m_Vector[2][NBb];
    INT32 m_Nk;                         /* 4,6,8(128,192,256 bit) key length */
    INT32 m_Nr;                         /* 10,12,14 rounds */
    CChacha20 m_Random;

    VOID ShareData(UINT8 x0[], UINT8 x1[], const UINT8 x[]);
    static VOID CombineData(UINT8 x[], const UINT8 x0[], const UINT8 x1[]);

    VOID AddVector(VOID);
    VOID SubBytes(VOID);            /* FIPS 197  P.16 Figure  6 */
    VOID ShiftRows(VOID);           /* FIPS 197  P.17 Figure  8 */
    VOID MixColumns(VOID);          /* FIPS 197  P.18 Figure  9 */
    VOID AddRoundKey(INT32 n);        /* FIPS 197  P.19 Figure 10 */
    VOID KeyExpansion(const UINT8 * keys); /* FIPS 197  P.20 Figure 11 */
    VOID invShiftRows(VOID);        /* FIPS 197  P.22 Figure 13 */
    VOID invSubBytes(VOID);         /* FIPS 197  P.22 5.3.2 */
    VOID invMixColumns(VOID);       /* FIPS 197  P.23 5.3.3 */

    UINT32 random32() { return m_Random.Read32(); }
    UINT16 random16() { return m_Random.Read16(); }
    UINT8 random8() { return m_Random.Read8(); }

    static UINT32 xtime32(UINT32 x);

#if ENABLE_MASKING
    static VOID isw_and_word(UINT16 a0, UINT16 a1, UINT16 b0, UINT16 b1, UINT16 r, UINT16 * z0, UINT16 * z1)
    {
        *z0 = (UINT16)((a0 & b0) ^ r);
        *z1 = (UINT16)((a0 & b1) ^ (a1 & b0) ^ (a1 & b1) ^ r);
    }
#endif

    static VOID pack_bitslice16(const UINT8 in[16], UINT16 q[8]);
    static VOID unpack_bitslice16(const UINT16 q[8], UINT8 out[16]);
    static VOID B_linear_map_inplace(UINT16 q0[8], UINT16 q1[8]);
    VOID sbox_masked_planes16(UINT16 p0[8], UINT16 p1[8]);
    VOID sbox_masked_bs16(UINT8 data0[16], UINT8 data1[16]);
    VOID inv_sbox_masked_bs16(UINT8 data0[16], UINT8 data1[16]);

    VOID SubWord(UINT32 & t0, UINT32 & t1);        /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
    static INT32 RotWord(INT32 in);        /* FIPS 197  P.20 Figure 11 */ /* FIPS 197  P.19  5.2 */
};

#endif // #if !defined(_AESCBC2S_H_)

