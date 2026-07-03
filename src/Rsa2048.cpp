/* ========================================================================== */
/**
 * @file    Rsa2048.cpp
 * @brief   2048-bit RSA signature class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "Rsa2048.h"
#include "sha256.h"
#include "RandomGenerator.h"
#include "secure.h"

static CRandomGenerator random;

// ---------- generate 1024-bit odd number ----------
static VOID random_1024_odd(CRsaBigInt2048 & x)
{
    UINT8 le[128];
    random.Fill(le, sizeof(le));
    // set MSB and LSB
    le[127] |= 0x80;
    le[0] |= 0x01;
    x.fromBytesLE(le, 128);
    secure_zero(le, sizeof(le));
}

static BOOL prime_filter(const CRsaBigInt2048 & n)
{
    static const UINT32 primes[] = {
           3,    5,    7,   11,   13,   17,   19,   23,   29,   31,
          37,   41,   43,   47,   53,   59,   61,   67,   71,   73,
          79,   83,   89,   97,  101,  103,  107,  109,  113,  127,
         131,  137,  139,  149,  151,  157,  163,  167,  173,  179,
         181,  191,  193,  197,  199,  211,  223,  227,  229,  233,
         239,  241,  251,  257,  263,  269,  271,  277,  281,  283,
         293,  307,  311,  313,  317,  331,  337,  347,  349,  353,
         359,  367,  373,  379,  383,  389,  397,  401,  409,  419,
         421,  431,  433,  439,  443,  449,  457,  461,  463,  467,
         479,  487,  491,  499,  503,  509,  521,  523,  541,  547,
         557,  563,  569,  571,  577,  587,  593,  599,  601,  607,
         613,  617,  619,  631,  641,  643,  647,  653,  659,  661,
         673,  677,  683,  691,  701,  709,  719,  727,  733,  739,
         743,  751,  757,  761,  769,  773,  787,  797,  809,  811,
         821,  823,  827,  829,  839,  853,  857,  859,  863,  877,
         881,  883,  887,  907,  911,  919,  929,  937,  941,  947,
         953,  967,  971,  977,  983,  991,  997, 1009, 1013, 1019,
        1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087,
        1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
        1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229
    };

    for ( INT32 i = 0; i < sizeof(primes) / sizeof(primes[0]); i++ )
    {
        if ( n.ModSmall(primes[i]) == 0 )
        {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL miller_rabin(const CRsaBigInt2048 & n, INT32 rounds)
{
    if ( n <= CRsaBigInt2048::One ) return FALSE;
    if ( n == CRsaBigInt2048::Two || n == CRsaBigInt2048::Three ) return TRUE;
    if ( n.IsEven() )
    {
        return FALSE;
    }

    CRsaBigInt2048 n_minus_1;
    CFeBigInt2048::Sub(n_minus_1, n, CRsaBigInt2048::One);

    CRsaBigInt2048 d = n_minus_1;
    INT32 r = 0;
    while ( d.IsEven() )
    {
        d.ShiftRight1();
        r++;
    }

    CRsaMontCtx2048 ctx;
    if ( !CRsaBigInt2048::PrepareContext(&ctx, n, 64) )
    {
        return FALSE;
    }

    CRsaBigInt2048 ONE_M;
    ONE_M.ToMont64(CRsaBigInt2048::One, &ctx);

    CRsaBigInt2048 Nminus1_M;
    Nminus1_M.ToMont64(n_minus_1, &ctx);

    CRsaBigInt2048 n_minus_2;
    CFeBigInt2048::Sub(n_minus_2, n, CRsaBigInt2048::Two);

    UINT8 rnd[128];

    for ( INT32 t = 0; t < rounds; t++ )
    {
        CRsaBigInt2048 a;
        do
        {
            random.Fill(rnd, sizeof(rnd));
            a.fromBytesLE(rnd, sizeof(rnd));
        }
        while ( a < CRsaBigInt2048::Two || a > n_minus_2 );

        CRsaBigInt2048 aM;
        aM.ToMont64(a, &ctx);

        CRsaBigInt2048 A = ONE_M;

        INT32 bitlen_d = d.SearchMSB() + 1;

        for ( INT32 i = bitlen_d - 1; i >= 0; --i )
        {
            RSA_SQR64(A, A, &ctx);
            UINT32 ebit = (UINT32)d.GetBit(i);
            CRsaBigInt2048 tmp;
            RSA_MUL64(tmp, A, aM, &ctx);
            A.cmux(tmp, (UINT32)0 - (ebit & 1u));
        }
        CRsaBigInt2048 xM = A;

        if ( xM == ONE_M || xM == Nminus1_M )
        {
            continue;
        }

        BOOL witness_composite = TRUE;
        for ( INT32 i = 1; i < r; i++ )
        {
            RSA_SQR64(xM, xM, &ctx);
            if ( xM == Nminus1_M )
            {
                witness_composite = FALSE;
                break;
            }
        }
        if ( witness_composite )
        {
            return FALSE;
        }
    }

    return TRUE; // probably prime
}


// ---------- generate 1024-bit prime number ----------
static VOID generate_prime_1024(CRsaBigInt2048 & p, INT32 mr_rounds)
{
    do
    {
        random_1024_odd(p);
    }
    while ( !prime_filter(p) || !miller_rabin(p, mr_rounds) );
}


// ---------- OS2IP / I2OSP ----------
static VOID OS2IP(CRsaBigInt2048 & x, const UINT8 * be, SIZE_T len)
{
    x.fromBytesBE(be, len);
}
static VOID I2OSP(UINT8 * be, SIZE_T len, const CRsaBigInt2048 & x)
{
    x.toBytesBE(be, len);
}


// ---------- MGF1(SHA-256) ----------
static VOID mgf1_sha256(UINT8 * out, SIZE_T outLen, const UINT8 * seed, SIZE_T seedLen)
{
    UINT8 counter_be[4];
    UINT8 digest[32];
    SIZE_T produced = 0;
    for ( UINT32 ctr = 0; produced < outLen; ctr++ )
    {
        counter_be[0] = (UINT8)(ctr >> 24);
        counter_be[1] = (UINT8)(ctr >> 16);
        counter_be[2] = (UINT8)(ctr >> 8);
        counter_be[3] = (UINT8)(ctr);
        // Hash( seed || counter )
        CSha256 sha;
        sha.Initialize();
        sha.Update(seed, (INT32)seedLen);
        sha.Update(counter_be, sizeof(counter_be));
        sha.Finish(digest);

        SIZE_T need = outLen - produced;
        if ( need > sizeof(digest) )
        {
            need = sizeof(digest);
        }
        memcpy(out + produced, digest, need);
        produced += need;
    }
    secure_zero(counter_be, sizeof(counter_be));
    secure_zero(digest, sizeof(digest));
}


// ---------- EMSA-PSS-ENCODE (SHA-256) ----------
static BOOL emsa_pss_encode_sha256(UINT8 * EM, SIZE_T emLen, const UINT8 * m, SIZE_T mLen, UINT32 saltLen, SIZE_T modBits)
{
    // emBits = modBits - 1
    const INT32 hLen = 32;
    const INT32 emBits = (INT32)modBits - 1;
    const INT32 emLenExpected = (emBits + 7) / 8;

    if ( (INT32)emLen < emLenExpected )
    {
        return FALSE;
    }

    // 1) mHash = Hash(m)
    UINT8 mHash[32];
    CSha256 sha;
    sha.Initialize();
    sha.Update(m, (INT32)mLen);
    sha.Finish(mHash);

    // 2) 8 zeros || mHash || salt
    sha.Initialize();
    static const UINT8 zeros[8] = { 0 };
    sha.Update(zeros, sizeof(zeros));
    sha.Update(mHash, sizeof(mHash));
    secure_zero(mHash, sizeof(mHash));

    // 3) DB = PS || 0x01 || salt
    INT32 psLen = (INT32)(emLen - hLen - 2 - saltLen);
    if ( psLen <= 0 )
    {
        return FALSE;
    }
    secure_zero(EM, psLen);
    EM[psLen] = 0x01;
    random.Fill(EM + psLen + 1, saltLen);
    sha.Update(EM + psLen + 1, saltLen);

    UINT8 H[32];
    sha.Finish(H);

    // 4) dbMask = MGF1(H, emLen - hLen -1)
    UINT8 dbMask[256 - 32 - 1]; // at most
    mgf1_sha256(dbMask, emLen - hLen - 1, H, 32);

    // 5) maskedDB = DB ^ dbMask; clear leftmost bit
    for ( INT32 i = 0; i < (INT32)emLen - hLen - 1; ++i )
    {
        EM[i] ^= dbMask[i];
    }
    // clear leftmost bit (MSB)
    INT32 unusedBits = (INT32)(8 * emLen - emBits);
    if ( unusedBits > 0 )
    {
        EM[0] &= (UINT8)(0xFFu >> unusedBits);
    }

    // 6) EM = maskedDB || H || 0xBC
    memcpy(EM + emLen - hLen - 1, H, hLen);
    EM[emLen - 1] = 0xBC;

    secure_zero(H, sizeof(H));

    return TRUE;
}

// ---------- EMSA-PSS-VERIFY ----------
static BOOL emsa_pss_verify_sha256(const UINT8 * EM, SIZE_T emLen, const UINT8 * m, SIZE_T mLen, UINT32 saltLen, SIZE_T modBits)
{
    const INT32 hLen = 32;
    const INT32 emBits = (INT32)modBits - 1;
    const INT32 emLenExpected = (emBits + 7) / 8;

    if ( (INT32)emLen < emLenExpected || (INT32)emLen < hLen + 2 || EM[emLen - 1] != 0xBC )
    {
        return FALSE;
    }

    UINT8 mHash[32];
    CSha256 sha;
    sha.Initialize();
    sha.Update(m, (INT32)mLen);
    sha.Finish(mHash);

    // 1) maskedDB || H || 0xBC
    const UINT8 * H = EM + emLen - hLen - 1;

    // 2) recover DB clearing first unusedBits of maskedDB
    INT32 unusedBits = (INT32)(8 * emLen - emBits);
    UINT8 DB[256 - 32 - 1]; // at most
    INT32 dbLen = (INT32)(emLen - hLen - 1);
    memcpy(DB, EM, dbLen);

    UINT8 mask = (UINT8)(0xFFu >> unusedBits);
    if ( unusedBits > 0 )
    {
        if ( (DB[0] & ~mask) != 0 )
        {
            secure_zero(mHash, sizeof(mHash));
            return FALSE;
        }
    }

    // 3) dbMask = MGF1(H, emLen - hLen - 1), DB ^= dbMask
    UINT8 dbMask[256 - 32 - 1]; // at most
    mgf1_sha256(dbMask, dbLen, H, hLen);
    for ( INT32 i = 0; i < dbLen; ++i )
    {
        DB[i] ^= dbMask[i];
    }

    if ( unusedBits > 0 )
    {
        DB[0] &= mask;
    }

    // 4) check format as PS||0x01||salt
    INT32 psLen = (INT32)(dbLen - 1 - saltLen);
    // first unusedBits must be already 0
    for ( INT32 i = 0; i < psLen; ++i )
    {
        if ( DB[i] != 0x00 )
        {
            secure_zero(mHash, sizeof(mHash));
            return FALSE;
        }
    }
    if ( DB[psLen] != 0x01 )
    {
        secure_zero(mHash, sizeof(mHash));
        return FALSE;
    }
    const UINT8 * salt = DB + psLen + 1;

    // 5) H' = Hash( 8zero || mHash || salt )
    static const UINT8 zeros[8] = { 0 };
    UINT8 Hprime[32];
    sha.Initialize();
    sha.Update(zeros, sizeof(zeros));
    sha.Update(mHash, sizeof(mHash));
    sha.Update(salt, saltLen);
    sha.Finish(Hprime);

    BOOL eq = secure_equal(Hprime, H, sizeof(Hprime));

    secure_zero(mHash, sizeof(mHash));
    secure_zero(Hprime, sizeof(Hprime));

    return eq;
}

// ---------- generate keys ----------
BOOL RsaGenerate2048(CRsaKey2048 & key, INT32 mr_rounds)
{
    // 1) generate prime numbers p, q (1024bit)
    CRsaBigInt2048 p;
    CRsaBigInt2048 q;
    generate_prime_1024(p, mr_rounds);
    do
    {
        generate_prime_1024(q, mr_rounds);
    }
    while ( p == q );

    // 2) N = p*q
    CRsaBigInt2048 N;
    CFeBigInt2048::Mul(N, p, q);

    // 3) e = 65537
    UINT32 e = 65537;
    // convert e to BigInt
    CRsaBigInt2048 eBI((UINT32)e);

    // 4) dp = e^{-1} mod (p-1), dq = e^{-1} mod (q-1)
    CRsaBigInt2048 pm1;
    CRsaBigInt2048 qm1;
    CFeBigInt2048::Sub(pm1, p, CRsaBigInt2048::One);
    CFeBigInt2048::Sub(qm1, q, CRsaBigInt2048::One);

    CRsaBigInt2048 dp, dq;
    if ( !RSA_INV(dp, eBI, pm1) || !RSA_INV(dq, eBI, qm1) )
    {
        return FALSE;
    }

    // 5) qInv = q^{-1} mod p
    CRsaBigInt2048 qInv;
    if ( !RSA_INV(qInv, q, p) )
    {
        return FALSE;
    }

    // 6) prepare context
    key.pub.N = N;
    key.pub.e = e;
    CRsaBigInt2048::PrepareContext(&key.pub.montN, key.pub.N, 64);

    key.priv.p = p;
    key.priv.q = q;
    key.priv.dp = dp;
    key.priv.dq = dq;
    key.priv.qInv = qInv;
    CRsaBigInt2048::PrepareContext(&key.priv.montP, key.priv.p);
    CRsaBigInt2048::PrepareContext(&key.priv.montQ, key.priv.q);

    return TRUE;
}

// ---------- signature (RSASSA-PSS, SHA-256, variable saltLen) ----------
BOOL RsaSignPSS_SHA256(const CRsaKey2048 & key, const UINT8 * msg, SIZE_T msgLen, UINT8 sig[256], UINT32 saltLen)
{
    const SIZE_T modBits = key.pub.N.SearchMSB() + 1;
    const SIZE_T emLen   = (modBits - 1 + 7) / 8; // 256

    // 1) EMSA-PSS-ENCODE
    UINT8 EM[256];
    if ( !emsa_pss_encode_sha256(EM, emLen, msg, msgLen, saltLen, modBits) )
    {
        return FALSE;
    }

    // 2) m = OS2IP(EM)
    CRsaBigInt2048 m;
    OS2IP(m, EM, emLen);

    // 3) CRT signature
    // mp = m mod p, mq = m mod q
    CRsaBigInt2048 mpM;
    CRsaBigInt2048 mqM;
    // m(2048) -> mp(1024)
    mpM.Reduce2048to1024(m, &key.priv.montP);
    mqM.Reduce2048to1024(m, &key.priv.montQ);

    CRsaBigInt2048 sp;
    CRsaBigInt2048 sq;
    RSA_EXP32(sp, mpM, key.priv.dp, &key.priv.montP);
    RSA_EXP32(sq, mqM, key.priv.dq, &key.priv.montQ);

    // 1) diff = (sp - sq) mod p
    CRsaBigInt2048 diff;
    RSA_SUB(diff, sp, sq, key.priv.p);

    // 2) make diff to mont field (diff * R mod p)
    CRsaBigInt2048 diffM;
    diffM.ToMont32(diff, &key.priv.montP); 
    CRsaBigInt2048 qInvM;
    qInvM.ToMont32(key.priv.qInv, &key.priv.montP);

    // 3) h = (diffM * qInvM * R^-1) mod p = (diff * qInv * R) mod p
    CRsaBigInt2048 hM;
    RSA_MUL32(hM, diffM, qInvM, &key.priv.montP);

    // 4) extract from mont (hM * R^-1 mod p) = (diff * qInv) mod p
    CRsaBigInt2048 h;
    hM.FromMont32(h, &key.priv.montP);

    // s = sq + q*h
    // q*h is within 2048 bits: Mul(FOLD) -> Extract
    CRsaBigInt2048 qh;
    CFeBigInt2048::Mul(qh, key.priv.q, h);
    CRsaBigInt2048 s;
    RSA_ADD(s, sq, qh, key.pub.N);

    // 4) I2OSP
    I2OSP(sig, 256, s);

    secure_zero(EM, sizeof(EM));

    return TRUE;
}

// ---------- verify (RSASSA-PSS, SHA-256) ----------
BOOL RsaVerifyPSS_SHA256(const CRsaKey2048Pub & pub, const UINT8 * msg, SIZE_T msgLen, const UINT8 sig[256], UINT32 saltLen)
{
    const SIZE_T modBits = pub.N.SearchMSB() + 1;
    const SIZE_T emLen   = (modBits - 1 + 7) / 8; // 256

    // 1) s = OS2IP(sig)
    CRsaBigInt2048 s;
    OS2IP(s, sig, 256);

    // check range: s < N
    if ( s >= pub.N )
    {
        return FALSE;
    }

    // 2) m = s^e mod N
    CRsaBigInt2048 m;
    CRsaBigInt2048::Exp64_e32(m, s, pub.e, &pub.montN);

    // 3) EM = I2OSP(m, emLen)
    UINT8 EM[256];
    I2OSP(EM, emLen, m);

    // 4) EMSA-PSS-VERIFY
    BOOL ok = emsa_pss_verify_sha256(EM, emLen, msg, msgLen, saltLen, modBits);

    secure_zero(EM, sizeof(EM));

    return ok;
}

