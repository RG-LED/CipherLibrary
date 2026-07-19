/* ========================================================================== */
/**
 * @file    tls13.h
 * @brief   TLS 1.3 message handling client class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_TLS13_H_)
#define _TLS13_H_

#include "Sha384.h"
#include "Sha256.h"

#define KEY_EXCHANGE_GROUP  1   // 0=X25519, 1=Secp256r1, 2=Secp384r1

#if KEY_EXCHANGE_GROUP == 2
#define HASH_CLASS  CSha384
#else
#define HASH_CLASS  CSha256
#endif

typedef VOID (*TLS_CALLBACK)(INT32 id, const UINT8 * p, SIZE_T len);

class CTls13
{
public:
    enum Phase {
        SendingClientHello,
        ReceivingServerHello,
        ReceivingEncryptedExtensions,
        ReceivingCertificate,
        ReceivingCertificateVerify,
        ReceivingFinished,
        SendingFinished,
        Connected,
        Closed,
        Error
    };
    enum ErrorDetail {
        DecryptError,
        UnknownSignature,
    };

    CTls13() { Reset(); m_receiverFunc = m_senderFunc = NULL; }
    ~CTls13();

    BOOL StartConnection(TLS_CALLBACK receiver, TLS_CALLBACK sender, UINT32 id);

    Phase CurrentPhase() const { return m_phase; }
    UINT32 GetAlertDetail() const { return m_alertDetail; } // 0x10000 means client side

    BOOL ProcessReceivedMessage(UINT8 * msg, SIZE_T & len); // msg will be overwritten

    BOOL BuildPacket(UINT8 * out, SIZE_T & len, const VOID * msg, SIZE_T msglen);

private:
    static constexpr SIZE_T CIPHER_AES128_KEYSIZE = 16;
    static constexpr SIZE_T CIPHER_AES256_KEYSIZE = 32;
    static constexpr SIZE_T CIPHER_CHACHA20_KEYSIZE = 32;
    static constexpr SIZE_T CIPHER_MAX_KEYSIZE = 32;

#if KEY_EXCHANGE_GROUP == 2
    static constexpr SIZE_T HASH_SIZE = 48;
#else
    static constexpr SIZE_T HASH_SIZE = 32;
#endif

    static constexpr SIZE_T TAG_SIZE = 16;

    static constexpr SIZE_T X25519_PV_KEYSIZE = 32;
    static constexpr SIZE_T X25519_PB_KEYSIZE = 32;
    static constexpr SIZE_T SECP256_PV_KEYSIZE = 32;
    static constexpr SIZE_T SECP256_PB_KEYSIZE = 65;
    static constexpr SIZE_T SECP384_PV_KEYSIZE = 48;
    static constexpr SIZE_T SECP384_PB_KEYSIZE = 97;
    static constexpr SIZE_T PB_MAX_KEYSIZE = MAX(X25519_PB_KEYSIZE, MAX(SECP256_PB_KEYSIZE, SECP384_PB_KEYSIZE));
    static constexpr SIZE_T PV_MAX_KEYSIZE = MAX(X25519_PV_KEYSIZE, MAX(SECP256_PV_KEYSIZE, SECP384_PV_KEYSIZE));

    VOID Reset();
    BOOL SendClientHello();
    BOOL SendClientFinished();
    BOOL SendKeyUpdate();
    BOOL SendAlert(INT32 level, INT32 desc);

    BOOL MakeClientHello(UINT8 * msg, SIZE_T & len);
    BOOL MakeClientFinished(UINT8 * msg, SIZE_T & len);

    BOOL EncryptPacket(UINT8 * msg, SIZE_T len);   // msg will be extended for 16 bytes
    BOOL DecryptPacket(UINT8 * msg, SIZE_T len);   // msg will be overwritten

    BOOL ProcessHandshake(const UINT8 * msg, SIZE_T len);
    INT32 ParseServerHello(const UINT8 * msg, SIZE_T len);
    BOOL ParseEncryptedExtension(const UINT8 * msg, SIZE_T & len);
    BOOL ParseCertificate(const UINT8 * msg, SIZE_T & len);
    BOOL ParseCertificateVerify(const UINT8 * msg, SIZE_T & len);
    BOOL ParseFinished(const UINT8 * msg, SIZE_T & len);
    BOOL ParseKeyUpdate(const UINT8 * msg, SIZE_T & len);

    BOOL ParsePublicKeyEcdsa(UINT8 * out, const UINT8 * p, SIZE_T len);
    BOOL PrepareEncryption();
    VOID PrepareEncryption2(const UINT8 * trans_hash);
    VOID UpdateEncryptionToReceive();
    VOID UpdateEncryptionToSend();
    SIZE_T MakeLabel(UINT8 * out, SIZE_T outlen, const CHAR8 * label, const UINT8 * context = NULL, SIZE_T ctxlen = 0);

    struct Asn1Node
    {
        UINT8  tag;
        SIZE_T length;
        const UINT8 * value;
        const UINT8 * next;
    };

    BOOL ReadAsn1Node(const UINT8 * p, const UINT8 * end, Asn1Node & node);
    BOOL ExtractX509PublicKey(const UINT8 * in, SIZE_T inlen);
    BOOL ExtractRsaPublicKey(const UINT8 * p, SIZE_T len);
    BOOL ExtractEcdsaPublicKey(const UINT8 * p, SIZE_T len);
    BOOL ExtractEd25519PublicKey(const UINT8 * p, SIZE_T len);

    Phase m_phase;
    enum { X25519, Secp256r1, Secp384r1 } m_keyExchange;
    enum { RSA, ECDSA256, ECDSA384, ED25519 } m_certAlgorithm;
    enum { AES128GCM, AES256GCM, CHACHA20POLY1305 } m_cipherSuite;
    UINT32 m_alertDetail;

    TLS_CALLBACK m_receiverFunc;
    TLS_CALLBACK m_senderFunc;
    UINT32 m_callbackID;

    UINT8 m_privateKey[PV_MAX_KEYSIZE];
    UINT8 m_clientPublicKey[PB_MAX_KEYSIZE];
    UINT8 m_serverPublicKey[PB_MAX_KEYSIZE];
    UINT8 m_sharedSecret[HASH_SIZE];
    UINT8 m_derivedSecret[HASH_SIZE];
    UINT8 m_clientAppSecret[HASH_SIZE];
    UINT8 m_serverAppSecret[HASH_SIZE];
    SIZE_T m_privateKeySize;

    UINT64 m_sendSequence;
    UINT64 m_receiveSequence;
    UINT8 m_clientKey[CIPHER_MAX_KEYSIZE];
    UINT8 m_clientIV[12];
    UINT8 m_serverKey[CIPHER_MAX_KEYSIZE];
    UINT8 m_serverIV[12];
    SIZE_T m_cipherKeySize;

    SIZE_T m_cookieSize;
    UINT8 m_cookie[256];
    UINT8 m_certPublicKey1[256];
    UINT8 m_certPublicKey2[HASH_SIZE];
    SIZE_T m_certKeyLength1;
    SIZE_T m_certKeyLength2;
    UINT8 m_serverFinishedKey[HASH_SIZE];
    UINT8 m_clientFinishedKey[HASH_SIZE];

    HASH_CLASS m_transHash;
    UINT8 m_buf[16 * 1024]; // buffer for encryption / decryption (may be smaller in most cases)
};

#endif // _TLS13_H_

