/* ========================================================================== */
/**
 * @file    tls13.cpp
 * @brief   TLS 1.3 message handling client class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "tls13.h"
#include "x25519.h"
#include "ecdh.h"
#include "hkdf.h"
#include "rsa2048.h"
#include "chacha20poly1305.h"
#include "aesgcm.h"
#include "ecdsa.h"
#include "ed25519.h"
#include "hmac.h"
#include "secure.h"

#define READ16(p)       (((p)[0] << 8) | (p)[1])
#define READ24(p)       (((p)[0] << 16) | ((p)[1] << 8) | (p)[2])
#define WRITE16(p, n)   { (p)[0] = (UINT8)((n) >> 8); (p)[1] = (UINT8)(n); }
#define WRITE24(p, n)   { (p)[0] = (UINT8)((n) >> 16); (p)[1] = (UINT8)((n) >> 8); (p)[2] = (UINT8)(n); }

/* Alert */
/* Alert level */
#define ALERT_WARNING   1
#define ALERT_FATAL     2

/* Alert description */
#define ALERT_UNEXPECTED_MESSAGE    10
#define ALERT_BAD_RECORD_MAC        20
#define ALERT_ILLEGAL_PARAMETER     47
#define ALERT_DECODE_ERROR          50
#define ALERT_DECRYPT_ERROR         51
#define ALERT_PROTOCOL_VERSION      70
#define ALERT_INTERNAL_ERROR        80

CTls13::~CTls13()
{
    secure_zero(m_privateKey, sizeof(m_privateKey));
    secure_zero(m_clientPublicKey, sizeof(m_clientPublicKey));
    secure_zero(m_serverPublicKey, sizeof(m_serverPublicKey));
    secure_zero(m_sharedSecret, sizeof(m_sharedSecret));
    secure_zero(m_derivedSecret, sizeof(m_derivedSecret));

    secure_zero(m_clientKey, sizeof(m_clientKey));
    secure_zero(m_clientIV, sizeof(m_clientIV));
    secure_zero(m_serverKey, sizeof(m_serverKey));
    secure_zero(m_serverIV, sizeof(m_serverIV));

    secure_zero(m_cookie, sizeof(m_cookie));
    secure_zero(m_certPublicKey1, sizeof(m_certPublicKey1));
    secure_zero(m_certPublicKey2, sizeof(m_certPublicKey2));
    secure_zero(m_serverFinishedKey, sizeof(m_serverFinishedKey));
    secure_zero(m_clientFinishedKey, sizeof(m_clientFinishedKey));
}


VOID CTls13::Reset()
{
    m_phase = SendingClientHello;
#if KEY_EXCHANGE_GROUP == 0
    m_keyExchange = X25519;
    m_privateKeySize = X25519_PV_KEYSIZE;
#elif KEY_EXCHANGE_GROUP == 1
    m_keyExchange = Secp256r1;
    m_privateKeySize = SECP256_PV_KEYSIZE;
#elif KEY_EXCHANGE_GROUP == 2
    m_keyExchange = Secp384r1;
    m_privateKeySize = SECP384_PV_KEYSIZE;
#else
#error "Key exchange is not properly decided."
#endif
    m_cookieSize = 0;
    m_transHash.Initialize();
    m_alertDetail = 0;
}


#pragma pack(push, 1)

struct RecordHeader
{
    UINT8 ContentType;
    UINT8 ProtocolVersion[2];
    UINT8 RecordLength[2];
};

struct HandshakeHeader
{
    UINT8 HandshakeType;
    UINT8 HandshakeLength[3];
};

struct HelloHeader
{
    UINT8 ProtocolVersion[2];
    UINT8 Random[32];
};

#pragma pack(pop)


BOOL CTls13::StartConnection(TLS_CALLBACK receiver, TLS_CALLBACK sender, UINT32 id)
{
    m_receiverFunc = receiver;
    m_senderFunc = sender;
    m_callbackID = id;

    Reset();

    return SendClientHello();
}


BOOL CTls13::SendClientHello()
{
    UINT8 msg[256];
    SIZE_T len = sizeof(msg);

    if ( !MakeClientHello(msg, len) )
    {
        secure_zero(msg, sizeof(msg));
        return FALSE;
    }
    if ( m_senderFunc != NULL )
    {
        (*m_senderFunc)(m_callbackID, msg, len);
    }

    m_cookieSize = 0;
    secure_zero(msg, sizeof(msg));
    return TRUE;
}


BOOL CTls13::SendClientFinished()
{
    UINT8 msg[HASH_SIZE * 2];
    SIZE_T len = sizeof(msg);

    if ( !MakeClientFinished(msg, len) )
    {
        secure_zero(msg, sizeof(msg));
        return FALSE;
    }
    if ( m_senderFunc != NULL )
    {
        (*m_senderFunc)(m_callbackID, msg, len);
    }

    secure_zero(msg, sizeof(msg));
    return TRUE;
}


BOOL CTls13::SendAlert(INT32 level, INT32 desc)
{
    UINT8 msg[32];
    SIZE_T len = sizeof(RecordHeader) + 2;

    RecordHeader * pk = (RecordHeader *)msg;

    pk->ContentType = 0x15;              // Alert
    pk->ProtocolVersion[0] = 0x03;       // LegacyRecordVersion
    pk->ProtocolVersion[1] = 0x03;
    pk->RecordLength[0] = 0x00;
    pk->RecordLength[1] = 0x02;

    msg[sizeof(RecordHeader)] = (UINT8)level;
    msg[sizeof(RecordHeader) + 1] = (UINT8)desc;

    m_alertDetail = READ16(&msg[sizeof(RecordHeader)]) | 0x10000;

    if ( m_phase >= ReceivingServerHello )
    {
        pk->ContentType = 0x16;              // Handshake
        msg[sizeof(RecordHeader) + 2] = 0x15;       // Alert
        EncryptPacket(msg, sizeof(RecordHeader) + 3);
        len += TAG_SIZE + 1;
    }

    if ( m_senderFunc != NULL )
    {
        (*m_senderFunc)(m_callbackID, msg, len);
    }

    if ( level == ALERT_FATAL )
    {
        m_phase = Error;
    }

    secure_zero(msg, sizeof(msg));

    return TRUE;
}


BOOL CTls13::MakeClientHello(UINT8 * msg, SIZE_T & len)
{
    static const UINT8 tmpl1[] = {
                        // legacy session ID
        0x00,           //   length (no ID)
                        // cipher suites
#if KEY_EXCHANGE_GROUP == 2
        0x00, 0x02,     //   length
        0x13, 0x02,     //   TLS_AES_256_GCM_SHA384
#else
        0x00, 0x04,     //   length
        0x13, 0x03,     //   TLS_CHACHA20_POLY1305_SHA256
        0x13, 0x01,     //   TLS_AES_128_GCM_SHA256
#endif
                        // compression methods
        0x01,           //   length
        0x00            //   null
    };
    static const UINT8 tmpl2[] = {
                        //   extension #1 (7 bytes)
        0x00, 0x2b,     //     supported version
        0x00, 0x03,     //     length
        0x02,           //     versions length
        0x03, 0x04      //     TLS 1.3
    };
#if KEY_EXCHANGE_GROUP == 2
    static const UINT8 tmpl3_secp384r1[] = {
                        //   extension #2
        0x00, 0x33,     //     key share
        0x00, 0x67,     //     length = 103 (= 2 + 101)
        0x00, 0x65,     //     client_shares_length = 101
        0x00, 0x18,     //     group = secp384r1
        0x00, 0x61      //     key_exchange_length = 97
    };
#else
    static const UINT8 tmpl3_secp256r1[] = {
                        //   extension #2
        0x00, 0x33,     //     key share
        0x00, 0x47,     //     length = 71 (= 2 + 69)
        0x00, 0x45,     //     client_shares_length = 69
        0x00, 0x17,     //     group = secp256r1
        0x00, 0x41      //     key_exchange_length = 65
    };
    static const UINT8 tmpl3_x25519[] = {
                        //   extension #2
        0x00, 0x33,     //     key share
        0x00, 0x26,     //     length = 38 (= 2 + 36)
        0x00, 0x24,     //     client_shares_length = 36
        0x00, 0x1d,     //     group = x25519
        0x00, 0x20      //     key_exchange_length = 32
    };
#endif
    static const UINT8 tmpl4[] = {
                        //   extension #3
        0x00, 0x0a,     //     supported_groups
#if KEY_EXCHANGE_GROUP == 2
        0x00, 0x04,     //     length = 6 (= 2 + 4)
        0x00, 0x02,     //     named group list length = 4
        0x00, 0x18,     //     secp384r1
#else
        0x00, 0x06,     //     length = 6 (= 2 + 4)
        0x00, 0x04,     //     named group list length = 4
        0x00, 0x17,     //     secp256r1
        0x00, 0x1d,     //     x25519
#endif
                        //   extension #4
        0x00, 0x0d,     //     signature_algorithms
#if KEY_EXCHANGE_GROUP == 2
        0x00, 0x04,     //     length = 4 (= 2 + 2)
        0x00, 0x02,     //     list length = 2
        0x05, 0x03      //     ecdsa_secp384r1_sha384
#else
        0x00, 0x08,     //     length = 6 (= 2 + 4)
        0x00, 0x06,     //     list length = 4
        0x08, 0x04,     //     rsa_pss_rsae_sha256
        0x04, 0x03,     //     ecdsa_secp256r1_sha256
        0x08, 0x07      //     ed25519
#endif
    };

    SIZE_T kexlen;

    switch ( m_keyExchange )
    {
#if KEY_EXCHANGE_GROUP == 2
        case Secp384r1:
               kexlen = sizeof(tmpl3_secp384r1) + SECP384_PB_KEYSIZE;
               break;
#else
        case Secp256r1:
               kexlen = sizeof(tmpl3_secp256r1) + SECP256_PB_KEYSIZE;
               break;
        case X25519:
               kexlen = sizeof(tmpl3_x25519) + X25519_PB_KEYSIZE;
               break;
#endif
        default:
               return FALSE;
    }

    SIZE_T cookielen = (m_cookieSize > 0) ? m_cookieSize + 4 : 0;

    if ( m_phase != SendingClientHello ||
         len < sizeof(RecordHeader) + sizeof(HandshakeHeader) +
               sizeof(tmpl1) + sizeof(tmpl2) + 2 /* extension length */ +
               kexlen + cookielen + sizeof(tmpl4) )
    {
        SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
        return FALSE;
    }

    RecordHeader * pk1 = (RecordHeader *)msg;
    HandshakeHeader * pk2 = (HandshakeHeader *)&pk1[1];
    HelloHeader * pk3 = (HelloHeader *)&pk2[1];

    pk1->ContentType = 0x16;              // Handshake
    pk1->ProtocolVersion[0] = 0x03;       // LegacyRecordVersion
    pk1->ProtocolVersion[1] = 0x03;
    pk1->RecordLength[0] = 0;             // temporarily
    pk1->RecordLength[1] = 0;

    pk2->HandshakeType = 0x01;         // ClientHello
    pk2->HandshakeLength[0] = 0;       // temporarily
    pk2->HandshakeLength[1] = 0;
    pk2->HandshakeLength[2] = 0;

    pk3->ProtocolVersion[0] = 0x03;        // TLS 1.2
    pk3->ProtocolVersion[1] = 0x03;
    secure_random(pk3->Random, sizeof(pk3->Random));

    SIZE_T offset = sizeof(RecordHeader) + sizeof(HandshakeHeader) + sizeof(HelloHeader);

    memcpy(&msg[offset], tmpl1, sizeof(tmpl1));
    offset += sizeof(tmpl1);

    UINT8 * extlen = &msg[offset];
    offset += 2; // skip extensions length
    UINT8 * extension = &msg[offset];

    memcpy(&msg[offset], tmpl2, sizeof(tmpl2));
    offset += sizeof(tmpl2);

    switch ( m_keyExchange )
    {
#if KEY_EXCHANGE_GROUP == 2
        case Secp384r1:
            memcpy(&msg[offset], tmpl3_secp384r1, sizeof(tmpl3_secp384r1));
            offset += sizeof(tmpl3_secp384r1);
            do
            {
                secure_random(m_privateKey, SECP384_PV_KEYSIZE);
            }
            while ( !CEcdh<EcCurve::P384>::PrivateKeyToPublicKey(m_clientPublicKey, m_privateKey) );
            memcpy(&msg[offset], m_clientPublicKey, SECP384_PB_KEYSIZE);
            offset += SECP384_PB_KEYSIZE;
            break;
#else
        case X25519:
            memcpy(&msg[offset], tmpl3_x25519, sizeof(tmpl3_x25519));
            offset += sizeof(tmpl3_x25519);
            secure_random(m_privateKey, X25519_PV_KEYSIZE);
            CX25519::PrivateKeyToPublicKey(m_clientPublicKey, m_privateKey);
            memcpy(&msg[offset], m_clientPublicKey, X25519_PB_KEYSIZE);
            offset += X25519_PB_KEYSIZE;
            break;

        case Secp256r1:
            memcpy(&msg[offset], tmpl3_secp256r1, sizeof(tmpl3_secp256r1));
            offset += sizeof(tmpl3_secp256r1);
            do
            {
                secure_random(m_privateKey, SECP256_PV_KEYSIZE);
            }
            while ( !CEcdh<EcCurve::P256>::PrivateKeyToPublicKey(m_clientPublicKey, m_privateKey) );
            memcpy(&msg[offset], m_clientPublicKey, SECP256_PB_KEYSIZE);
            offset += SECP256_PB_KEYSIZE;
            break;
#endif
        default:
            SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
            return FALSE;
    }

    if ( m_cookieSize > 0 )
    {
        msg[offset++] = 0x00;
        msg[offset++] = 0x2c;
        msg[offset++] = (UINT8)(m_cookieSize >> 8);
        msg[offset++] = (UINT8)m_cookieSize;
        memcpy(&msg[offset], m_cookie, m_cookieSize);
        offset += m_cookieSize;
    }

    memcpy(&msg[offset], tmpl4, sizeof(tmpl4));
    offset += sizeof(tmpl4);

    SIZE_T n = &msg[offset] - extension;

    WRITE16(extlen, n);
    extlen[1] = (UINT8)n;

    n = &msg[offset] - (UINT8 *)pk3;
    WRITE24(pk2->HandshakeLength, n);

    n = &msg[offset] - (UINT8 *)pk2;
    WRITE16(pk1->RecordLength, n);

    len = offset;
    m_phase = ReceivingServerHello;
    m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader));

    return TRUE;
}


BOOL CTls13::MakeClientFinished(UINT8 * msg, SIZE_T & len)
{
    if ( m_phase != SendingFinished ||
         len < sizeof(RecordHeader) + sizeof(HandshakeHeader) + HASH_SIZE + 1 + TAG_SIZE )
    {
        SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
        return FALSE;
    }

    UINT8 hash[HASH_SIZE];
    HASH_CLASS sha = m_transHash;
    CHmac<HASH_CLASS> hmac;

    sha.Finish(hash);
    hmac.Initialize(m_clientFinishedKey, sizeof(m_clientFinishedKey));
    hmac.Update(hash, sizeof(hash));
    hmac.Finish(hash);

    RecordHeader * pk1 = (RecordHeader *)msg;
    HandshakeHeader * pk2 = (HandshakeHeader *)&pk1[1];
    UINT8 * pk3 = (UINT8 *)&pk2[1];

    pk1->ContentType = 0x17;              // ApplicationData
    pk1->ProtocolVersion[0] = 0x03;       // LegacyRecordVersion
    pk1->ProtocolVersion[1] = 0x03;
    pk1->RecordLength[0] = 0x00;          // size
    pk1->RecordLength[1] = sizeof(HandshakeHeader) + HASH_SIZE + 1 + TAG_SIZE; // 4 + 32 + 1 + 16

    pk2->HandshakeType = 0x14;         // Finished(client)
    pk2->HandshakeLength[0] = 0x00;    // size
    pk2->HandshakeLength[1] = 0x00;
    pk2->HandshakeLength[2] = HASH_SIZE;

    memcpy(pk3, hash, sizeof(hash));
    pk3[sizeof(hash)] = 0x16;       // Handshake

    len = sizeof(RecordHeader) + sizeof(HandshakeHeader) + HASH_SIZE + 1;

    sha = m_transHash;
    sha.Finish(hash);

    m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader) - 1); // exclude inner content type

    EncryptPacket(msg, len);

    len += TAG_SIZE;

    PrepareEncryption2(hash);

    m_phase = Connected;

    secure_zero(hash, sizeof(hash));

    return TRUE;
}


BOOL CTls13::ProcessReceivedMessage(UINT8 * msg, SIZE_T & len)
{
    UINT8 * p = msg;

    while ( len > sizeof(RecordHeader) )
    {
        RecordHeader * pk = (RecordHeader *)p;
        if ( pk->ProtocolVersion[0] != 0x03 ||   // LegacyRecordVersion
             pk->ProtocolVersion[1] != 0x03 )
        {
            SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
            return FALSE;
        }

        SIZE_T size = READ16(pk->RecordLength);

        if ( len < size + sizeof(RecordHeader) )
        {
            break;
        }

        SIZE_T contents = size;
        UINT8 * ptr = (UINT8 *)&pk[1];

    Retry:
        switch ( pk->ContentType )
        {
            case 0x14:  // ChangeCipherSpec (TLS 1.2)
                if ( ptr[0] != 0x01 )
                {
                    SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                    return FALSE;
                }
                break;

            case 0x15:  // Alert
                if ( ptr[0] == 0x01 &&  // warning
                     ptr[1] == 0x00 )   // close_notify
                {
                    m_phase = Closed;
                }
                else
                {
                    m_phase = Error;
                    m_alertDetail = READ16(ptr);
                }
                return FALSE;

            case 0x16:  // Handshake
                if ( !ProcessHandshake(ptr, contents) )
                {
                    return FALSE;
                }
                break;

            case 0x17:  // ApplicationData
                if ( contents <= TAG_SIZE + 1 )
                {
                    SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
                    return FALSE;
                }
                if ( !DecryptPacket(p, contents + sizeof(RecordHeader)) )
                {
                    SendAlert(ALERT_FATAL, ALERT_BAD_RECORD_MAC);
                    return FALSE;
                }
                contents -= TAG_SIZE + 1;
                while ( contents > 0 && ptr[contents] == 0x00 )
                {
                    contents--;
                }
                if ( ptr[contents] != 0x17 )  // ApplicationData
                {
                    pk->ContentType = ptr[contents];
                    goto Retry;
                }
                if ( m_receiverFunc != NULL )
                {
                    (*m_receiverFunc)(m_callbackID, ptr, contents);
                }
                break;

            default:
                SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
                return FALSE;
        }

        p += size + sizeof(RecordHeader);
        len -= size + sizeof(RecordHeader);
    }
    if ( len > 0 )
    {
        for ( SIZE_T i = 0; i < len; i++ )
        {
            msg[i] = p[i];
        }
    }
    if ( m_phase == SendingFinished )
    {
        return SendClientFinished();
    }
    if ( m_phase == SendingClientHello )
    {
        return SendClientHello();
    }
    return TRUE;
}


BOOL CTls13::ProcessHandshake(const UINT8 * msg, SIZE_T len)
{
    while ( len > sizeof(HandshakeHeader) )
    {
        const HandshakeHeader * pk = (HandshakeHeader *)msg;
        SIZE_T size = READ24(pk->HandshakeLength);
        if ( len < size + sizeof(HandshakeHeader) )
        {
            break;
        }
        const UINT8 * ptr = (UINT8 *)&pk[1];
        switch ( pk->HandshakeType )
        {
            case 0x02:  // ServerHello
                {
                    INT32 ret = ParseServerHello(ptr, size);
                    if ( ret < 0 )
                    {
                        return FALSE;
                    }
                    m_transHash.Update(msg, len);
                    if ( ret > 0 && !PrepareEncryption() )
                    {
                        SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
                        return FALSE;
                    }
                }
                return TRUE;    // no other handshake will follow

            case 0x08:  // EncryptedExtensions
                if ( !ParseEncryptedExtension(ptr, size) )
                {
                    return FALSE;
                }
                m_transHash.Update(msg, size + sizeof(HandshakeHeader));
                break;

            case 0x0b:  // Certificate
                if ( !ParseCertificate(ptr, size) )
                {
                    return FALSE;
                }
                m_transHash.Update(msg, size + sizeof(HandshakeHeader));
                break;

            case 0x0d:  // CertificateRequest
                SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
                return FALSE;   // This implementation does not support client certification

            case 0x0f:  // CertificateVerify
                if ( !ParseCertificateVerify(ptr, size) )
                {
                    return FALSE;
                }
                m_transHash.Update(msg, size + sizeof(HandshakeHeader));
                break;

            case 0x14:  // Finished
                if ( !ParseFinished(ptr, size) )
                {
                    return FALSE;
                }
                m_transHash.Update(msg, size + sizeof(HandshakeHeader));
                break;

            case 0x04:  // NewSessionTicket
                break;

            default:
                SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
                return FALSE;
        }
        msg += size + sizeof(HandshakeHeader);
        len -= size + sizeof(HandshakeHeader);
    }
    return TRUE;
}

BOOL CTls13::BuildPacket(UINT8 * out, SIZE_T & len, const VOID * msg, SIZE_T msglen)
{
    RecordHeader * pk = (RecordHeader *)out;

    SIZE_T n = sizeof(RecordHeader) + msglen + 1 + TAG_SIZE;
    if ( len < n )
    {
        SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
        return FALSE;
    }

    len = n;

    pk->ContentType = 0x17;              // ApplicationData
    pk->ProtocolVersion[0] = 0x03;       // LegacyRecordVersion
    pk->ProtocolVersion[1] = 0x03;

    memcpy(&out[sizeof(RecordHeader)], msg, msglen);
    out[sizeof(RecordHeader) + msglen] = 0x17;           // ApplicationData

    WRITE16(pk->RecordLength, msglen + 1 + TAG_SIZE);

    EncryptPacket(out, sizeof(RecordHeader) + msglen + 1);

    return TRUE;
}


INT32 CTls13::ParseServerHello(const UINT8 * msg, SIZE_T len)
{
    static const UINT8 HelloRetryRequest[] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };

    if ( m_phase != ReceivingServerHello )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return -1;
    }

    if ( len < sizeof(HelloHeader) )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return -1;
    }

    const HelloHeader * pk = (const HelloHeader *)msg;

    if ( pk->ProtocolVersion[0] != 0x03 ||        // TLS 1.2
         pk->ProtocolVersion[1] != 0x03 )
    {
        SendAlert(ALERT_FATAL, ALERT_PROTOCOL_VERSION);
        return -1;
    }

    BOOL retry = (memcmp(pk->Random, HelloRetryRequest, sizeof(pk->Random)) == 0);

    if ( len < sizeof(HelloHeader) + 1 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return -1;
    }

    SIZE_T offset = sizeof(HelloHeader);
    SIZE_T n = msg[offset++];   // legacy session ID length
    offset += n;    // skip legacy session ID

    if ( len < offset + 3 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return -1;
    }

    switch ( READ16(&msg[offset]) )
    {
        case 0x1301:    // TLS_AES_128_GCM_SHA256
            m_cipherSuite = AES128GCM;
            m_cipherKeySize = CIPHER_AES128_KEYSIZE;
            break;
        case 0x1302:    // TLS_AES_256_GCM_SHA384
            m_cipherSuite = AES256GCM;
            m_cipherKeySize = CIPHER_AES256_KEYSIZE;
            break;
        case 0x1303:    // TLS_CHACHA20_POLY1305_SHA256
            m_cipherSuite = CHACHA20POLY1305;
            m_cipherKeySize = CIPHER_CHACHA20_KEYSIZE;
            break;
        default:
            SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
            return -1;
    }
    offset += 2;    // skip cipher suite
    offset++;       // skip compression method

    if ( len < offset + 2 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return -1;
    }

    INT32 extlen = READ16(&msg[offset]);  // extensions length
    offset += 2;        // skip it

    if ( len < offset + extlen )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return -1;
    }

    const UINT8 * extension = &msg[offset];

    BOOL gotSupportedVersion = FALSE;
    BOOL gotKeyshare = FALSE;

    while ( extlen > 4 )    // type (2 bytes) and length (2 bytes) at least
    {
        UINT32 exttype = READ16(extension);
        extension += 2;
        extlen -= 2;
        INT32 size = READ16(extension);
        extension += 2;
        extlen -= 2;

        if ( extlen < size )
        {
            SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
            return -1;
        }

        switch ( exttype )
        {
            case 0x002b:    // supported version
                if ( size != 2 || extlen < 2 || READ16(extension) != 0x0304 )
                {
                    SendAlert(ALERT_FATAL, ALERT_PROTOCOL_VERSION);
                    return -1;
                }
                extension += 2;
                extlen -= 2;
                gotSupportedVersion = TRUE;
                break;

            case 0x002c:    // cookie
                if ( size > sizeof(m_cookie) )
                {
                    SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
                    return -1;
                }
                memcpy(m_cookie, extension, size);
                m_cookieSize = size;
                extension += size;
                extlen -= size;
                break;

            case 0x0033:    // key share
                if ( retry )
                {
                    UINT32 group = READ16(extension);
                    extension += 2;
                    extlen -= 2;
                    switch ( group )
                    {
#if KEY_EXCHANGE_GROUP == 2
                        case 0x0018:    // secp384r1
                            m_keyExchange = Secp384r1;
                            m_privateKeySize = SECP384_PV_KEYSIZE;
                            break;
#else
                        case 0x0017:    // secp256r1
                            m_keyExchange = Secp256r1;
                            m_privateKeySize = SECP256_PV_KEYSIZE;
                            break;
                        case 0x001d:    // x25519
                            m_keyExchange = X25519;
                            m_privateKeySize = X25519_PV_KEYSIZE;
                            break;
#endif
                        default:
                            SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                            return -1;
                    }
                    gotKeyshare = TRUE;
                }
                else
                {
                    if ( size < HASH_SIZE + 2 + 2 || extlen < size )
                    {
                        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
                        return -1;
                    }
                    UINT32 group = READ16(extension);
                    extension += 2;
                    INT32 keylen = READ16(extension);
                    extension += 2;
                    extlen -= 4;
                    if ( extlen < keylen )
                    {
                        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
                        return -1;
                    }
                    switch ( group )
                    {
#if KEY_EXCHANGE_GROUP == 2
                        case 0x0018:    // secp384r1
                            if ( keylen != SECP384_PB_KEYSIZE )
                            {
                                SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                                return -1;
                            }
                            memcpy(m_serverPublicKey, extension, SECP384_PB_KEYSIZE);
                            extension += SECP384_PB_KEYSIZE;
                            extlen -= SECP384_PB_KEYSIZE;
                            m_keyExchange = Secp384r1;
                            gotKeyshare = TRUE;
                            break;
#else
                        case 0x0017:    // secp256r1
                            if ( keylen != SECP256_PB_KEYSIZE )
                            {
                                SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                                return -1;
                            }
                            memcpy(m_serverPublicKey, extension, SECP256_PB_KEYSIZE);
                            extension += SECP256_PB_KEYSIZE;
                            extlen -= SECP256_PB_KEYSIZE;
                            m_keyExchange = Secp256r1;
                            gotKeyshare = TRUE;
                            break;

                        case 0x001d:    // x25519
                            if ( keylen != X25519_PB_KEYSIZE )
                            {
                                SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                                return -1;
                            }
                            memcpy(m_serverPublicKey, extension, X25519_PB_KEYSIZE);
                            extension += X25519_PB_KEYSIZE;
                            extlen -= X25519_PB_KEYSIZE;
                            m_keyExchange = X25519;
                            gotKeyshare = TRUE;
                            break;
#endif
                        default:
                            SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                            return -1;
                    }
                }
                break;

            default:
                extension += size;
                extlen -= size;
                break;
        }
    }

    if ( retry )
    {
        UINT8 hash[HASH_SIZE];
        m_transHash.Finish(hash);
        m_transHash.Initialize();
        UINT8 header[4];
        header[0] = 0xfe;
        header[1] = 0x00;
        WRITE16(&header[2], HASH_SIZE);
        m_transHash.Update(header, sizeof(header));
        m_transHash.Update(hash, sizeof(hash));

        m_phase = SendingClientHello;

        secure_zero(hash, sizeof(hash));

        return 0;   // retry
    }
    else if ( !gotSupportedVersion || !gotKeyshare )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return -1;
    }

    m_phase = ReceivingEncryptedExtensions;

    return 1;   // proceed
}


BOOL CTls13::ParseEncryptedExtension(const UINT8 * msg, SIZE_T & len)
{
    if ( m_phase != ReceivingEncryptedExtensions )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    if ( len < 2 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return FALSE;
    }

    SIZE_T extlen = READ16(msg); // extensions length

    const UINT8 * extension = &msg[2];

    if ( len < extlen + 2 )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    len = extension - msg + extlen;

    while ( extlen > 4 )    // type (2 bytes) and length (2 bytes) at least
    {
        UINT32 exttype = READ16(extension);
        extension += 2;
        extlen -= 2;
        SIZE_T size = READ16(extension);
        extension += 2;
        extlen -= 2;

        if ( extlen < size )
        {
            SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
            return FALSE;
        }

        switch ( exttype )
        {
            case 0x000a:    // supported groups
                break;

            default:
                break;
        }
        extension += size;
        extlen -= size;
    }

    m_phase = ReceivingCertificate;

    return TRUE;
}


BOOL CTls13::ParseCertificate(const UINT8 * msg, SIZE_T & len)
{
    if ( m_phase != ReceivingCertificate )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    if ( len < 1 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return FALSE;
    }

    SIZE_T offset = 0;
    offset += msg[offset] + 1;

    if ( len < offset + 6 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return FALSE;
    }

    SIZE_T total = READ24(&msg[offset]);
    offset += 3;
    SIZE_T size = READ24(&msg[offset]);
    offset += 3;

    if ( total < size + 3 || len < total + 3 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return FALSE;
    }

    len = total + 4;

    if ( !ExtractX509PublicKey(&msg[offset], size) )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    m_phase = ReceivingCertificateVerify;

    return TRUE;
}


BOOL CTls13::ParseCertificateVerify(const UINT8 * msg, SIZE_T & len)
{
    if ( m_phase != ReceivingCertificateVerify )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    if ( len < 4 )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    INT32 algo = READ16(&msg[0]);
    SIZE_T siglen = READ16(&msg[2]);
    const UINT8 * sig = &msg[4];

    if ( len < siglen + 4 )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    len = sig - msg + siglen;

    UINT8 hash[64 + 33 + 1 + HASH_SIZE];
    for ( INT32 i = 0; i < 64; i++ )
    {
        hash[i] = 0x20; // ' '
    }
    memcpy(hash + 64, "TLS 1.3, server CertificateVerify", 33 + 1); // including '\0'

    HASH_CLASS sha = m_transHash;
    sha.Finish(hash + 64 + 33 + 1);

    BOOL match = FALSE;

    switch ( algo )
    {
        case 0x0804:    // rsa_pss_rsae_sha256
            if ( siglen == 256 && m_certAlgorithm == RSA )
            {
                UINT32 e = 0;
                for ( SIZE_T i = 0; i < m_certKeyLength2; i++ )
                {
                    e = (e << 8) | m_certPublicKey2[i];
                }

                CRsaKey2048Pub pub;
                if ( pub.LoadBytes(m_certPublicKey1, m_certKeyLength1, e) )
                {
                    match = RsaVerifyPSS_SHA256(pub, hash, sizeof(hash), sig);
                }
            }
            break;

        case 0x0403:    // ecdsa_secp256r1_sha256
            if ( m_certAlgorithm == ECDSA256 )
            {
                UINT8 buf[64];
                if ( ParsePublicKeyEcdsa(buf, sig, siglen ) )
                {
                    sha.Initialize();
                    sha.Update(hash, sizeof(hash));
                    sha.Finish(hash);
                    CEcdsa<EcCurve::P256>::CPublicKey pub;
                    pub.x.fromBytesBE(m_certPublicKey1, m_certKeyLength1);
                    pub.y.fromBytesBE(m_certPublicKey2, m_certKeyLength2);
                    match = CEcdsa<EcCurve::P256>::VerifyDigest(pub, hash, buf);
                }
            }
            break;

        case 0x0503:    // ecdsa_secp384r1_sha384
            if ( m_certAlgorithm == ECDSA384 )
            {
                UINT8 buf[96];
                if ( ParsePublicKeyEcdsa(buf, sig, siglen ) )
                {
                    sha.Initialize();
                    sha.Update(hash, sizeof(hash));
                    sha.Finish(hash);
                    CEcdsa<EcCurve::P384>::CPublicKey pub;
                    pub.x.fromBytesBE(m_certPublicKey1, m_certKeyLength1);
                    pub.y.fromBytesBE(m_certPublicKey2, m_certKeyLength2);
                    match = CEcdsa<EcCurve::P384>::VerifyDigest(pub, hash, buf);
                }
            }
            break;

        case 0x0807:    // ed25519
            if ( siglen == 64 && m_certAlgorithm == ED25519 )
            {
                match = ed25519_verify(m_certPublicKey1, hash, sizeof(hash), sig);
            }
            break;
    }

    secure_zero(hash, sizeof(hash));

    if ( !match )
    {
        SendAlert(ALERT_FATAL, ALERT_DECRYPT_ERROR);
        return FALSE;
    }

    m_phase = ReceivingFinished;

    return TRUE;
}


BOOL CTls13::ParsePublicKeyEcdsa(UINT8 * out, const UINT8 * p, SIZE_T len)
{
    Asn1Node node;
    const UINT8 * end = p + len;

    secure_zero(out, 64);

    if ( !ReadAsn1Node(p, end, node) || node.tag != 0x30 )
    {
        return FALSE;
    }

    const UINT8 * next = node.next;
    if ( !ReadAsn1Node(node.value, node.next, node) || node.tag != 0x02 )
    {
        return FALSE;
    }
    while ( node.value[0] == 0x00 )
    {
        node.value++;
        node.length--;
    }
    if ( node.length > HASH_SIZE )
    {
        return FALSE;
    }
    memcpy(out + (HASH_SIZE - node.length), node.value, node.length);

    if ( !ReadAsn1Node(node.next, next, node) || node.tag != 0x02 )
    {
        return FALSE;
    }
    while ( node.value[0] == 0x00 )
    {
        node.value++;
        node.length--;
    }
    if ( node.length > HASH_SIZE )
    {
        return FALSE;
    }
    memcpy(out + HASH_SIZE + (HASH_SIZE - node.length), node.value, node.length);

    return TRUE;
}


BOOL CTls13::ParseFinished(const UINT8 * msg, SIZE_T & len)
{
    if ( m_phase != ReceivingFinished )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    if ( len < HASH_SIZE )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    len = HASH_SIZE;

    CHmac<HASH_CLASS> hmac;
    UINT8 hash[HASH_SIZE];

    HASH_CLASS sha = m_transHash;
    sha.Finish(hash);
    hmac.Initialize(m_serverFinishedKey, sizeof(m_serverFinishedKey));
    hmac.Update(hash, sizeof(hash));
    hmac.Finish(hash);

    if ( memcmp(msg, hash, sizeof(hash)) != 0 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECRYPT_ERROR);
        return FALSE;
    }

    m_phase = SendingFinished;

    return TRUE;
}


BOOL CTls13::EncryptPacket(UINT8 * msg, SIZE_T len)
{
    UINT8 vec[sizeof(m_clientIV)];

    memcpy(vec, m_clientIV, sizeof(vec));
    for ( INT32 i = 0; i < 8; i++ )
    {
        vec[11 - i] ^= (m_sendSequence >> (i * 8));
    }
    m_sendSequence++;

    switch ( m_cipherSuite )
    {
        case AES128GCM:
        case AES256GCM:
            {
                CAesGcm aes;

                aes.SetKeys(m_clientKey, m_cipherKeySize);
                aes.Init(vec, sizeof(vec), msg, sizeof(RecordHeader));
                msg += sizeof(RecordHeader);
                len -= sizeof(RecordHeader);
                aes.Encrypt(m_buf, msg, len);
                aes.Finalize();
                memcpy(msg, m_buf, len);
                aes.GetTag(&msg[len]);
            }
            break;

        case CHACHA20POLY1305:
            {
                CChacha20Poly1305 chacha;

                chacha.Initialize(m_clientKey, vec);
                chacha.UpdateAad(msg, sizeof(RecordHeader));
                msg += sizeof(RecordHeader);
                len -= sizeof(RecordHeader);
                chacha.Encrypt(m_buf, msg, len);
                memcpy(msg, m_buf, len);
                chacha.Finish(&msg[len]);
            }
            break;

        default:
            SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
            break;
    }

    return TRUE;
}


BOOL CTls13::DecryptPacket(UINT8 * msg, SIZE_T len)
{
    UINT8 vec[sizeof(m_serverIV)];

    memcpy(vec, m_serverIV, sizeof(vec));
    for ( INT32 i = 0; i < 8; i++ )
    {
        vec[11 - i] ^= (m_receiveSequence >> (i * 8));
    }
    m_receiveSequence++;

    BOOL ret = FALSE;

    switch ( m_cipherSuite )
    {
        case AES128GCM:
        case AES256GCM:
            {
                CAesGcm aes;

                aes.SetKeys(m_serverKey, m_cipherKeySize);
                aes.Init(vec, sizeof(vec), msg, sizeof(RecordHeader));
                msg += sizeof(RecordHeader);
                len -= sizeof(RecordHeader) + TAG_SIZE;
                aes.SetTag(&msg[len]);
                if ( len > sizeof(m_buf) )
                {
                    SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
                    return FALSE;
                }
                aes.Decrypt(m_buf, msg, len);
                aes.Finalize();
                memcpy(msg, m_buf, len);
                ret = aes.CheckTag();
            }
            break;

        case CHACHA20POLY1305:
            {
                CChacha20Poly1305 chacha;

                chacha.Initialize(m_serverKey, vec);
                chacha.UpdateAad(msg, sizeof(RecordHeader));
                msg += sizeof(RecordHeader);
                len -= sizeof(RecordHeader) + TAG_SIZE;
                if ( len > sizeof(m_buf) )
                {
                    SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
                    return FALSE;
                }
                ret = chacha.VerifyAndDecrypt(m_buf, msg, len, &msg[len]);
                memcpy(msg, m_buf, len);
            }
            break;

        default:
            SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
            break;
    }

    return ret;
}


BOOL CTls13::PrepareEncryption()
{
    switch ( m_keyExchange )
    {
#if KEY_EXCHANGE_GROUP == 2
        case Secp384r1:
            CEcdh<EcCurve::P384>::GetSharedSecret(m_sharedSecret, m_privateKey, m_serverPublicKey);
            break;
#else
        case Secp256r1:
            CEcdh<EcCurve::P256>::GetSharedSecret(m_sharedSecret, m_privateKey, m_serverPublicKey);
            break;
        case X25519:
            CX25519::GetSharedSecret(m_sharedSecret, m_privateKey, m_serverPublicKey);
            break;
#endif
        default:
            return FALSE;
    }

    UINT8 info[2 + 1 + 20 + 1 + HASH_SIZE];   // length + label_len + label + context_len + context
    UINT8 handshake[HASH_SIZE];
    UINT8 chs[HASH_SIZE];
    UINT8 shs[HASH_SIZE];
    UINT8 trans_hash[HASH_SIZE];
    UINT8 zero_hash[HASH_SIZE];
    UINT8 zero[HASH_SIZE] = { 0 };
    SIZE_T len;

    HASH_CLASS sha = m_transHash;

    sha.Finish(trans_hash);
    sha.Initialize();
    sha.Finish(zero_hash);

    CHkdf<HASH_CLASS> hkdf;

    hkdf.Initialize(zero, sizeof(zero), zero, sizeof(zero));
    len = MakeLabel(info, sizeof(handshake), "derived", zero_hash, sizeof(zero_hash));
    hkdf.DeriveKey(info, len, handshake, sizeof(handshake));

    hkdf.Initialize(handshake, sizeof(handshake), m_sharedSecret, m_privateKeySize);
    len = MakeLabel(info, sizeof(chs), "c hs traffic", trans_hash, sizeof(trans_hash));
    hkdf.DeriveKey(info, len, chs, sizeof(chs));
    len = MakeLabel(info, sizeof(shs), "s hs traffic", trans_hash, sizeof(trans_hash));
    hkdf.DeriveKey(info, len, shs, sizeof(shs));
    len = MakeLabel(info, sizeof(m_derivedSecret), "derived", zero_hash, sizeof(zero_hash));
    hkdf.DeriveKey(info, len, m_derivedSecret, sizeof(m_derivedSecret));

    hkdf.SetPrk(chs);
    len = MakeLabel(info, m_cipherKeySize, "key");
    hkdf.DeriveKey(info, len, m_clientKey, m_cipherKeySize);
    len = MakeLabel(info, sizeof(m_clientIV), "iv");
    hkdf.DeriveKey(info, len, m_clientIV, sizeof(m_clientIV));
    len = MakeLabel(info, sizeof(m_clientFinishedKey), "finished");
    hkdf.DeriveKey(info, len, m_clientFinishedKey, sizeof(m_clientFinishedKey));

    hkdf.SetPrk(shs);
    len = MakeLabel(info, m_cipherKeySize, "key");
    hkdf.DeriveKey(info, len, m_serverKey, m_cipherKeySize);
    len = MakeLabel(info, sizeof(m_serverIV), "iv");
    hkdf.DeriveKey(info, len, m_serverIV, sizeof(m_serverIV));
    len = MakeLabel(info, sizeof(m_serverFinishedKey), "finished");
    hkdf.DeriveKey(info, len, m_serverFinishedKey, sizeof(m_serverFinishedKey));

    m_sendSequence = 0;
    m_receiveSequence = 0;

    return TRUE;
}


VOID CTls13::PrepareEncryption2(const UINT8 * trans_hash)
{
    UINT8 info[2 + 1 + 20 + 1 + HASH_SIZE];   // length + label_len + label + context_len + context
    UINT8 cap[HASH_SIZE];
    UINT8 sap[HASH_SIZE];
    UINT8 zero[HASH_SIZE] = { 0 };
    SIZE_T len;

    CHkdf<HASH_CLASS> hkdf;

    hkdf.Initialize(m_derivedSecret, sizeof(m_derivedSecret), zero, sizeof(zero));
    len = MakeLabel(info, sizeof(cap), "c ap traffic", trans_hash, HASH_SIZE);
    hkdf.DeriveKey(info, len, cap, sizeof(cap));
    len = MakeLabel(info, sizeof(sap), "s ap traffic", trans_hash, HASH_SIZE);
    hkdf.DeriveKey(info, len, sap, sizeof(sap));

    hkdf.SetPrk(cap);
    len = MakeLabel(info, m_cipherKeySize, "key");
    hkdf.DeriveKey(info, len, m_clientKey, m_cipherKeySize);
    len = MakeLabel(info, sizeof(m_clientIV), "iv");
    hkdf.DeriveKey(info, len, m_clientIV, sizeof(m_clientIV));

    hkdf.SetPrk(sap);
    len = MakeLabel(info, m_cipherKeySize, "key");
    hkdf.DeriveKey(info, len, m_serverKey, m_cipherKeySize);
    len = MakeLabel(info, sizeof(m_serverIV), "iv");
    hkdf.DeriveKey(info, len, m_serverIV, sizeof(m_serverIV));

    m_sendSequence = 0;
    m_receiveSequence = 0;
}

SIZE_T CTls13::MakeLabel(UINT8 * out, SIZE_T outlen, const CHAR8 * label, const UINT8 * context, SIZE_T ctxlen)
{
    static const CHAR8 tag[] = "tls13 ";
    SIZE_T i;

    WRITE16(out, outlen);

    for ( i = 0; i < sizeof(tag) - 1; i++ )
    {
        out[i + 3] = tag[i];
    }

    while ( *label )
    {
        out[i + 3] = *label;
        i++;
        label++;
    }
    out[2] = (UINT8)i;

    i += 3;
    SIZE_T j = i++;
    while ( ctxlen > 0 )
    {
        out[i] = *context;
        i++;
        context++;
        ctxlen--;
    }
    out[j] = (UINT8)(i - j - 1);

    return i;
}


BOOL CTls13::ReadAsn1Node(const UINT8 * p, const UINT8 * end, Asn1Node & node)
{
    if ( p + 2 >= end )
    {
        return FALSE;
    }

    node.tag = *p++;

    SIZE_T len = *p++;

    if ( (len & 0x80) != 0 )
    {
        SIZE_T bytes = len & 0x7f;

        if ( p + bytes > end )
        {
            return FALSE;
        }

        len = 0;
        while ( bytes-- )
        {
            len = (len << 8) | *p++;
        }
    }
    node.length = len;

    if ( p + node.length > end )
    {
        return FALSE;
    }

    node.value = p;
    node.next = p + node.length;

    return TRUE;
}

BOOL CTls13::ExtractX509PublicKey(const UINT8 * in, SIZE_T inlen)
{
    static const UINT8 RSA_OID[] =
    {
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
    };
    static const UINT8 ECDSA_OID[] =
    {
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
    };
    static const UINT8 ECDSA256_OID[] =
    {
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };
    static const UINT8 ECDSA384_OID[] =
    {
        0x2b, 0x81, 0x04, 0x00, 0x22
    };
    static const UINT8 ED25519_OID[] =
    {
        0x2b, 0x65, 0x70
    };

    const UINT8 * start = in;
    const UINT8 * end = in + inlen;
    Asn1Node node[5];
    struct {
        const UINT8 * start;
        const UINT8 * end;
        INT32 position;
    } stack[4];
    INT32 depth = 0;
    INT32 childpos = 0;
    BOOL foundkey = FALSE;
    BOOL foundalgo = FALSE;

    for ( ; ; )
    {
        if ( !ReadAsn1Node(start, end, node[depth]) )
        {
            if ( depth <= 1 )   // not found
            {
                return FALSE;
            }
            depth--;
            start = stack[depth].start;
            end = stack[depth].end;
            childpos = stack[depth].position;
            continue;
        }
        childpos++;
        switch ( node[depth].tag )
        {
            case 0x03:  // BIT STRING = pickup public key
                if ( depth == 3 && childpos == 2 &&
                     stack[1].position == 1 && stack[0].position == 1 )
                {
                    if ( foundalgo )
                    {
                        switch ( m_certAlgorithm )
                        {
                            case RSA:
                                if ( ExtractRsaPublicKey(node[depth].value, node[depth].length) )
                                {
                                    return TRUE;
                                }
                                break;

                            case ECDSA256:
                            case ECDSA384:
                                if ( ExtractEcdsaPublicKey(node[depth].value, node[depth].length) )
                                {
                                    return TRUE;
                                }
                                break;

                            case ED25519:
                                if ( ExtractEd25519PublicKey(node[depth].value, node[depth].length) )
                                {
                                    return TRUE;
                                }
                                break;

                            default:
                                break;
                        }
                    }
                    return FALSE;
                }
                start = node[depth].next;
                break;

            case 0x06:  // OID = signature algorithm
                if ( depth == 4 &&
                     (stack[2].position == 6 || stack[2].position == 7) &&
                     stack[1].position == 1 && stack[0].position == 1 )
                {
                    if ( childpos == 1 )
                    {
                        if ( memcmp(node[depth].value, RSA_OID, node[depth].length) == 0 )
                        {
                            m_certAlgorithm = RSA;
                            foundalgo = TRUE;
                        }
                        else if ( memcmp(node[depth].value, ECDSA_OID, node[depth].length) == 0 )
                        {
                            m_certAlgorithm = ECDSA256;
                        }
                        else if ( memcmp(node[depth].value, ED25519_OID, node[depth].length) == 0 )
                        {
                            m_certAlgorithm = ED25519;
                            foundalgo = TRUE;
                        }
                        if ( foundkey && foundalgo )
                        {
                            return TRUE;
                        }
                    }
                    else if ( childpos == 2 && m_certAlgorithm == ECDSA256 )
                    {
                        if ( memcmp(node[depth].value, ECDSA256_OID, node[depth].length) == 0 )
                        {
                            foundalgo = TRUE;
                        }
                        else if ( memcmp(node[depth].value, ECDSA384_OID, node[depth].length) == 0 )
                        {
                            m_certAlgorithm = ECDSA384;
                            foundalgo = TRUE;
                        }
                        if ( foundkey && foundalgo )
                        {
                            return TRUE;
                        }
                    }
                }
                start = node[depth].next;
                break;

            case 0x30:
                if ( depth < 5 )
                {
                    stack[depth].start = node[depth].next;
                    stack[depth].end = end;
                    stack[depth].position = childpos;
                    start = node[depth].value;
                    end = node[depth].next;
                    childpos = 0;
                    depth++;
                }
                else
                {
                    start = node[depth].next;
                }
                break;

            default:
                start = node[depth].next;
                break;
        }
    }
}

BOOL CTls13::ExtractRsaPublicKey(const UINT8 * p, SIZE_T len)
{
    Asn1Node node1;
    Asn1Node node2;

    p++; len--; // skip first one byte

    if ( !ReadAsn1Node(p, p + len, node1) ||
         node1.tag != 0x30 ||
         node1.next > p + len )
    {
        return FALSE;
    }
    if ( !ReadAsn1Node(node1.value, node1.next, node2) ||
         node2.tag != 0x02 ||
         node2.next > node1.next )
    {
        return FALSE;
    }
    if ( node2.value[0] == 0x00 )
    {
        node2.value++;
        node2.length--;
    }
    if ( node2.length > sizeof(m_certPublicKey1) )
    {
        return FALSE;
    }
    memcpy(m_certPublicKey1, node2.value, node2.length);
    m_certKeyLength1 = node2.length;

    if ( !ReadAsn1Node(node2.next, node1.next, node2) ||
         node2.tag != 0x02 ||
         node2.next > node1.next )
    {
        return FALSE;
    }
    if ( node2.value[0] == 0x00 )
    {
        node2.value++;
        node2.length--;
    }
    if ( node2.length > sizeof(m_certPublicKey2) )
    {
        return FALSE;
    }

    memcpy(m_certPublicKey2, node2.value, node2.length);
    m_certKeyLength2 = node2.length;

    return TRUE;
}

BOOL CTls13::ExtractEcdsaPublicKey(const UINT8 * p, SIZE_T len)
{
    p++; len--; // skip first one byte

    if ( *p != 0x04 )
    {
        return FALSE;
    }
    p++; len--; // skip 0x04
    len /= 2;
    if ( len > MIN(sizeof(m_certPublicKey1), sizeof(m_certPublicKey2)) )
    {
        return FALSE;
    }
    memcpy(m_certPublicKey1, p, len);
    m_certKeyLength1 = len;
    memcpy(m_certPublicKey2, p + len, len);
    m_certKeyLength2 = len;

    return TRUE;
}

BOOL CTls13::ExtractEd25519PublicKey(const UINT8 * p, SIZE_T len)
{
    p++; len--; // skip first one byte

    if ( len > sizeof(m_certPublicKey1) )
    {
        return FALSE;
    }
    memcpy(m_certPublicKey1, p, len);
    m_certKeyLength1 = len;

    return TRUE;
}

