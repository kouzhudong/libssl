#pragma once

#include "pch.h"


#ifndef ALGIDDEF
#define ALGIDDEF
typedef unsigned int ALG_ID;
#endif


typedef struct _SCHANNEL_CRED {
    DWORD           dwVersion;      // always SCHANNEL_CRED_VERSION
    DWORD           cCreds;
    //PCCERT_CONTEXT *paCred;
    PVOID           paCred;
    //HCERTSTORE      hRootStore;
    PVOID           hRootStore;

    DWORD           cMappers;
    struct _HMAPPER ** aphMappers;

    DWORD           cSupportedAlgs;
    ALG_ID * palgSupportedAlgs;

    DWORD           grbitEnabledProtocols;
    DWORD           dwMinimumCipherStrength;
    DWORD           dwMaximumCipherStrength;
    DWORD           dwSessionLifespan;
    DWORD           dwFlags;
    DWORD           dwCredFormat;
} SCHANNEL_CRED, * PSCHANNEL_CRED;

typedef enum _eTlsAlgorithmUsage {
    TlsParametersCngAlgUsageKeyExchange,          // Key exchange algorithm. RSA, ECHDE, DHE, etc.
    TlsParametersCngAlgUsageSignature,            // Signature algorithm. RSA, DSA, ECDSA, etc.
    TlsParametersCngAlgUsageCipher,               // Encryption algorithm. AES, DES, RC4, etc.
    TlsParametersCngAlgUsageDigest,               // Digest of cipher suite. SHA1, SHA256, SHA384, etc.
    TlsParametersCngAlgUsageCertSig               // Signature and/or hash used to sign certificate. RSA, DSA, ECDSA, SHA1, SHA256, etc.
} eTlsAlgorithmUsage;

// SCH_CREDENTIALS structures
typedef struct _CRYPTO_SETTINGS {
    eTlsAlgorithmUsage  eAlgorithmUsage;         // How this algorithm is being used.
    UNICODE_STRING      strCngAlgId;             // CNG algorithm identifier.
    DWORD               cChainingModes;          // Set to 0 if CNG algorithm does not have a chaining mode.
    PUNICODE_STRING     rgstrChainingModes;      // Set to NULL if CNG algorithm does not have a chaining mode.
    DWORD               dwMinBitLength;          // Blacklist key sizes less than this. Set to 0 if not defined or CNG algorithm implies bit length.
    DWORD               dwMaxBitLength;          // Blacklist key sizes greater than this. Set to 0 if not defined or CNG algorithm implies bit length.
} CRYPTO_SETTINGS, * PCRYPTO_SETTINGS;

typedef struct _TLS_PARAMETERS {
    DWORD               cAlpnIds;                // Valid for server applications only. Must be zero otherwise. Number of ALPN IDs in rgstrAlpnIds; set to 0 if applies to all.
    PUNICODE_STRING     rgstrAlpnIds;            // Valid for server applications only. Must be NULL otherwise. Array of ALPN IDs that the following settings apply to; set to NULL if applies to all.
    DWORD               grbitDisabledProtocols;  // List protocols you DO NOT want negotiated.
    DWORD               cDisabledCrypto;         // Number of CRYPTO_SETTINGS structures; set to 0 if there are none.
    PCRYPTO_SETTINGS    pDisabledCrypto;         // Array of CRYPTO_SETTINGS structures; set to NULL if there are none;
    DWORD               dwFlags;                 // Optional flags to pass; set to 0 if there are none.
} TLS_PARAMETERS, * PTLS_PARAMETERS;

#define TLS_PARAMS_OPTIONAL 0x00000001           // Valid for server applications only. Must be zero otherwise.
// TLS_PARAMETERS that will only be honored if they do not cause this server to terminate the handshake.

typedef struct _SCH_CREDENTIALS {
    DWORD               dwVersion;               // Always SCH_CREDENTIALS_VERSION.
    DWORD               dwCredFormat;
    DWORD               cCreds;
    //PCCERT_CONTEXT     *paCred;
    PVOID * paCred;
    //HCERTSTORE          hRootStore;
    PVOID               hRootStore;

    DWORD               cMappers;
    struct _HMAPPER ** aphMappers;

    DWORD               dwSessionLifespan;
    DWORD               dwFlags;
    DWORD               cTlsParameters;
    PTLS_PARAMETERS     pTlsParameters;
} SCH_CREDENTIALS, * PSCH_CREDENTIALS;


#define KPH_PROTECTED_DATA_SECTION_PUSH() \
    __pragma(data_seg(push))\
    __pragma(data_seg("KSIDATA"))
#define KPH_PROTECTED_DATA_SECTION_POP() \
    __pragma(data_seg(pop))
#define KPH_PROTECTED_DATA_SECTION_RO_PUSH() \
    __pragma(const_seg(push))\
    __pragma(const_seg("KSIRO"))
#define KPH_PROTECTED_DATA_SECTION_RO_POP() \
    __pragma(const_seg(pop))

#define SCHANNEL_NAME_A  "Schannel"
#define SCHANNEL_NAME_W  L"Schannel"

#define KphTracePrint 

#define SCHANNEL_RENEGOTIATE    0   // renegotiate a connection
#define SCHANNEL_SHUTDOWN       1   // gracefully close down a connection
#define SCHANNEL_ALERT          2   // build an error message
#define SCHANNEL_SESSION        3   // session control


typedef PVOID KPH_TLS_HANDLE;
typedef PVOID * PKPH_TLS_HANDLE;


#define SCH_CRED_NO_SYSTEM_MAPPER                    0x00000002
#define SCH_CRED_NO_SERVERNAME_CHECK                 0x00000004
#define SCH_CRED_MANUAL_CRED_VALIDATION              0x00000008
#define SCH_CRED_NO_DEFAULT_CREDS                    0x00000010
#define SCH_CRED_AUTO_CRED_VALIDATION                0x00000020
#define SCH_CRED_USE_DEFAULT_CREDS                   0x00000040
#define SCH_CRED_DISABLE_RECONNECTS                  0x00000080

#define SCH_CRED_REVOCATION_CHECK_END_CERT           0x00000100
#define SCH_CRED_REVOCATION_CHECK_CHAIN              0x00000200
#define SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT 0x00000400
#define SCH_CRED_IGNORE_NO_REVOCATION_CHECK          0x00000800
#define SCH_CRED_IGNORE_REVOCATION_OFFLINE           0x00001000

#define SCH_CRED_RESTRICTED_ROOTS                    0x00002000
#define SCH_CRED_REVOCATION_CHECK_CACHE_ONLY         0x00004000
#define SCH_CRED_CACHE_ONLY_URL_RETRIEVAL            0x00008000

#define SCH_CRED_MEMORY_STORE_CERT                   0x00010000

#define SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE  0x00020000

#define SCH_SEND_ROOT_CERT                           0x00040000
#define SCH_CRED_SNI_CREDENTIAL                      0x00080000
#define SCH_CRED_SNI_ENABLE_OCSP                     0x00100000
#define SCH_SEND_AUX_RECORD                          0x00200000
#define SCH_USE_STRONG_CRYPTO                        0x00400000
#define SCH_USE_PRESHAREDKEY_ONLY                    0x00800000
#define SCH_USE_DTLS_ONLY                            0x01000000
#define SCH_ALLOW_NULL_ENCRYPTION                    0x02000000

#define SCHANNEL_RENEGOTIATE    0   // renegotiate a connection
#define SCHANNEL_SHUTDOWN       1   // gracefully close down a connection
#define SCHANNEL_ALERT          2   // build an error message
#define SCHANNEL_SESSION        3   // session control

#define SCH_CRED_V1              0x00000001
#define SCH_CRED_V2              0x00000002  // for legacy code
#define SCH_CRED_VERSION         0x00000002  // for legacy code
#define SCH_CRED_V3              0x00000003  // for legacy code
#define SCHANNEL_CRED_VERSION    0x00000004  // for legacy code
#define SCH_CREDENTIALS_VERSION  0x00000005


#define SP_PROT_PCT1_SERVER             0x00000001
#define SP_PROT_PCT1_CLIENT             0x00000002
#define SP_PROT_PCT1                    (SP_PROT_PCT1_SERVER | SP_PROT_PCT1_CLIENT)

#define SP_PROT_SSL2_SERVER             0x00000004
#define SP_PROT_SSL2_CLIENT             0x00000008
#define SP_PROT_SSL2                    (SP_PROT_SSL2_SERVER | SP_PROT_SSL2_CLIENT)

#define SP_PROT_SSL3_SERVER             0x00000010
#define SP_PROT_SSL3_CLIENT             0x00000020
#define SP_PROT_SSL3                    (SP_PROT_SSL3_SERVER | SP_PROT_SSL3_CLIENT)

#define SP_PROT_TLS1_SERVER             0x00000040
#define SP_PROT_TLS1_CLIENT             0x00000080
#define SP_PROT_TLS1                    (SP_PROT_TLS1_SERVER | SP_PROT_TLS1_CLIENT)

#define SP_PROT_SSL3TLS1_CLIENTS        (SP_PROT_TLS1_CLIENT | SP_PROT_SSL3_CLIENT)
#define SP_PROT_SSL3TLS1_SERVERS        (SP_PROT_TLS1_SERVER | SP_PROT_SSL3_SERVER)
#define SP_PROT_SSL3TLS1                (SP_PROT_SSL3 | SP_PROT_TLS1)

#define SP_PROT_UNI_SERVER              0x40000000
#define SP_PROT_UNI_CLIENT              0x80000000
#define SP_PROT_UNI                     (SP_PROT_UNI_SERVER | SP_PROT_UNI_CLIENT)

#define SP_PROT_ALL                     0xffffffff
#define SP_PROT_NONE                    0
#define SP_PROT_CLIENTS                 (SP_PROT_PCT1_CLIENT | SP_PROT_SSL2_CLIENT | SP_PROT_SSL3_CLIENT | SP_PROT_UNI_CLIENT | SP_PROT_TLS1_CLIENT)
#define SP_PROT_SERVERS                 (SP_PROT_PCT1_SERVER | SP_PROT_SSL2_SERVER | SP_PROT_SSL3_SERVER | SP_PROT_UNI_SERVER | SP_PROT_TLS1_SERVER)


#define SP_PROT_TLS1_0_SERVER           SP_PROT_TLS1_SERVER
#define SP_PROT_TLS1_0_CLIENT           SP_PROT_TLS1_CLIENT
#define SP_PROT_TLS1_0                  (SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_0_CLIENT)

#define SP_PROT_TLS1_1_SERVER           0x00000100
#define SP_PROT_TLS1_1_CLIENT           0x00000200
#define SP_PROT_TLS1_1                  (SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_1_CLIENT)

#define SP_PROT_TLS1_2_SERVER           0x00000400
#define SP_PROT_TLS1_2_CLIENT           0x00000800
#define SP_PROT_TLS1_2                  (SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT)

#define SP_PROT_TLS1_3_SERVER           0x00001000
#define SP_PROT_TLS1_3_CLIENT           0x00002000
#define SP_PROT_TLS1_3                  (SP_PROT_TLS1_3_SERVER | SP_PROT_TLS1_3_CLIENT)

#define SP_PROT_DTLS_SERVER             0x00010000
#define SP_PROT_DTLS_CLIENT             0x00020000
#define SP_PROT_DTLS                    (SP_PROT_DTLS_SERVER | SP_PROT_DTLS_CLIENT )

#define SP_PROT_DTLS1_0_SERVER          SP_PROT_DTLS_SERVER
#define SP_PROT_DTLS1_0_CLIENT          SP_PROT_DTLS_CLIENT
#define SP_PROT_DTLS1_0                 (SP_PROT_DTLS1_0_SERVER | SP_PROT_DTLS1_0_CLIENT)

#define SP_PROT_DTLS1_2_SERVER          0x00040000
#define SP_PROT_DTLS1_2_CLIENT          0x00080000
#define SP_PROT_DTLS1_2                 (SP_PROT_DTLS1_2_SERVER | SP_PROT_DTLS1_2_CLIENT)

#define SP_PROT_DTLS1_X_SERVER          (SP_PROT_DTLS1_0_SERVER | SP_PROT_DTLS1_2_SERVER)
#define SP_PROT_DTLS1_X_CLIENT          (SP_PROT_DTLS1_0_CLIENT | SP_PROT_DTLS1_2_CLIENT)
#define SP_PROT_DTLS1_X                 (SP_PROT_DTLS1_X_SERVER | SP_PROT_DTLS1_X_CLIENT)

#define SP_PROT_TLS1_1PLUS_SERVER       (SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER)
#define SP_PROT_TLS1_1PLUS_CLIENT       (SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT)

#define SP_PROT_TLS1_1PLUS              (SP_PROT_TLS1_1PLUS_SERVER | SP_PROT_TLS1_1PLUS_CLIENT)

#define SP_PROT_TLS1_3PLUS_SERVER       SP_PROT_TLS1_3_SERVER
#define SP_PROT_TLS1_3PLUS_CLIENT       SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3PLUS              (SP_PROT_TLS1_3PLUS_SERVER | SP_PROT_TLS1_3PLUS_CLIENT)

#define SP_PROT_TLS1_X_SERVER           (SP_PROT_TLS1_0_SERVER | \
                                         SP_PROT_TLS1_1_SERVER | \
                                         SP_PROT_TLS1_2_SERVER | \
                                         SP_PROT_TLS1_3_SERVER)
#define SP_PROT_TLS1_X_CLIENT           (SP_PROT_TLS1_0_CLIENT | \
                                         SP_PROT_TLS1_1_CLIENT | \
                                         SP_PROT_TLS1_2_CLIENT | \
                                         SP_PROT_TLS1_3_CLIENT)
#define SP_PROT_TLS1_X                  (SP_PROT_TLS1_X_SERVER | SP_PROT_TLS1_X_CLIENT)

#define SP_PROT_SSL3TLS1_X_CLIENTS      (SP_PROT_TLS1_X_CLIENT | SP_PROT_SSL3_CLIENT)
#define SP_PROT_SSL3TLS1_X_SERVERS      (SP_PROT_TLS1_X_SERVER | SP_PROT_SSL3_SERVER)
#define SP_PROT_SSL3TLS1_X              (SP_PROT_SSL3 | SP_PROT_TLS1_X)

#define SP_PROT_X_CLIENTS               (SP_PROT_CLIENTS | SP_PROT_TLS1_X_CLIENT | SP_PROT_DTLS1_X_CLIENT )
#define SP_PROT_X_SERVERS               (SP_PROT_SERVERS | SP_PROT_TLS1_X_SERVER | SP_PROT_DTLS1_X_SERVER )

#define PAGED_FILE() \
    __pragma(bss_seg("PAGEBBS"))\
    __pragma(code_seg("PAGE"))\
    __pragma(data_seg("PAGEDATA"))\
    __pragma(const_seg("PAGERO"))


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _KPH_TLS_RECV {
    ULONG Received;
    ULONG Used;
    ULONG Available;
    PVOID Decrypted;
} KPH_TLS_RECV, * PKPH_TLS_RECV;

typedef struct _KPH_TLS {
    CredHandle CredentialsHandle;
    CtxtHandle ContextHandle;
    SecPkgContext_StreamSizes StreamSizes;
    PVOID Buffer;
    ULONG Length;
    KPH_TLS_RECV Recv;
} KPH_TLS, * PKPH_TLS;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern PSecurityFunctionTableW KphpSecFnTable;


EXTERN_C_START


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketTlsCreate(_Outptr_allocatesMem_ PKPH_TLS_HANDLE Tls);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketTlsHandshake(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ KPH_TLS_HANDLE Tls,
    _In_ PUNICODE_STRING TargetName
);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketTlsSend(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ KPH_TLS_HANDLE Tls,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketTlsRecv(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ KPH_TLS_HANDLE Tls,
    _Out_writes_bytes_to_(*Length, *Length) PVOID Buffer,
    _Inout_ PULONG Length
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphSocketTlsShutdown(_In_ KPH_SOCKET_HANDLE Socket, _In_ KPH_TLS_HANDLE Tls);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphSocketTlsClose(_In_freesMem_ KPH_TLS_HANDLE Tls);


EXTERN_C_END
