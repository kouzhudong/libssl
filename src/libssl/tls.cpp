//SHA-1: a3c639140649dec395d150a1bb54205f7bb93970

#include "socket.h"
#include "tls.h"


KPH_PROTECTED_DATA_SECTION_PUSH();
// Not all the functions we need are exported, however they should all be available through the dispatch table.
PSecurityFunctionTableW KphpSecFnTable = NULL;
KPH_PROTECTED_DATA_SECTION_POP();


//////////////////////////////////////////////////////////////////////////////////////////////////


PAGED_FILE();


_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS KphpSecStatusToNtStatus(_In_ SECURITY_STATUS SecStatus)
/**
 * \brief Converts a SECURITY_STATUS (HRESULT) code to an NTSTATUS code.
 *
 * \param[in] SecStatus The SECURITY_STATUS code to convert.
 *
 * \return STATUS_SUCCESS if SecStatus is SEC_E_OK. Otherwise, an errant status.
 */
{
    PAGED_CODE_PASSIVE();

    switch (SecStatus) {
        // N.B. Should always return errant NTSTATUS except for SEC_E_OK.
    case SEC_E_OK:
    {
        return STATUS_SUCCESS;
    }
    case SEC_E_INSUFFICIENT_MEMORY:
    case SEC_E_EXT_BUFFER_TOO_SMALL:
    case SEC_E_INSUFFICIENT_BUFFERS:
    case SEC_E_BUFFER_TOO_SMALL:
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    case SEC_E_INVALID_PARAMETER:
    {
        return STATUS_INVALID_PARAMETER;
    }
    case SEC_E_INVALID_HANDLE:
    case SEC_E_WRONG_CREDENTIAL_HANDLE:
    {
        return STATUS_INVALID_HANDLE;
    }
    case SEC_E_QOP_NOT_SUPPORTED:
    case SEC_E_UNSUPPORTED_FUNCTION:
    {
        return STATUS_NOT_SUPPORTED;
    }
    case SEC_E_TARGET_UNKNOWN:
    case SEC_E_SECPKG_NOT_FOUND:
    {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    case SEC_E_INTERNAL_ERROR:
    {
        return STATUS_INTERNAL_ERROR;
    }
    case SEC_E_KDC_CERT_EXPIRED:
    case SEC_E_CERT_EXPIRED:
    {
        return STATUS_KDC_CERT_EXPIRED;
    }
    case SEC_E_KDC_CERT_REVOKED:
    {
        return STATUS_KDC_CERT_REVOKED;
    }
    case SEC_E_CERT_UNKNOWN:
    case SEC_E_UNTRUSTED_ROOT:
    case SEC_E_CERT_WRONG_USAGE:
    case SEC_E_WRONG_PRINCIPAL:
    case SEC_E_ISSUING_CA_UNTRUSTED:
    case SEC_E_ISSUING_CA_UNTRUSTED_KDC:
    case SEC_E_NO_AUTHENTICATING_AUTHORITY:
    case SEC_E_NO_KERB_KEY:
    {
        return STATUS_ISSUING_CA_UNTRUSTED;
    }
    case SEC_E_LOGON_DENIED:
    case SEC_E_NO_CREDENTIALS:
    case SEC_E_NOT_OWNER:
    {
        return STATUS_ACCESS_DENIED;
    }
    case SEC_I_CONTEXT_EXPIRED: // server closed the TLS connection
    case SEC_I_RENEGOTIATE:     // we don't support TLS renegotiation
    {
        return STATUS_PORT_DISCONNECTED;
    }
    case SEC_E_DECRYPT_FAILURE:
    {
        return STATUS_DECRYPTION_FAILED;
    }
    case SEC_E_ENCRYPT_FAILURE:
    {
        return STATUS_ENCRYPTION_FAILED;
    }
    case SEC_E_OUT_OF_SEQUENCE:
    {
        return STATUS_REQUEST_OUT_OF_SEQUENCE;
    }
    case SEC_E_INCOMPLETE_MESSAGE:
    {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    case E_NOINTERFACE: // missing KphpSecFnTable or dispatch function
    {
        return STATUS_NOINTERFACE;
    }
    default:
    {
        // All other codes are normalized to a generic error.
        NT_ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }
    }
}


_Function_class_(ACQUIRE_CREDENTIALS_HANDLE_FN_W)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
_Must_inspect_result_
SECURITY_STATUS KphpSecAcquireCredentialsHandle(
    _In_opt_ PSECURITY_STRING Principal,
    _In_ PSECURITY_STRING Package,
    _In_ ULONG CredentialUse,
    _In_opt_ PVOID LogonId,
    _In_opt_ PVOID AuthData,
    _In_opt_ SEC_GET_KEY_FN GetKeyFn,
    _In_opt_ PVOID GetKeyArgument,
    _Out_ PCredHandle Credential,
    _Out_opt_ PTimeStamp Expiry
)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

    if (!KphpSecFnTable || !KphpSecFnTable->AcquireCredentialsHandleW) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->AcquireCredentialsHandleW(Principal,
                                                     Package,
                                                     CredentialUse,
                                                     LogonId,
                                                     AuthData,
                                                     GetKeyFn,
                                                     GetKeyArgument,
                                                     Credential,
                                                     Expiry);
}


_Function_class_(DELETE_SECURITY_CONTEXT_FN)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
SECURITY_STATUS KphpSecDeleteSecurityContext(_In_ PCtxtHandle Context)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);
    NT_ASSERT(SecIsValidHandle(Context));

    if (!KphpSecFnTable || !KphpSecFnTable->DeleteSecurityContext) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->DeleteSecurityContext(Context);
}


_Function_class_(FREE_CONTEXT_BUFFER_FN)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
SECURITY_STATUS KphpSecFreeContextBuffer(_Inout_ PVOID ContextBuffer)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

    if (!KphpSecFnTable || !KphpSecFnTable->FreeContextBuffer) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->FreeContextBuffer(ContextBuffer);
}


_Function_class_(FREE_CREDENTIALS_HANDLE_FN)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
SECURITY_STATUS KphpSecFreeCredentialsHandle(_In_ PCredHandle Credential)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);
    NT_ASSERT(SecIsValidHandle(Credential));

    if (!KphpSecFnTable || !KphpSecFnTable->FreeCredentialsHandle) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->FreeCredentialsHandle(Credential);
}


_Function_class_(INITIALIZE_SECURITY_CONTEXT_FN_W)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
_Must_inspect_result_
SECURITY_STATUS KphpSecInitializeSecurityContext(
    _In_opt_ PCredHandle Credential,
    _In_opt_ PCtxtHandle Context,
    _In_opt_ PSECURITY_STRING TargetName,
    _In_ ULONG ContextReq,
    _In_ ULONG Reserved1,
    _In_ ULONG TargetDataRep,
    _In_opt_ PSecBufferDesc Input,
    _In_ ULONG Reserved2,
    _Inout_opt_ PCtxtHandle NewContext,
    _Inout_opt_ PSecBufferDesc Output,
    _Out_ PULONG ContextAttr,
    _Out_opt_ PTimeStamp Expiry
)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

    if (!KphpSecFnTable || !KphpSecFnTable->InitializeSecurityContextW) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->InitializeSecurityContextW(Credential,
                                                      Context,
                                                      TargetName,
                                                      ContextReq,
                                                      Reserved1,
                                                      TargetDataRep,
                                                      Input,
                                                      Reserved2,
                                                      NewContext,
                                                      Output,
                                                      ContextAttr,
                                                      Expiry);
}


_Function_class_(QUERY_CONTEXT_ATTRIBUTES_FN_W)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
_Must_inspect_result_
SECURITY_STATUS KphpSecQueryContextAttributes(_In_ PCtxtHandle Context, _In_ ULONG Attribute, _Out_ PVOID Buffer)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

    if (!KphpSecFnTable || !KphpSecFnTable->QueryContextAttributesW) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->QueryContextAttributesW(Context, Attribute, Buffer);
}


_Function_class_(ENCRYPT_MESSAGE_FN)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
_Must_inspect_result_
SECURITY_STATUS KphpSecEncryptMessage(
    _In_ PCtxtHandle Context,
    _In_ ULONG QOP,
    _In_ PSecBufferDesc Message,
    _In_ ULONG MessageSeqNo
)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

    if (!KphpSecFnTable || !KphpSecFnTable->EncryptMessage) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->EncryptMessage(Context, QOP, Message, MessageSeqNo);
}


_Function_class_(DECRYPT_MESSAGE_FN)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
_Must_inspect_result_
SECURITY_STATUS KphpSecDecryptMessage(
    _In_ PCtxtHandle Context,
    _In_ PSecBufferDesc Message,
    _In_ ULONG MessageSeqNo,
    _Out_opt_ PULONG QOP
)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

    if (!KphpSecFnTable || !KphpSecFnTable->DecryptMessage) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->DecryptMessage(Context, Message, MessageSeqNo, QOP);
}


_Function_class_(APPLY_CONTROL_TOKEN_FN)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return == SEC_E_OK)
_Must_inspect_result_
SECURITY_STATUS KphpSecApplyControlToken(_In_ PCtxtHandle Context, _In_ PSecBufferDesc Input)
{
    PAGED_CODE_PASSIVE();

    NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

    if (!KphpSecFnTable || !KphpSecFnTable->ApplyControlToken) {
        return E_NOINTERFACE;
    }

    return KphpSecFnTable->ApplyControlToken(Context, Input);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphSocketTlsClose(_In_freesMem_ KPH_TLS_HANDLE Tls)
/**
 * \brief Closes a TLS object.
 *
 * \param[in] Tls Handle to a TLS object to close.
 */
{
    PKPH_TLS tls;
    KAPC_STATE apcState;

    PAGED_CODE_PASSIVE();

    KeStackAttachProcess(PsInitialSystemProcess, &apcState);

    tls = (PKPH_TLS)Tls;

    NT_ASSERT(SecIsValidHandle(&tls->CredentialsHandle));
    NT_ASSERT(!SecIsValidHandle(&tls->ContextHandle));

    KphpSecFreeCredentialsHandle(&tls->CredentialsHandle);

    if (tls->Buffer) {
        KphFree(tls->Buffer, KPH_TAG_TLS_BUFFER);
    }

    KphFree(tls, KPH_TAG_TLS);

    KeUnstackDetachProcess(&apcState);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketTlsCreate(_Outptr_allocatesMem_ PKPH_TLS_HANDLE Tls)
/**
 * \brief Creates a TLS object.
 *
 * \details The TLS handle should be closed using KphSocketTlsClose.
 *
 * \param[out] Tls On success, receives a handle to the TLS object.
 *
 * \return Successful or errant status.
 */
{
    NTSTATUS status;
    SECURITY_STATUS secStatus;
    KAPC_STATE apcState;
    PKPH_TLS tls;
    SCH_CREDENTIALS credentials;
    TLS_PARAMETERS tlsParameters[1];
    UNICODE_STRING KphpSecurityPackageName = RTL_CONSTANT_STRING(SCHANNEL_NAME_W);

    PAGED_CODE_PASSIVE();

    *Tls = NULL;

    KeStackAttachProcess(PsInitialSystemProcess, &apcState);

    tls = (PKPH_TLS)KphAllocatePaged(sizeof(KPH_TLS), KPH_TAG_TLS);
    if (!tls) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    SecInvalidateHandle(&tls->CredentialsHandle);
    SecInvalidateHandle(&tls->ContextHandle);

    RtlZeroMemory(&credentials, sizeof(credentials));
    RtlZeroMemory(&tlsParameters, sizeof(tlsParameters));

    credentials.dwVersion = SCH_CREDENTIALS_VERSION;
    credentials.dwFlags = (
        SCH_USE_STRONG_CRYPTO | SCH_CRED_AUTO_CRED_VALIDATION |
        SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_REVOCATION_CHECK_CHAIN);
    credentials.cTlsParameters = ARRAYSIZE(tlsParameters);
    credentials.pTlsParameters = tlsParameters;
    // TODO(jxy-s) look into testing and supporting TLS 1.3
    tlsParameters[0].grbitDisabledProtocols = (ULONG)~SP_PROT_TLS1_2;

    secStatus = KphpSecAcquireCredentialsHandle(NULL,
                                                &KphpSecurityPackageName,
                                                SECPKG_CRED_OUTBOUND,
                                                NULL,
                                                &credentials,
                                                NULL,
                                                NULL,
                                                &tls->CredentialsHandle,
                                                NULL);
    if (secStatus != SEC_E_OK) {
        status = KphpSecStatusToNtStatus(secStatus);
        NT_ASSERT(!NT_SUCCESS(status));
        goto Exit;
    }

    *Tls = tls;
    tls = NULL;
    status = STATUS_SUCCESS;

Exit:
    if (tls) {
        if (SecIsValidHandle(&tls->CredentialsHandle)) {
            KphpSecFreeCredentialsHandle(&tls->CredentialsHandle);
        }

        KphFree(tls, KPH_TAG_TLS);
    }

    KeUnstackDetachProcess(&apcState);

    return status;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphpSocketTlsReallocateBuffer(_Inout_ PKPH_TLS Tls, _In_ ULONG Length)
/**
 * \brief Reallocates the buffer used by a TLS object.
 *
 * \param[in,out] Tls The object to reallocate the buffer of.
 * \param[in] Length The requested new length of the buffer.
 *
 * \return Successful or error status.
 */
{
    PVOID buffer;

    PAGED_CODE_PASSIVE();

    if (Tls->Length >= Length) {
        return STATUS_SUCCESS;
    }

    if (Length > MAXUSHORT) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    buffer = KphAllocatePaged(Length, KPH_TAG_TLS_BUFFER);
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (Tls->Buffer) {
        RtlCopyMemory(buffer, Tls->Buffer, Tls->Length);
        KphFree(Tls->Buffer, KPH_TAG_TLS_BUFFER);
    }

    Tls->Buffer = buffer;
    Tls->Length = Length;

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphpSocketTlsHandshakeFinalize(_Inout_ PKPH_TLS Tls)
/**
 * \brief Finalizes the TLS handshake.
 *
 * \details This must be called after the handshake completes successfully.
 *
 * \param[in] Tls The TLS object to finalize the handshake of.
 *
 * \return Successful or error status.
 */
{
    NTSTATUS status;
    SECURITY_STATUS secStatus;
    ULONG length;

    PAGED_CODE_PASSIVE();

    secStatus = KphpSecQueryContextAttributes(&Tls->ContextHandle, SECPKG_ATTR_STREAM_SIZES, &Tls->StreamSizes);
    if (secStatus != SEC_E_OK) {
        status = KphpSecStatusToNtStatus(secStatus);
        NT_ASSERT(!NT_SUCCESS(status));
        goto Exit;
    }

    length = 0;

    status = RtlULongAdd(length, Tls->StreamSizes.cbHeader, &length);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = RtlULongAdd(length, Tls->StreamSizes.cbMaximumMessage, &length);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = RtlULongAdd(length, Tls->StreamSizes.cbTrailer, &length);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = KphpSocketTlsReallocateBuffer(Tls, length);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

Exit:

    return status;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphpSocketTlsHandshakeExtra(_Inout_ PKPH_TLS Tls, _In_ PSecBuffer Extra, _Inout_ PULONG Received)
/**
 * \brief Processes extra buffers during the TSL handshake.
 *
 * \details There are a few cases where this can happen:
 * 1. A connection is being renegotiated (we don't support this). Include the
 *    information to be processed immediately regardless.
 * 2. We are negotiating a connection and this extra data is part of the
 *    handshake, usually due to the initial buffer being insufficient.
 *    Downstream we will reallocate as necessary.
 * Regardless, this prepares the state during the handshake by moving the extra data to the front of the buffer.
 *
 * \param[in,out] Tls The TLS object to process extra data for.
 * \param[in] Extra The extra data to process.
 * \param[in,out] Received On input, the amount of data already received during the handshake.
 * On output, the amount of extra data that needs processed.
 *
 * \return Successful or errant status.
 */
{
    NTSTATUS status;
    ULONG offset;
    ULONG end;

    PAGED_CODE_PASSIVE();

    NT_ASSERT(Extra->BufferType == SECBUFFER_EXTRA);

    status = RtlULongSub(*Received, Extra->cbBuffer, &offset);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (offset == 0) {
        // No need to move data if the extra data is at the front.
        *Received = Extra->cbBuffer;
        status = STATUS_SUCCESS;
        goto Exit;
    }

    status = RtlULongAdd(offset, Extra->cbBuffer, &end);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (end > Tls->Length) {
        status = STATUS_BUFFER_OVERFLOW;
        goto Exit;
    }

    RtlMoveMemory(Tls->Buffer, Add2Ptr(Tls->Buffer, offset), Extra->cbBuffer);
    *Received = Extra->cbBuffer;
    status = STATUS_SUCCESS;

Exit:

    return status;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphpSocketTlsHandshakeRecv(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Inout_ PKPH_TLS Tls,
    _Inout_ PULONG Received
)
/**
 * \brief Receives data during the TLS handshake.
 *
 * \details Reallocates the internal TLS object buffer if necessary.
 *
 * \param[in] Socket A handle to the socket object to receive data from.
 * \param[in] Timeout Optional timeout for the receive.
 * \param[in,out] Tls The TLS object to receive data for.
 * \param[in,out] Received On input, the amount of data already received during
 * the TLS handshake. On output, updated to reflect the addition of the newly received bytes.
 *
 * \return Successful or error status.
 */
{
    NTSTATUS status;
    ULONG length;

    PAGED_CODE_PASSIVE();

    if (*Received >= Tls->Length) {
        status = RtlULongAdd(Tls->Length, PAGE_SIZE, &length);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        status = KphpSocketTlsReallocateBuffer(Tls, length);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    }

    NT_ASSERT(Tls->Length > *Received);
    length = Tls->Length - *Received;
    status = KphSocketRecv(Socket, Timeout, Add2Ptr(Tls->Buffer, *Received), &length);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    *Received += length;

Exit:
    return status;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketTlsHandshake(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ KPH_TLS_HANDLE Tls,
    _In_ PUNICODE_STRING TargetName
)
/**
 * \brief Performs TLS handshake.
 *
 * \details After a successful TLS handshake, the caller must eventually call
 * KphSocketTlsShutdown to inform the peer the intention to shut down the TLS session.
 * It is acceptable to call TlsSocketTlsShutdown on a TLS handle even if this routine fails.
 *
 * \param[in] Socket Handle to a socket to perform the handshake on.
 * \param[in] Timeout Optional timeout for the handshake. This timeout is for
 * any individual socket operation. meaning that the total time spent may
 * exceed the requested timeout. But any given socket operation will not.
 * \param[in] Tls Handle to a TLS object.
 * \param[in] TargetName The target name to use for principal verification.
 *
 * \return Successful or error status.
 */
/*
谨记：不建议在这里单步或在下断点，除非遇到问题。
      不然的话，握手超时的问题大概率会发生。
所以，还是认真观察思考代码吧！
*/
{
    PKPH_TLS tls = (PKPH_TLS)Tls;
    CtxtHandle * context = NULL;

    PAGED_CODE_PASSIVE();

    NT_ASSERT(SecIsValidHandle(&tls->CredentialsHandle));
    NT_ASSERT(!SecIsValidHandle(&tls->ContextHandle));

    SecBuffer outBuffers[1];
    outBuffers[0].pvBuffer = NULL;

    SecBufferDesc inDesc;
    SecBuffer inBuffers[2];
    inDesc.ulVersion = SECBUFFER_VERSION;
    inDesc.cBuffers = ARRAYSIZE(inBuffers);
    inDesc.pBuffers = inBuffers;

    SecBufferDesc outDesc;
    outDesc.ulVersion = SECBUFFER_VERSION;
    outDesc.cBuffers = ARRAYSIZE(outBuffers);
    outDesc.pBuffers = outBuffers;

    KAPC_STATE apcState;
    KeStackAttachProcess(PsInitialSystemProcess, &apcState);

    NTSTATUS status = KphpSocketTlsReallocateBuffer(tls, PAGE_SIZE * 2);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    for (ULONG received = 0;;) {
        inBuffers[0].BufferType = SECBUFFER_TOKEN;
        inBuffers[0].pvBuffer = tls->Buffer;
        inBuffers[0].cbBuffer = received;

        inBuffers[1].BufferType = SECBUFFER_EMPTY;
        inBuffers[1].pvBuffer = NULL;
        inBuffers[1].cbBuffer = 0;

        if (outBuffers[0].pvBuffer) {
            KphpSecFreeContextBuffer(outBuffers[0].pvBuffer);
        }
        outBuffers[0].BufferType = SECBUFFER_TOKEN;
        outBuffers[0].pvBuffer = NULL;
        outBuffers[0].cbBuffer = 0;

        ULONG flags = (ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_CONFIDENTIALITY |
                       ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM);

        SECURITY_STATUS secStatus = KphpSecInitializeSecurityContext(&tls->CredentialsHandle,
                                                                     context,
                                                                     context ? NULL : TargetName,
                                                                     flags,
                                                                     0,
                                                                     SECURITY_NETWORK_DREP,
                                                                     context ? &inDesc : NULL,
                                                                     0,
                                                                     &tls->ContextHandle,
                                                                     &outDesc,
                                                                     &flags,
                                                                     NULL);
        context = &tls->ContextHandle;
        if ((inBuffers[1].BufferType == SECBUFFER_EXTRA) && (inBuffers[1].cbBuffer > 0)) {
            status = KphpSocketTlsHandshakeExtra(tls, &inBuffers[1], &received);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }

            // Force a receive. But, only if a output continuation isn't necessary (there is an output buffer).
            if ((secStatus == SEC_I_CONTINUE_NEEDED) && (outBuffers[0].BufferType != SECBUFFER_MISSING)) {
                secStatus = SEC_E_INCOMPLETE_MESSAGE;
            }
        } else if (inBuffers[1].BufferType != SECBUFFER_MISSING) {
            received = 0;
        }

        if (secStatus == SEC_E_OK) {// The handshake completed successfully.            
            status = KphpSocketTlsHandshakeFinalize((PKPH_TLS)Tls);
            if (!NT_SUCCESS(status)) {

            }

            goto Exit;
        }

        if (secStatus == SEC_I_INCOMPLETE_CREDENTIALS) {
            status = STATUS_NOT_SUPPORTED;
            goto Exit;
        }

        if ((secStatus == SEC_I_CONTINUE_NEEDED) && (outBuffers[0].BufferType != SECBUFFER_MISSING)) {
            status = KphSocketSend(Socket, Timeout, outBuffers[0].pvBuffer, outBuffers[0].cbBuffer);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }

            continue;
        }

        if (secStatus != SEC_E_INCOMPLETE_MESSAGE) {
            status = KphpSecStatusToNtStatus(secStatus);
            NT_ASSERT(!NT_SUCCESS(status));
            goto Exit;
        }

        // The handshake is not complete, we need to receive more data.
        status = KphpSocketTlsHandshakeRecv(Socket, Timeout, tls, &received);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    }

Exit:
    if (outBuffers[0].pvBuffer) {
        KphpSecFreeContextBuffer(outBuffers[0].pvBuffer);
    }

    if (!NT_SUCCESS(status) && SecIsValidHandle(&tls->ContextHandle)) {
        KphpSecDeleteSecurityContext(&tls->ContextHandle);
        SecInvalidateHandle(&tls->ContextHandle);
    }

    KeUnstackDetachProcess(&apcState);

    return status;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphSocketTlsShutdown(_In_ KPH_SOCKET_HANDLE Socket, _In_ KPH_TLS_HANDLE Tls)
/**
 * \brief Shuts down a TLS session.
 *
 * \details It is appropriate to call this even when KphSocketTlsHandshake
 * fails. Regardless of any send or receive errors, shutdown should always be
 * called to inform the peer of the intention to shut down the TLS session.
 *
 * \param[in] Socket Handle to a socket object to shut down the TLS session on.
 * \param[in] Tls Handle to a TLS object to shut down the session of.
 */
{
    NTSTATUS status;
    SECURITY_STATUS secStatus;
    KAPC_STATE apcState;
    PKPH_TLS tls;
    ULONG shutdown;
    SecBuffer inBuffers[1];
    SecBuffer outBuffers[1];
    SecBufferDesc inDesc;
    SecBufferDesc outDesc;
    ULONG flags;

    PAGED_CODE_PASSIVE();

    tls = (PKPH_TLS)Tls;

    if (!SecIsValidHandle(&tls->ContextHandle)) {
        return;
    }

    KeStackAttachProcess(PsInitialSystemProcess, &apcState);

    inDesc.ulVersion = SECBUFFER_VERSION;
    inDesc.cBuffers = ARRAYSIZE(inBuffers);
    inDesc.pBuffers = inBuffers;

    outDesc.ulVersion = SECBUFFER_VERSION;
    outDesc.cBuffers = ARRAYSIZE(outBuffers);
    outDesc.pBuffers = outBuffers;

    shutdown = SCHANNEL_SHUTDOWN;
    inBuffers[0].BufferType = SECBUFFER_TOKEN;
    inBuffers[0].pvBuffer = &shutdown;
    inBuffers[0].cbBuffer = sizeof(shutdown);

    outBuffers[0].pvBuffer = NULL;

    secStatus = KphpSecApplyControlToken(&tls->ContextHandle, &inDesc);
    if (secStatus != SEC_E_OK) {
        goto Exit;
    }

    do {
        inBuffers[0].BufferType = SECBUFFER_EMPTY;
        inBuffers[0].pvBuffer = NULL;
        inBuffers[0].cbBuffer = 0;

        if (outBuffers[0].pvBuffer) {
            KphpSecFreeContextBuffer(outBuffers[0].pvBuffer);
        }
        outBuffers[0].BufferType = SECBUFFER_TOKEN;
        outBuffers[0].pvBuffer = NULL;
        outBuffers[0].cbBuffer = 0;

        flags = (ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT |
                 ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM);

        secStatus = KphpSecInitializeSecurityContext(&tls->CredentialsHandle,
                                                     &tls->ContextHandle,
                                                     NULL,
                                                     flags,
                                                     0,
                                                     SECURITY_NETWORK_DREP,
                                                     &inDesc,
                                                     0,
                                                     &tls->ContextHandle,
                                                     &outDesc,
                                                     &flags,
                                                     NULL);
        if ((secStatus == SEC_I_CONTINUE_NEEDED) && (outBuffers[0].BufferType != SECBUFFER_MISSING)) {
            status = KphSocketSend(Socket, &KphpSocketCloseTimeout, outBuffers[0].pvBuffer, outBuffers[0].cbBuffer);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }
        }
    } while ((secStatus != SEC_E_OK) && (secStatus != SEC_I_CONTEXT_EXPIRED));

Exit:
    if (outBuffers[0].pvBuffer) {
        KphpSecFreeContextBuffer(outBuffers[0].pvBuffer);
    }

    KphpSecDeleteSecurityContext(&tls->ContextHandle);
    SecInvalidateHandle(&tls->ContextHandle);

    RtlZeroMemory(&tls->StreamSizes, sizeof(tls->StreamSizes));
    RtlZeroMemory(&tls->Recv, sizeof(tls->Recv));

    KeUnstackDetachProcess(&apcState);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketTlsSend(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ KPH_TLS_HANDLE Tls,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
)
/**
 * \brief Sends data over a TLS session.
 *
 * \details If the requested data to be sent exceeds the maximum size capable
 * of being sent at once, this routine will perform multiple sends.
 *
 * \param[in] Socket Handle to a socket object to send data over.
 * \param[in] Timeout Optional timeout for the handshake. This timeout is for
 * any individual socket operation. meaning that the total time spent may
 * exceed the requested timeout. But any given socket operation will not.
 * \param[in] Tls Handle to a TLS object to use for sending data.
 * \param[in] Buffer Pointer to a buffer containing the data to send.
 * \param[in] Length The length of the data to send.
 *
 * \return Successful or errant status.
 */
{
    NTSTATUS status;
    KAPC_STATE apcState;
    PKPH_TLS tls = (PKPH_TLS)Tls;

    PAGED_CODE_PASSIVE();

    RtlZeroMemory(&tls->Recv, sizeof(tls->Recv));

    if (Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeStackAttachProcess(PsInitialSystemProcess, &apcState);

    SecBufferDesc desc;
    SecBuffer buffers[3];
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = ARRAYSIZE(buffers);
    desc.pBuffers = buffers;

    for (ULONG remaining = Length; remaining > 0;) {
        ULONG length;

        // The preallocated buffer is determined during the handshake and will
        // be sufficient for the maximum packet size.
        NT_ASSERT(tls->Length >= (tls->StreamSizes.cbHeader +
                                  tls->StreamSizes.cbMaximumMessage +
                                  tls->StreamSizes.cbTrailer));

        length = min(remaining, tls->StreamSizes.cbMaximumMessage);

        NT_ASSERT(length <= Length);
        NT_ASSERT(remaining <= Length);

        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = tls->Buffer;
        buffers[0].cbBuffer = tls->StreamSizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = Add2Ptr(tls->Buffer, tls->StreamSizes.cbHeader);
        buffers[1].cbBuffer = length;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = Add2Ptr(tls->Buffer, (ULONG_PTR)tls->StreamSizes.cbHeader + length);
        buffers[2].cbBuffer = tls->StreamSizes.cbTrailer;

        RtlCopyMemory(buffers[1].pvBuffer, Add2Ptr(Buffer, Length - remaining), length);

        SECURITY_STATUS secStatus = KphpSecEncryptMessage(&tls->ContextHandle, 0, &desc, 0);
        if (secStatus != SEC_E_OK) {
            status = KphpSecStatusToNtStatus(secStatus);
            NT_ASSERT(!NT_SUCCESS(status));
            goto Exit;
        }

        remaining -= length;
        length += (tls->StreamSizes.cbHeader + tls->StreamSizes.cbTrailer);
        status = KphSocketSend(Socket, Timeout, tls->Buffer, length);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
    }

    status = STATUS_SUCCESS;

Exit:
    KeUnstackDetachProcess(&apcState);
    return status;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketTlsRecv(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ KPH_TLS_HANDLE Tls,
    _Out_writes_bytes_to_(*Length, *Length) PVOID Buffer,
    _Inout_ PULONG Length
)
/**
 * \brief Receives data over a TLS session.
 *
 * \details This routine will populate as much of the supplied buffer as
 * possible and prepare more data to be received by a following call. The
 * caller should check the output Length parameter for 0 to determine if there is no more data to be received.
 *
 * \param[in] Socket Handle to a socket object to receive data over.
 * \param[in] Timeout Optional timeout for the handshake. This timeout is for
 * any individual socket operation. meaning that the total time spent may
 * exceed the requested timeout. But any given socket operation will not.
 * \param[in] Tls Handle to a TLS object to use for receiving data.
 * \param[out] Buffer Pointer to a buffer to receive the data.
 * \param[in,out] Length On input, the length of the buffer. On output, the length of the data received.
 *
 * \return Successful or errant status.
 */
{
    NTSTATUS status;
    KAPC_STATE apcState;
    SecBuffer buffers[4];

    PAGED_CODE_PASSIVE();

    KeStackAttachProcess(PsInitialSystemProcess, &apcState);

    PKPH_TLS tls = (PKPH_TLS)Tls;
    PVOID buffer = Buffer;
    ULONG length = *Length;

    SecBufferDesc desc;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = ARRAYSIZE(buffers);
    desc.pBuffers = buffers;

    while (length > 0) {
        ULONG received;
        SECURITY_STATUS secStatus;

        if (tls->Recv.Available > 0) {
            ULONG consumed;

            NT_ASSERT(tls->Recv.Decrypted);

            consumed = min(length, tls->Recv.Available);

            RtlCopyMemory(buffer, tls->Recv.Decrypted, consumed);
            buffer = Add2Ptr(buffer, consumed);
            length -= consumed;

            if (consumed == tls->Recv.Available) {
                NT_ASSERT(tls->Recv.Used <= tls->Length);
                NT_ASSERT(tls->Recv.Used <= tls->Recv.Received);

                RtlMoveMemory(tls->Buffer,
                              Add2Ptr(tls->Buffer, tls->Recv.Used),
                              tls->Recv.Received - tls->Recv.Used);

                tls->Recv.Received -= tls->Recv.Used;
                tls->Recv.Used = 0;
                tls->Recv.Available = 0;
                tls->Recv.Decrypted = NULL;
            } else {
                tls->Recv.Available -= consumed;
                tls->Recv.Decrypted = Add2Ptr(tls->Recv.Decrypted, consumed);
            }

            continue;
        }

        if (tls->Recv.Received > 0) {
            buffers[0].BufferType = SECBUFFER_DATA;
            buffers[0].pvBuffer = tls->Buffer;
            buffers[0].cbBuffer = tls->Recv.Received;
            buffers[1].BufferType = SECBUFFER_EMPTY;
            buffers[1].pvBuffer = NULL;
            buffers[1].cbBuffer = 0;
            buffers[2].BufferType = SECBUFFER_EMPTY;
            buffers[2].pvBuffer = NULL;
            buffers[2].cbBuffer = 0;
            buffers[3].BufferType = SECBUFFER_EMPTY;
            buffers[3].pvBuffer = NULL;
            buffers[3].cbBuffer = 0;

            secStatus = KphpSecDecryptMessage(&tls->ContextHandle, &desc, 0, NULL);
            if (secStatus == SEC_E_OK) {
                if ((buffers[0].BufferType != SECBUFFER_STREAM_HEADER) ||
                    (buffers[1].BufferType != SECBUFFER_DATA) ||
                    (buffers[2].BufferType != SECBUFFER_STREAM_TRAILER)) {
                    status = STATUS_UNEXPECTED_NETWORK_ERROR;
                    goto Exit;
                }

                tls->Recv.Decrypted = buffers[1].pvBuffer;
                tls->Recv.Available = buffers[1].cbBuffer;
                tls->Recv.Used = tls->Recv.Received;
                if (buffers[3].BufferType == SECBUFFER_EXTRA) {
                    status = RtlULongSub(tls->Recv.Used, buffers[3].cbBuffer, &tls->Recv.Used);
                    if (!NT_SUCCESS(status)) {
                        goto Exit;
                    }
                }

                continue;
            }

            if (secStatus == SEC_I_CONTEXT_EXPIRED) {// The TLS session has been closed.                
                RtlZeroMemory(&tls->Recv, sizeof(tls->Recv));
                break;
            }

            if (secStatus != SEC_E_INCOMPLETE_MESSAGE) {
                status = KphpSecStatusToNtStatus(secStatus);
                NT_ASSERT(!NT_SUCCESS(status));
                goto Exit;
            }
        }

        NT_ASSERT(tls->Recv.Received < tls->Length);
        received = tls->Length - tls->Recv.Received;
        status = KphSocketRecv(Socket, Timeout, Add2Ptr(tls->Buffer, tls->Recv.Received), &received);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }

        if (received == 0) {
            if (tls->Recv.Received == 0) {
                NT_ASSERT(tls->Recv.Available == 0);
                break;
            }

            status = STATUS_UNEXPECTED_NETWORK_ERROR;
            goto Exit;
        }

        tls->Recv.Received += received;
    }

    status = STATUS_SUCCESS;

Exit:

    *Length = (*Length - length);

    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(&tls->Recv, sizeof(tls->Recv));
    }

    KeUnstackDetachProcess(&apcState);

    return status;
}
