#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _KPH_SOCKET
{
    PWSK_SOCKET WskSocket;
    PWSK_PROVIDER_CONNECTION_DISPATCH WskDispatch;
    KPH_WSK_IO Io;
} KPH_SOCKET, * PKPH_SOCKET;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern LARGE_INTEGER KphpSocketCloseTimeout;


EXTERN_C_START


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID KphSocketClose(KPH_SOCKET_HANDLE Socket);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketConnect(
    _In_ USHORT SocketType,
    _In_ ULONG Protocol,
    _In_ PSOCKADDR LocalAddress,
    _In_ PSOCKADDR RemoteAddress,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Outptr_allocatesMem_ PKPH_SOCKET_HANDLE Socket
);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketSend(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length
);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS KphSocketRecv(
    _In_ KPH_SOCKET_HANDLE Socket,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_writes_bytes_to_(*Length, *Length) PVOID Buffer,
    _Inout_ PULONG Length
);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphInitializeSocket(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphCleanupSocket(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS KphGetAddressInfo(
    _In_ PUNICODE_STRING NodeName,
    _In_opt_ PUNICODE_STRING ServiceName,
    _In_opt_ PADDRINFOEXW Hints,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Outptr_allocatesMem_ PADDRINFOEXW * AddressInfo
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID KphFreeAddressInfo(_In_freesMem_ PADDRINFOEXW AddressInfo);


EXTERN_C_END
