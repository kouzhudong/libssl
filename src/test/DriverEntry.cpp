#include "DriverEntry.h"
#include "..\libssl\libssl.h"


_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID Unload(_In_ struct _DRIVER_OBJECT * DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();
}


void TestGetHttps()
{
    KPH_TLS_HANDLE Tls = nullptr;
    PADDRINFOEXW AddressInfo{};
    KPH_SOCKET_HANDLE Socket{};

    __try {
        NTSTATUS Status = KphInitializeSocket();
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = KphSocketTlsCreate(&Tls);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Status:%#x", Status);
            __leave;
        }
        ASSERT(Tls);

        UNICODE_STRING NodeName = RTL_CONSTANT_STRING(L"www.microsoft.com");//IP变化很频繁，且还有可能是IPv6.
        LARGE_INTEGER Timeout = {.QuadPart = -30000000ll}; // 3 seconds
        Status = KphGetAddressInfo(&NodeName, NULL, NULL, &Timeout, &AddressInfo);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Status:%#x", Status);
            __leave;
        }

        PSOCKADDR LocalAddress{};
        SOCKADDR_IN LocalAddressV4 = {0};
        SOCKADDR_IN6 LocalAddressV6 = {0};

        switch (AddressInfo->ai_family) {
        case AF_INET:
        {
            IN4ADDR_SETANY(&LocalAddressV4);
            LocalAddress = (PSOCKADDR)&LocalAddressV4;

            PSOCKADDR_IN RemoteAddress = (PSOCKADDR_IN)AddressInfo->ai_addr;
            RemoteAddress->sin_port = RtlUshortByteSwap(IPPORT_HTTPS);

            CHAR RemoteIPv4[17]{};
            RtlIpv4AddressToStringA(&RemoteAddress->sin_addr, RemoteIPv4);
            Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "RemoteIPv4:%s", RemoteIPv4);

            break;
        }
        case AF_INET6:
        {
            IN6ADDR_SETANY(&LocalAddressV6);
            LocalAddress = (PSOCKADDR)&LocalAddressV6;

            PSOCKADDR_IN6 RemoteAddress = (PSOCKADDR_IN6)AddressInfo->ai_addr;
            RemoteAddress->sin6_family = RtlUshortByteSwap(IPPORT_HTTPS);

            CHAR RemoteIPv6[65]{};
            RtlIpv6AddressToStringA(&RemoteAddress->sin6_addr, RemoteIPv6);
            Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "RemoteIPv6:%s", RemoteIPv6);

            break;
        }
        default:
            ASSERT(FALSE);
            break;
        }

        USHORT SocketType{SOCK_STREAM};
        ULONG Protocol{IPPROTO_TCP};
        Status = KphSocketConnect(SocketType,
                                  Protocol,
                                  LocalAddress,
                                  AddressInfo->ai_addr,
                                  &Timeout,
                                  &Socket);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = KphSocketTlsHandshake(Socket, &Timeout, Tls, &NodeName);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Status:%#x", Status);
            __leave;
        }

        const char * Message = "GET / HTTP/1.0\r\n\r\n";
        ULONG Length = (ULONG)strlen(Message);
        Status = KphSocketTlsSend(Socket, &Timeout, Tls, (PVOID)Message, Length);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Status:%#x", Status);
            __leave;
        }

        CHAR Buffer[MAX_PATH];

        for (;;) {
            Length = sizeof(Buffer);
            RtlZeroMemory(Buffer, Length);
            Length--;//空一个字节，用于打印。
            Status = KphSocketTlsRecv(Socket, &Timeout, Tls, Buffer, &Length);
            if (!NT_SUCCESS(Status)) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "Status:%#x", Status);
                break;
            }

            if (!Length) {//接收完毕的标志。
                break;
            }

            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "%s", Buffer);
        }
    } __finally {
        if (AddressInfo) {
            KphFreeAddressInfo(AddressInfo);
        }

        if (Socket) {
            if (Tls) {
                KphSocketTlsShutdown(Socket, Tls);
            }

            KphSocketClose(Socket);
        }

        if (Tls) {
            KphSocketTlsClose(Tls);
        }

        KphCleanupSocket();
    }
}


EXTERN_C DRIVER_INITIALIZE DriverEntry;
//#pragma INITCODE
//#pragma alloc_text(INIT, DriverEntry)
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(RegistryPath);

    if (!KD_DEBUGGER_NOT_PRESENT) {
        KdBreakPoint();//__debugbreak();
    }

    //if (*InitSafeBootMode) {
    //    return STATUS_ACCESS_DENIED;
    //}

    PAGED_CODE();

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    DriverObject->DriverUnload = Unload;

    TestGetHttps();

    return Status;
}
