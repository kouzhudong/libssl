/*
文件名字取自VS2017的控制台示例工程的头文件.

功能:预编译头,不过没有用命令强制第一个包含这个文件.

注意:
1.这个文件只包含系统的头文件和一些公共的数据.
2.这个文件只包含一些公共的数据.
3.也就是说别的头文件只准包含这个文件,不准再包含别的系统文件.

此文件主要用于解决:
1.系统文件包含导致的编译错误问题.
2.统一规划文件的包含关系.
*/


#pragma once


#if (NTDDI_VERSION >= NTDDI_VISTA)
#define NDIS60 1
#define NDIS_SUPPORT_NDIS6 1
#endif 

#define POOL_NX_OPTIN 1
#define _CRT_NON_CONFORMING_SWPRINTFS
#define INITGUID
#define NTSTRSAFE_LIB

#pragma warning(disable:4200) // 使用了非标准扩展 : 结构/联合中的零大小数组
#pragma warning(disable:4201) // unnamed struct/union
#pragma warning(disable:4214) // 使用了非标准扩展: 整形以外的位域类型
#pragma warning(disable:4127) // 条件表达式是常量
#pragma warning(disable:4057) // 在稍微不同的基类型间接寻址上不同
#pragma warning(disable:4152) // 非标准扩展，表达式中的函数/数据指针转换
#pragma warning(disable:28172) //The function 'XXX' has PAGED_CODE or PAGED_CODE_LOCKED but is not declared to be in a paged segment. 原因：1.函数内IRQL升级，2.函数内的函数的参数用局部变量，且要求这个变量是非分页内存。

#include <winerror.h>
#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <windef.h> //应该放在ntddk.h的后面.
#include <in6addr.h>
#include <ip2string.h>
#include <guiddef.h>
#include <ndis.h>
#include <initguid.h> //静态定义UUID用的，否则：error LNK2001。
#include <Ntstrsafe.h>
#include <ipmib.h>
#include <netpnp.h>
#include <ntintsafe.h>
#include <fltkernel.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <Bcrypt.h>

/*
WDK7600.16385.1的内核头文件没有u_short的定义,用户层的头文件有u_short的定义.
SOCKADDR结构里用到u_short.
SOCKADDR在ws2def.h中定义.
ws2def.h不建议直接包含.
netioapi.h包含ws2def.h等文件.
所以在WDK7600.16385.1中,如果不包含应用层的头文件,应该在包含netioapi.h之前,加上u_short的定义.
否者,每个包含(包括间接包含)ws2def.h的c/cpp文件都出现一大堆的错误.
*/
typedef unsigned short  u_short;
#include <netioapi.h>
//#include <ws2def.h>
#include <ws2ipdef.h>
#include <mstcpip.h>
#include <wmilib.h>
#include <wmistr.h>
#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>
#include <tdistat.h>
#include <fwpmk.h>
#include <wsk.h>
#include <ntimage.h>
#include <fwpsk.h>  //NDIS61
#include <dontuse.h>
#include <suppress.h>
#include <aux_klib.h>
#include <assert.h>
#include <Ntdddisk.h>
#include <intrin.h> //VS2012编译。
#include <immintrin.h>//VS2012编译。
//#include <mmintrin.h> //WDK 编译。
//#include <emmintrin.h>//WDK 编译。
//#include <xmmintrin.h>//WDK 编译。
#include <wdmsec.h>
#define SECURITY_KERNEL
#include <sspi.h>


#define TAG 'tset' //test


//////////////////////////////////////////////////////////////////////////////////////////////////


#define _Outptr_allocatesMem_ _Outptr_result_nullonfailure_ __drv_allocatesMem(Mem)
#define _Out_allocatesMem_ _Out_ __drv_allocatesMem(Mem)
#define _Out_allocatesMem_size_(size) _Out_allocatesMem_ _Post_writable_byte_size_(size)
#define _FreesMem_ _Pre_notnull_ _Post_ptr_invalid_ __drv_freesMem(Mem)
#define _In_freesMem_ _In_ _FreesMem_
#define _In_aliasesMem_ _In_ _Pre_notnull_ _Post_ptr_invalid_ __drv_aliasesMem
#define _Return_allocatesMem_ __drv_allocatesMem(Mem) _Post_maybenull_ _Must_inspect_result_
#define _Return_allocatesMem_size_(size) _Return_allocatesMem_ _Post_writable_byte_size_(size)


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef PVOID KPH_SOCKET_HANDLE;
typedef PVOID * PKPH_SOCKET_HANDLE;

typedef PVOID KPH_TLS_HANDLE;
typedef PVOID * PKPH_TLS_HANDLE;


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


//////////////////////////////////////////////////////////////////////////////////////////////////


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


//////////////////////////////////////////////////////////////////////////////////////////////////


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


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_END
