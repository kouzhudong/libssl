#include "pch.h"
#include "tls.h"


KPH_PROTECTED_DATA_SECTION_PUSH();
static ULONG KphpRandomPoolTag = 0;
KPH_PROTECTED_DATA_SECTION_POP();


//////////////////////////////////////////////////////////////////////////////////////////////////


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID KphFree(_FreesMem_ PVOID Memory, _In_ ULONG Tag)
{
    NPAGED_CODE_DISPATCH_MAX();
    NT_ASSERT(Memory);

    if (KphpRandomPoolTag) {
        Tag = KphpRandomPoolTag;
    }

#pragma warning(suppress: 4995) // suppress deprecation warning
    ExFreePoolWithTag(Memory, Tag);
}


_IRQL_requires_max_(DISPATCH_LEVEL)
_Return_allocatesMem_size_(NumberOfBytes)
PVOID KphAllocateNPaged(_In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
    NPAGED_CODE_DISPATCH_MAX();

    if (KphpRandomPoolTag) {
        Tag = KphpRandomPoolTag;
    }

#pragma warning(suppress: 4995) // suppress deprecation warning
    return ExAllocatePoolZero(NonPagedPoolNx, NumberOfBytes, Tag);
}


_IRQL_requires_max_(APC_LEVEL)
_Return_allocatesMem_size_(NumberOfBytes)
PVOID KphAllocatePaged(_In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
    PAGED_CODE();

    if (KphpRandomPoolTag) {
        Tag = KphpRandomPoolTag;
    }

#pragma warning(suppress: 4995) // suppress deprecation warning
    return ExAllocatePoolZero(PagedPool, NumberOfBytes, Tag);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


_Function_class_(IO_COMPLETION_ROUTINE)
_IRQL_requires_same_
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS KphpWskIoCompletionRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    NPAGED_CODE_DISPATCH_MAX();
    NT_ASSERT(Context);

    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS KphpWskIoCreate(_Out_ PKPH_WSK_IO Io)
/**
 * \brief Initialize an WSK I/O object.
 *
 * \param[out] Io The WSK I/O object to initialize. Once initialized the data must be deleted with KphpWskIoDelete.
 *
 * \return Successful or errant status.
 */
{
    NPAGED_CODE_DISPATCH_MAX();

    KeInitializeEvent(&Io->Event, NotificationEvent, FALSE);

    Io->Irp = IoAllocateIrp(1, FALSE);
    if (!Io->Irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IoSetCompletionRoutine(Io->Irp, &KphpWskIoCompletionRoutine, &Io->Event, TRUE, TRUE, TRUE);

    return STATUS_SUCCESS;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID KphpWskIoReset(_Inout_ PKPH_WSK_IO Io)
/**
 * \brief Resets an WSK I/O, preparing it to be reused for another request.
 *
 * \param[in,out] Io The WSK I/O object to reset.
 */
{
    NPAGED_CODE_DISPATCH_MAX();

    KeResetEvent(&Io->Event);
    IoReuseIrp(Io->Irp, STATUS_UNSUCCESSFUL);
    IoSetCompletionRoutine(Io->Irp, &KphpWskIoCompletionRoutine, &Io->Event, TRUE, TRUE, TRUE);
}


_IRQL_requires_max_(DISPATCH_LEVEL)
VOID KphpWskIoDelete(_In_ PKPH_WSK_IO Io)
/**
 * \brief Deletes an WSK I/O object.
 *
 * \param[in] Io The WSK I/O object to delete.
 */
{
    NPAGED_CODE_DISPATCH_MAX();

    if (Io->Irp) {
        IoFreeIrp(Io->Irp);
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
