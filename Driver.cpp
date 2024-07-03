#include <ntifs.h>
#include <ntddk.h>

UNICODE_STRING DriverName, SymbolicLinkName;

#define IOCTL_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_PROCESS_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _KERNEL_READ_REQUEST {
    ULONG ProcessId;
    ULONG Address;
    PVOID pBuffer;
    ULONG Size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
    ULONG ProcessId;
    ULONG Address;
    PVOID pBuffer;
    ULONG Size;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_BASE_REQUEST {
    ULONG ProcessId;
    ULONG64 BaseAddress;
} KERNEL_BASE_REQUEST, *PKERNEL_BASE_REQUEST;

NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
    ULONG ControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;

    if (ControlCode == IOCTL_READ_MEMORY) {
        PKERNEL_READ_REQUEST ReadRequest = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        PEPROCESS Process;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ReadRequest->ProcessId, &Process))) {
            SIZE_T BytesRead;
            MmCopyVirtualMemory(Process, (PVOID)ReadRequest->Address, PsGetCurrentProcess(), ReadRequest->pBuffer, ReadRequest->Size, KernelMode, &BytesRead);
            Irp->IoStatus.Information = sizeof(KERNEL_READ_REQUEST);
            ObDereferenceObject(Process);
        } else {
            Irp->IoStatus.Information = 0;
        }

    } else if (ControlCode == IOCTL_WRITE_MEMORY) {
        PKERNEL_WRITE_REQUEST WriteRequest = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        PEPROCESS Process;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)WriteRequest->ProcessId, &Process))) {
            SIZE_T BytesWritten;
            MmCopyVirtualMemory(PsGetCurrentProcess(), WriteRequest->pBuffer, Process, (PVOID)WriteRequest->Address, WriteRequest->Size, KernelMode, &BytesWritten);
            Irp->IoStatus.Information = sizeof(KERNEL_WRITE_REQUEST);
            ObDereferenceObject(Process);
        } else {
            Irp->IoStatus.Information = 0;
        }

    } else if (ControlCode == IOCTL_GET_PROCESS_BASE) {
        PKERNEL_BASE_REQUEST BaseRequest = (PKERNEL_BASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        PEPROCESS Process;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)BaseRequest->ProcessId, &Process))) {
            BaseRequest->BaseAddress = (ULONG64)PsGetProcessSectionBaseAddress(Process);
            Irp->IoStatus.Information = sizeof(KERNEL_BASE_REQUEST);
            ObDereferenceObject(Process);
        } else {
            Irp->IoStatus.Information = 0;
        }

    } else {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    IoDeleteSymbolicLink(&SymbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&DriverName, L"\\Device\\odin123w&1337");
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\odin123w&1337");

    IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
    IoCreateSymbolicLink(&SymbolicLinkName, &DriverName);

    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = UnsupportedDispatch;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}
