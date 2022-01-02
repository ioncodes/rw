#include <ntifs.h>

#define MAX_RW_LENGTH 1024

#define IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_SUSPEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_RESUME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define LOG(x, ...) DbgPrint("[rw] " x, __VA_ARGS__)
#define STATUS_ASSERT(x) \
	do { \
		if (!NT_SUCCESS(x)) \
			LOG("NTSTATUS = %x\n", x); \
		NT_VERIFY(NT_SUCCESS(x)); \
	} while (0)

typedef NTSTATUS (NTAPI* MmCopyVirtualMemory)(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize);
typedef NTSTATUS(NTAPI* ZwProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection);
typedef NTSTATUS(NTAPI* PsSuspendProcess)(
	PEPROCESS Process);
typedef NTSTATUS(NTAPI* PsResumeProcess)(
	PEPROCESS Process);

#pragma pack(push, 1)
typedef struct _PROC_INFO
{
	HANDLE ProcessId;
	PVOID Address;
	ULONG Length;
	UINT8 Buffer[MAX_RW_LENGTH];
} PROC_INFO, *PPROC_INFO;
#pragma pack(pop)

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\rw");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\rw");

PDEVICE_OBJECT k_DeviceObject = nullptr;
MmCopyVirtualMemory k_MmCopyVirtualMemory = nullptr;
ZwProtectVirtualMemory k_ZwProtectVirtualMemory = nullptr;
PsSuspendProcess k_PsSuspendProcess = nullptr;
PsResumeProcess k_PsResumeProcess = nullptr;

template<typename RoutineType>
RoutineType GetProcAddress(
	_In_ const wchar_t* Name)
{
	UNICODE_STRING routineName{};
	RoutineType ptr;

	RtlInitUnicodeString(&routineName, Name);

	ptr = reinterpret_cast<RoutineType>(
		MmGetSystemRoutineAddress(&routineName));
	ASSERT(ptr != nullptr);

	return ptr;
}

VOID ReadFromAddress(
	_In_ PEPROCESS Process,
	_In_ PPROC_INFO ProcInfo)
{
	SIZE_T bytesRead;
	NTSTATUS status;

	LOG("Reading %d bytes from %p into %p\n",
		ProcInfo->Length, ProcInfo->Address, ProcInfo->Buffer);

	k_MmCopyVirtualMemory(
		Process, ProcInfo->Address,
		PsGetCurrentProcess(), ProcInfo->Buffer, ProcInfo->Length,
		KernelMode, &bytesRead);
	STATUS_ASSERT(status);
}

VOID WriteToAddress(
	_In_ PEPROCESS Process,
	_In_ PPROC_INFO ProcInfo)
{
	MEMORY_BASIC_INFORMATION memoryInfo{};
	ULONG oldProtection;
	SIZE_T returnLength;
	NTSTATUS status;
	HANDLE handle;

	LOG("Writing %d bytes from %p into %p\n",
		ProcInfo->Length, ProcInfo->Buffer, ProcInfo->Address);

	status = ObOpenObjectByPointer(
		Process, NULL, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &handle);
	STATUS_ASSERT(status);

	status = ZwQueryVirtualMemory(
		handle, ProcInfo->Address, MemoryBasicInformation, 
		&memoryInfo, sizeof(MEMORY_BASIC_INFORMATION), 
		&returnLength);
	STATUS_ASSERT(status);

	status = k_ZwProtectVirtualMemory(
		handle,
		&memoryInfo.BaseAddress, &memoryInfo.RegionSize,
		PAGE_EXECUTE_READWRITE,
		&oldProtection);
	STATUS_ASSERT(status);

	status = k_MmCopyVirtualMemory(
		PsGetCurrentProcess(), ProcInfo->Buffer,
		Process, ProcInfo->Address, ProcInfo->Length,
		KernelMode, &returnLength);
	STATUS_ASSERT(status);

	status = k_ZwProtectVirtualMemory(
		handle,
		&memoryInfo.BaseAddress, &memoryInfo.RegionSize,
		oldProtection,
		&oldProtection);
	STATUS_ASSERT(status);

	if (handle)
		ZwClose(handle);
}

NTSTATUS DeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stackLocation = IoGetCurrentIrpStackLocation(Irp);
	PPROC_INFO procInfo = nullptr;
	PEPROCESS process = nullptr;

	if (Irp->AssociatedIrp.SystemBuffer != nullptr)
	{
		procInfo = reinterpret_cast<PPROC_INFO>(
			Irp->AssociatedIrp.SystemBuffer);
		STATUS_ASSERT(PsLookupProcessByProcessId(
			procInfo->ProcessId,
			&process));

		switch (stackLocation->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_READ:
			ReadFromAddress(process, procInfo);
			Irp->IoStatus.Information = sizeof(PROC_INFO);
			break;
		case IOCTL_WRITE:
			WriteToAddress(process, procInfo);
			Irp->IoStatus.Information = sizeof(PROC_INFO);
			break;
		case IOCTL_SUSPEND:
			LOG("Suspending process\n");
			k_PsSuspendProcess(process);
			break;
		case IOCTL_RESUME:
			LOG("Resuming process\n");
			k_PsResumeProcess(process);
			break;
		}

		ObDereferenceObject(process);
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS CreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);

	if (k_DeviceObject != nullptr)
		IoDeleteDevice(k_DeviceObject);
}

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;

	status = IoCreateDevice(
		DriverObject,
		0,
		&DEVICE_NAME,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&k_DeviceObject);

	if (!NT_SUCCESS(status))
	{
		LOG("Failed @ IoCreateDevice\n");
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = DriverUnload;

	status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);

	if (!NT_SUCCESS(status))
	{
		LOG("Failed @ IoCreateSymbolicLink\n");
		IoDeleteDevice(k_DeviceObject);
		return status;
	}

	LOG("Driver loaded\n");

	k_MmCopyVirtualMemory = 
		GetProcAddress<MmCopyVirtualMemory>(L"MmCopyVirtualMemory");
	k_ZwProtectVirtualMemory =
		GetProcAddress<ZwProtectVirtualMemory>(L"ZwProtectVirtualMemory");
	k_PsSuspendProcess =
		GetProcAddress<PsSuspendProcess>(L"PsSuspendProcess");
	k_PsResumeProcess =
		GetProcAddress<PsResumeProcess>(L"PsResumeProcess");

	return STATUS_SUCCESS;
}