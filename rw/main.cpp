#include <iostream>
#include <Windows.h>

#define MAX_RW_LENGTH 1024

#define IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_SUSPEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_RESUME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _PROC_INFO
{
	HANDLE ProcessId;
	PVOID Address;
	ULONG Length;
	uint8_t Buffer[MAX_RW_LENGTH];
} PROC_INFO, *PPROC_INFO;
#pragma pack(pop)   

int main(int argc, char* argv[])
{
    HANDLE handle = CreateFileW(
        L"\\\\.\\rw",
        GENERIC_ALL, 0, 0, OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM, 0);

    PROC_INFO lol{};
    lol.ProcessId = (HANDLE)atoi(argv[1]);
    lol.Length = 2;
    lol.Address = (PVOID)0x0000000140000000;
    ZeroMemory(lol.Buffer, MAX_RW_LENGTH);

    DWORD read_bytes;
    DeviceIoControl(
        handle, IOCTL_SUSPEND,
        &lol, sizeof(PROC_INFO),
        nullptr, 0,
        &read_bytes, NULL);

    DeviceIoControl(
        handle, IOCTL_READ,
        &lol, sizeof(PROC_INFO),
        &lol, sizeof(PROC_INFO),
        &read_bytes, NULL);

    printf("%c%c\n",
        (char)lol.Buffer[0], (char)lol.Buffer[1]);

    lol.Buffer[0] = 'A';
    lol.Buffer[1] = 'B';

    DWORD written_bytes;
    DeviceIoControl(
        handle, IOCTL_WRITE,
        &lol, sizeof(PROC_INFO),
        nullptr, 0,
        &written_bytes, NULL);

    DeviceIoControl(
        handle, IOCTL_RESUME,
        &lol, sizeof(PROC_INFO),
        nullptr, 0,
        &read_bytes, NULL);

    DeviceIoControl(
        handle, IOCTL_READ,
        &lol, sizeof(PROC_INFO),
        &lol, sizeof(PROC_INFO),
        &read_bytes, NULL);

    printf("%c%c\n",
        (char)lol.Buffer[0], (char)lol.Buffer[1]);

    CloseHandle(handle);
}