#include <Windows.h>
#include <iostream>

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

HANDLE OpenDriver() {
    HANDLE hDevice = CreateFile(L"\\\\.\\odin123w&1337",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open driver: " << GetLastError() << std::endl;
        return nullptr;
    }

    return hDevice;
}

ULONG64 GetProcessBaseAddress(HANDLE hDevice, ULONG processId) {
    KERNEL_BASE_REQUEST baseRequest = { 0 };
    baseRequest.ProcessId = processId;

    DWORD returned;
    if (!DeviceIoControl(hDevice, IOCTL_GET_PROCESS_BASE, &baseRequest, sizeof(baseRequest), &baseRequest, sizeof(baseRequest), &returned, nullptr)) {
        std::cerr << "Failed to get process base address: " << GetLastError() << std::endl;
        return 0;
    }

    return baseRequest.BaseAddress;
}

bool ReadProcessMemory(HANDLE hDevice, ULONG processId, ULONG address, PVOID buffer, ULONG size) {
    KERNEL_READ_REQUEST readRequest = { 0 };
    readRequest.ProcessId = processId;
    readRequest.Address = address;
    readRequest.pBuffer = buffer;
    readRequest.Size = size;

    DWORD returned;
    if (!DeviceIoControl(hDevice, IOCTL_READ_MEMORY, &readRequest, sizeof(readRequest), &readRequest, sizeof(readRequest), &returned, nullptr)) {
        std::cerr << "Failed to read process memory: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}

bool WriteProcessMemory(HANDLE hDevice, ULONG processId, ULONG address, PVOID buffer, ULONG size) {
    KERNEL_WRITE_REQUEST writeRequest = { 0 };
    writeRequest.ProcessId = processId;
    writeRequest.Address = address;
    writeRequest.pBuffer = buffer;
    writeRequest.Size = size;

    DWORD returned;
    if (!DeviceIoControl(hDevice, IOCTL_WRITE_MEMORY, &writeRequest, sizeof(writeRequest), &writeRequest, sizeof(writeRequest), &returned, nullptr)) {
        std::cerr << "Failed to write process memory: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}

int main() {
    HANDLE hDevice = OpenDriver();
    if (hDevice == nullptr) {
        return 1;
    }

    ULONG processId = 1234; // Replace with the target process ID

    ULONG64 baseAddress = GetProcessBaseAddress(hDevice, processId);
    if (baseAddress == 0) {
        std::cerr << "Failed to get process base address." << std::endl;
        CloseHandle(hDevice);
        return 1;
    }
    std::cout << "Base Address: " << std::hex << baseAddress << std::endl;

    ULONG address = baseAddress + 0x1234; // Replace with the target address
    ULONG buffer = 0;
    if (!ReadProcessMemory(hDevice, processId, address, &buffer, sizeof(buffer))) {
        std::cerr << "Failed to read memory." << std::endl;
        CloseHandle(hDevice);
        return 1;
    }
    std::cout << "Read Value: " << std::hex << buffer << std::endl;

    ULONG newValue = 0xdeadbeef;
    if (!WriteProcessMemory(hDevice, processId, address, &newValue, sizeof(newValue))) {
        std::cerr << "Failed to write memory." << std::endl;
        CloseHandle(hDevice);
        return 1;
    }
    std::cout << "Memory written successfully." << std::endl;

    CloseHandle(hDevice);
    return 0;
}
