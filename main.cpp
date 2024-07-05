#include <iostream>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>

#define INFO(x) std::cout << "[INFO] " << x << '\n'
#define ERROR(x) std::cerr << "[ERROR] " << x << '\n'

std::vector<MEMORY_BASIC_INFORMATION> GetReadableWritableMemoryPages(const HANDLE handle) {
    std::vector<MEMORY_BASIC_INFORMATION> storage;
    MEMORY_BASIC_INFORMATION memInfo;
    LPVOID memoryAddress = nullptr;

    while (VirtualQueryEx(handle, memoryAddress, &memInfo, sizeof(memInfo)) == sizeof(memInfo))
    {
        if (memInfo.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        {
            storage.push_back(memInfo);
        }

        memoryAddress = (LPVOID)((ULONG_PTR) memInfo.BaseAddress + memInfo.RegionSize);
    }

    return storage;
}

LPVOID ScanMemory(const HANDLE handle, const int& valueToFind) {
    for (const auto& page : GetReadableWritableMemoryPages(handle)) {
        for (auto address = (DWORD_PTR) page.BaseAddress;
             address < (DWORD_PTR) page.BaseAddress + page.RegionSize;
             address += sizeof(int))
        {
            int valueRead = 0;
            SIZE_T bytesRead;
            auto success = ReadProcessMemory(handle, (LPCVOID)address, &valueRead, sizeof(valueRead), &bytesRead);

            if (success && bytesRead == sizeof(valueRead))
            {
                if (valueRead == valueToFind)
                {
                    INFO("Found value " << valueToFind << " at address " << (void*)address);
                    return (LPVOID)address;
                }
            }
        }
    }

    ERROR("Value " << valueToFind << " not found in any readable/writable memory pages.");
    return nullptr;
}

void VerifyAndModifyValue(const HANDLE handle, LPVOID address, int newValue)
{
    int valueRead = 0;
    SIZE_T bytesRead;

    if (ReadProcessMemory(handle, address, &valueRead, sizeof(valueRead), &bytesRead))
    {
        INFO("Value before modification: " << valueRead << " at address " << address);

        DWORD oldProtect;

        if (VirtualProtectEx(handle, address, sizeof(newValue), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            if (WriteProcessMemory(handle, address, &newValue, sizeof(newValue), &bytesRead))
            {
                INFO("Successfully wrote new value " << newValue << " to address " << address);
            }
            else
            {
                ERROR("Failed to write new value to address " << address << " error: " << GetLastError());
            }

            VirtualProtectEx(handle, address, sizeof(newValue), oldProtect, &oldProtect);
        } else {
            ERROR("Failed to change memory protection at address " << address << " error: " << GetLastError());
        }

        if (ReadProcessMemory(handle, address, &valueRead, sizeof(valueRead), &bytesRead))
        {
            INFO("Value after modification: " << valueRead << " at address " << address);
        }
        else
        {
            ERROR("Failed to read memory at address " << address << " error: " << GetLastError());
        }
    }
    else
    {
        ERROR("Failed to read memory at address " << address << " error: " << GetLastError());
    }
}

DWORD GetProcessId(const std::string& processName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE) 
        {
            if (std::string(entry.szExeFile) == processName) 
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

int main()
{
    DWORD processId = GetProcessId("javaw.exe");

    auto handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId);

    if (handle == nullptr)
    {
        ERROR("Failed to get the handle to the process");
        return 1;
    }

    INFO("Successfully got the handle to the process 0x" << handle);


    LPVOID foundAddress = ScanMemory(handle, 121212);

    if (foundAddress != nullptr)
    {
        int newValue = 69;
        VerifyAndModifyValue(handle, foundAddress, newValue);
    }

    CloseHandle(handle);

    return 0;
}
