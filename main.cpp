#include <iostream>
#include <vector>
#include <Windows.h>

#define INFO(x) std::cout << "[INFO] " << x << '\n';
#define ERROR(x) std::cout << "[ERROR] " << x << '\n';

// gets all the memory pages in a process using the handle we created
std::vector<MEMORY_BASIC_INFORMATION> GetMemoryPages(const HANDLE handle)
{
    // vector to store the memory pages
    std::vector<MEMORY_BASIC_INFORMATION> storage;

    // structure to store memory information
    MEMORY_BASIC_INFORMATION memInfo;

    // pointer to the memory address
    LPVOID memoryAddress = nullptr;

    // iterate thru each memory page
    while (VirtualQueryEx(handle, memoryAddress, &memInfo, sizeof(memInfo)) == sizeof(memInfo))
    {
        // store the memory information
        storage.push_back(memInfo);

        // move to the next memory address
        memoryAddress = (LPVOID)((ULONG_PTR) memInfo.BaseAddress + memInfo.RegionSize);
    }

    // return the memory pages
    return storage;
}

// this was very annoying
void ScanMemory(const HANDLE handle, const void* baseAddressToSearch, const int& valueToFind)
{

    // for each memory page
    for (const auto& page : GetMemoryPages(handle))
    {
        // lol autism
        if ((DWORD_PTR) baseAddressToSearch >= (DWORD_PTR) page.BaseAddress && (DWORD_PTR) baseAddressToSearch < ((DWORD_PTR) page.BaseAddress + page.RegionSize))
        {
            // Calculate the exact address to search within this page
            auto offsetFromBase = (DWORD_PTR) baseAddressToSearch - (DWORD_PTR)page.BaseAddress;
            auto addressToFind = (LPCVOID)((DWORD_PTR) page.BaseAddress + offsetFromBase);

            // check if we can access the memory (todo: figure out a bypass for this?)
            if (page.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            {
                SIZE_T bytesRead;
                int valueRead = 0;

                auto success = ReadProcessMemory(handle, addressToFind, &valueRead, sizeof(valueRead), &bytesRead);

                if (success && bytesRead == sizeof(valueRead))
                {
                    INFO("successfully read memory address: " << addressToFind << " value: " << valueRead);

                    if (valueRead == valueToFind)
                    {
                        INFO("found value " << valueToFind << " at address " << addressToFind);
                        break;
                    }
                }
                else
                {
                    ERROR("failed to read memory at address " << addressToFind << " error: " << GetLastError());
                }
            }
            else
            {
                ERROR("cannot access memory at address " << addressToFind << " protection flags prevent access ;(.")
            }
        }
    }
}

int main()
{

    // processId is the ID of the process to scan
    DWORD processId = 14092;
    //                ^^^ make sure to replace this with the process ID you want to scan fk idiots



    // create a handle to the process
    auto handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

    if (handle == nullptr)
    {
        ERROR("failed to get the handle to the process");
        return 1;
    }

    INFO("successfully got the handle to the process 0x%p" << handle);

    // iterate thru each memory page and print information
    for (const auto& memoryPage : GetMemoryPages(handle))
    {
        INFO("Memory Page Information");
        INFO("Base Address: " << memoryPage.BaseAddress);
        INFO("Region Size: " << memoryPage.RegionSize);
        INFO("State: " << memoryPage.State);
        INFO("Protect: " << memoryPage.Protect);
        INFO("Type: " << memoryPage.Type);
    }

    LPVOID baseAddress;

    INFO("enter the base address to search from (in hex):");
    std::cin >> std::hex >> baseAddress;

    int value;
    INFO("enter the value to search for: ")
    std::cin >> value;

    // scan the memory
    ScanMemory(handle, baseAddress, value);

    // IF there was a value found you could add ur own logic to write to the memory and manipulate it.


    // close the handle since we are done
    CloseHandle(handle);

    return 0;
}
