#include "stdafx.h"
#include "scanner/scanner.hpp"

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <PID>" << std::endl;
        return 1;
    }

    unsigned long pid = atoi(argv[1]);

    void* proc_handle;

    const auto status = util::open_process(pid, proc_handle);

    if (!NT_SUCCESS(status)) 
    {
        std::cerr << encrypt("Failed to open process on PID: ") << pid << " , Error Code: " << status << std::endl;
        return 0;
    }

    implants_scanner scanner(proc_handle, pid);
    scanner.scan_manual_map();

    sys(NTSTATUS, NtClose).call(proc_handle);

    return 0;
}