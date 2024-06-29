#include "stdafx.h"
#include "scanner/scanner.hpp"

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << encrypt("Usage: ") << argv[0] << encrypt(" <PID>") << std::endl;
        return 1;
    }

    unsigned long pid = atoi(argv[1]);

    void* proc_handle;

    const auto status = util::proc::open_process(pid, proc_handle);

    if (!NT_SUCCESS(status)) 
    {
        std::cerr << encrypt("Failed to open process on PID: ") << pid << encrypt(" , Error Code: ") << status << std::endl;
        return 0;
    }

    imp<HMODULE>("LoadLibraryA", "Wintrust.dll"); // load Wintrust.dll to use for signature verification later

    util::console::enable_console_color_support();

    std::cout << encrypt("Starting full image scan on PID: ") << pid << std::endl;

    implants_scanner scanner(proc_handle, pid);
    auto malicious_data = scanner.full_scan();

    if (malicious_data.empty()) {
        std::cout << encrypt("Done Scanning: ") << encrypt("No Malicious Regions Found").decrypt() << std::endl;
        return 0;
    }

    report::remove_duplicates(malicious_data); // removes duplicates for same dll path

    std::cout << std::endl << encrypt("Done Scanning: ") <<
        (encrypt("Number of Potentially Malicious Regions Found: \033[31m").decrypt() + std::to_string(malicious_data.size()))
        << "\033[0m" << std::endl;

    std::cout << std::endl << encrypt("Memory Scan Report:") << std::endl;

    report::print_malicious_regions(malicious_data);
    report::dump_malicious_regions(proc_handle, pid, malicious_data);

    sys<NTSTATUS>(
        "NtClose",
        proc_handle
    );

    return 0;
}