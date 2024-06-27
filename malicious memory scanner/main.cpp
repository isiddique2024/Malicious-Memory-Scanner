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

    util::enable_console_color_support();

    std::cout << encrypt("Starting full image scan on PID: ") << pid << std::endl;

    implants_scanner scanner(proc_handle, pid);
    auto malicious_data = scanner.full_scan();

    if (malicious_data.empty()) {
        std::cout << encrypt("Done Scanning: ") << encrypt("No Malicious Regions Found").decrypt() << std::endl;
        return 0;
    }

    util::remove_duplicates_vector(malicious_data); // removes duplicates for same dll path

    std::cout << encrypt("Done Scanning: ") <<
        (encrypt("Number of Potentially Malicious Regions Found: ").decrypt() + std::to_string(malicious_data.size()))
        << std::endl;

    std::cout << encrypt("\nDumping Memory Regions:") << std::endl;

    report::print_malicious_regions(malicious_data);
    report::dump_malicious_regions(proc_handle, pid, malicious_data);

    sys(NTSTATUS, NtClose).call(proc_handle);

    return 0;
}