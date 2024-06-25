#include "verification/verification.hpp"

/*  EAC Checked Memory Types :  https://github.com/Mes2d/EAC/blob/main/EasyAntiCheat.sys/cheatpages.c
[non - shared only] Executable. (MEM_PRIVATE && PAGE_EXECUTE)
[non - shared only]  Executable and read-only. (MEM_PRIVATE && PAGE_EXECUTE_READ)
[including shared]  Executable and read/write. (MEM_IMAGE || MEM_MAPPED) && PAGE_EXECUTE_READWRITE
[non - shared only]  Executable and copy-on-write. (MEM_PRIVATE && PAGE_EXECUTE_WRITECOPY)
[non - shared only]  Non-cacheable and executable. (MEM_PRIVATE && (PAGE_EXECUTE | PAGE_NOCACHE))
[non - shared only]  Non-cacheable, executable, and read-only. (MEM_PRIVATE && (PAGE_EXECUTE_READ | PAGE_NOCACHE))
[including shared]  Non-cacheable, executable, and read/write. (MEM_IMAGE || MEM_MAPPED) && (PAGE_EXECUTE_READWRITE | PAGE_NOCACHE)
[non - shared only]  Non-cacheable, executable, and copy-on-write. (MEM_PRIVATE && (PAGE_EXECUTE_WRITECOPY | PAGE_NOCACHE))
[non - shared only]  Guard page and executable. (MEM_PRIVATE && (PAGE_EXECUTE | PAGE_GUARD))
[non - shared only]  Guard page, executable, and read-only. (MEM_PRIVATE && (PAGE_EXECUTE_READ | PAGE_GUARD))
[including shared]  Guard page, executable, and read/write. (MEM_IMAGE || MEM_MAPPED) && (PAGE_EXECUTE_READWRITE | PAGE_GUARD)
[non - shared only]  Guard page, executable, and copy-on-write. (MEM_PRIVATE && (PAGE_EXECUTE_WRITECOPY | PAGE_GUARD))
[non - shared only]  Non-cacheable, guard page, and executable. (MEM_PRIVATE && (PAGE_EXECUTE | PAGE_NOCACHE | PAGE_GUARD))
[non - shared only]  Non-cacheable, guard page, executable, and read-only. (MEM_PRIVATE && (PAGE_EXECUTE_READ | PAGE_NOCACHE | PAGE_GUARD))
[including shared]  Non-cacheable, guard page, executable, and read/write. (MEM_IMAGE || MEM_MAPPED) && (PAGE_EXECUTE_READWRITE | PAGE_NOCACHE | PAGE_GUARD)
[non - shared only]  Non-cacheable, guard page, executable, and copy-on-write. (MEM_PRIVATE && (PAGE_EXECUTE_WRITECOPY | PAGE_NOCACHE | PAGE_GUARD))
*/

class implants_scanner 
{
    private:

    void* proc_handle;
    unsigned long pid;

    std::vector<std::tuple<uintptr_t, SIZE_T>> malicious_regions;
    bool found_malicious_page = false;

    std::unordered_map<std::string, std::string> pattern_map = {
        {"CRT_DLL_STUB", encrypt("48 8B C4 48 89 58 20 4C 89 40 18 89 50 10 48 89 48 08 56 57 41 56 48 83 EC 40 49 8B F0 8B FA 4C 8B F1 85 D2 75 0F 39 15 ? ? ? ? 7F 07 33 C0 E9 ? ? ? ?").decrypt()},
        {"DLL_MANIFEST_STUB", encrypt("3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E").decrypt()}
    };

    __forceinline auto is_matching_type(const MEMORY_BASIC_INFORMATION& mbi) -> bool
    {
        bool shared = (mbi.Type == MEM_IMAGE) || (mbi.Type == MEM_MAPPED);
        bool non_shared = (mbi.Type == MEM_PRIVATE);

        return
            (non_shared && (mbi.Protect == PAGE_EXECUTE)) ||                                         // Executable. (MEM_PRIVATE && PAGE_EXECUTE)
            (non_shared && (mbi.Protect == PAGE_EXECUTE_READ)) ||                                    // Executable and read-only. (MEM_PRIVATE && PAGE_EXECUTE_READ)
            (shared && (mbi.Protect == PAGE_EXECUTE_READWRITE)) ||                                   // Executable and read/write. (including shared)
            (non_shared && (mbi.Protect == PAGE_EXECUTE_WRITECOPY)) ||                               // Executable and copy-on-write. (MEM_PRIVATE && PAGE_EXECUTE_WRITECOPY)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE | PAGE_NOCACHE))) ||                        // Non-cacheable and executable. (MEM_PRIVATE && PAGE_EXECUTE | PAGE_NOCACHE)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE_READ | PAGE_NOCACHE))) ||                   // Non-cacheable, executable, and read-only. (MEM_PRIVATE && PAGE_EXECUTE_READ | PAGE_NOCACHE)
            (shared && (mbi.Protect == (PAGE_EXECUTE_READWRITE | PAGE_NOCACHE))) ||                  // Non-cacheable, executable, and read/write. (including shared)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE_WRITECOPY | PAGE_NOCACHE))) ||              // Non-cacheable, executable, and copy-on-write. (MEM_PRIVATE && PAGE_EXECUTE_WRITECOPY | PAGE_NOCACHE)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE | PAGE_GUARD))) ||                          // Guard page and executable. (MEM_PRIVATE && PAGE_EXECUTE | PAGE_GUARD)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE_READ | PAGE_GUARD))) ||                     // Guard page, executable, and read-only. (MEM_PRIVATE && PAGE_EXECUTE_READ | PAGE_GUARD)
            (shared && (mbi.Protect == (PAGE_EXECUTE_READWRITE | PAGE_GUARD))) ||                    // Guard page, executable, and read/write. (including shared)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE_WRITECOPY | PAGE_GUARD))) ||                // Guard page, executable, and copy-on-write. (MEM_PRIVATE && PAGE_EXECUTE_WRITECOPY | PAGE_GUARD)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE | PAGE_NOCACHE | PAGE_GUARD))) ||           // Non-cacheable, guard page, and executable. (MEM_PRIVATE && PAGE_EXECUTE | PAGE_NOCACHE | PAGE_GUARD)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE_READ | PAGE_NOCACHE | PAGE_GUARD))) ||      // Non-cacheable, guard page, executable, and read-only. (MEM_PRIVATE && PAGE_EXECUTE_READ | PAGE_NOCACHE | PAGE_GUARD)
            (shared && (mbi.Protect == (PAGE_EXECUTE_READWRITE | PAGE_NOCACHE | PAGE_GUARD))) ||     // Non-cacheable, guard page, executable, and read/write. (including shared)
            (non_shared && (mbi.Protect == (PAGE_EXECUTE_WRITECOPY | PAGE_NOCACHE | PAGE_GUARD)));   // Non-cacheable, guard page, executable, and copy-on-write. (MEM_PRIVATE && PAGE_EXECUTE_WRITECOPY | PAGE_NOCACHE | PAGE_GUARD)
    }

    __forceinline auto get_region_and_size(PVOID addr) -> std::tuple<uintptr_t, SIZE_T>
    {
        MEMORY_REGION_INFORMATION mri;
        auto status = sys(NTSTATUS, NtQueryVirtualMemory).call(proc_handle, addr, MemoryRegionInformation, &mri, sizeof(mri), nullptr);
        return std::make_tuple(reinterpret_cast<uintptr_t>(mri.AllocationBase), mri.CommitSize);
    }


    __forceinline auto print_malicious_regions() -> void 
    {
        util::enable_console_color_support();
        for (const auto& region : malicious_regions) 
        {
            std::cout << "\033[31m" << "Region Base: 0x" << std::hex << get<0>(region) 
                << " Region Size: 0x" << std::hex << get<1>(region) 
                << "\033[0m" << std::endl;
        }
    }

    __forceinline auto dump_malicious_regions() -> void
    {
        auto dir_name = encrypt("memory_dumps").decrypt();
        if (fn(_mkdir).get()(dir_name) != 0 && errno != EEXIST) {
            std::cerr << encrypt("Failed to create memory dump directory: ") << dir_name << std::endl;
            return;
        }

        auto region_idx = 0;

        for (const auto& region : malicious_regions) {
            const auto base_address = std::get<0>(region);
            const auto region_size = std::get<1>(region);
            std::vector<char> buffer(region_size);
            unsigned long bytes_read;

            auto status = sys(NTSTATUS, NtReadVirtualMemory).call(proc_handle, reinterpret_cast<void*>(base_address), buffer.data(), region_size, &bytes_read);
            if (!NT_SUCCESS(status)) {
                std::cerr << encrypt("Failed to read memory at address: 0x") << std::hex << base_address
                    << encrypt(" Error: ") << status << std::endl;
                continue;
            }

            auto file_name = std::string(dir_name) + "/" + "pid_" + std::to_string(pid) + encrypt("_dmp_").decrypt() + std::to_string(region_idx) + encrypt(".bin").decrypt();
            std::ofstream dump_file(file_name, std::ios::binary);
            if (!dump_file.is_open()) {
                std::cerr << encrypt("Failed to open dump file: ").decrypt() << file_name << std::endl;
                continue;
            }

            dump_file.write(buffer.data(), bytes_read);
            dump_file.close();

            region_idx++;
        }
    }

    public: 

    implants_scanner(void* proc_handle, unsigned long pid) : proc_handle(proc_handle), pid(pid) {};

    auto scan_manual_map() -> int
    {
        std::cout << encrypt("Starting scan on PID: ") << pid << std::endl;
        //auto mod = fn(GetModuleHandleA).get()(NULL);
        auto mod = util::get_remote_module_handle(pid);
        
        MODULEINFO mod_info;

        const auto status = fn(K32GetModuleInformation).get()(proc_handle, mod, &mod_info, sizeof(mod_info)); // replace with something of ntapi
        if (!status) {
            std::cout << encrypt("K32GetModuleInformation failed with status: ") << fn(GetLastError).get()() << std::endl;
            return 0;
        }

        // get minimum/maximum usermode address
        SYSTEM_BASIC_INFORMATION sbi;
        auto ntqsi_status = sys(NTSTATUS, NtQuerySystemInformation).call(SystemBasicInformation, &sbi, sizeof(sbi), nullptr);
        if (!NT_SUCCESS(ntqsi_status)) {
            std::cout << encrypt("ntqsi on sbi fail with status: 0x ") << status << std::endl;
            return 0;
        }

        start:
        auto curr_addr = sbi.MinimumUserModeAddress;
        const auto max_addr = sbi.MaximumUserModeAddress;
        MEMORY_BASIC_INFORMATION mbi;

        while (curr_addr < max_addr)
        {
            const auto status = sys(NTSTATUS, NtQueryVirtualMemory).call(proc_handle, reinterpret_cast<void*>(curr_addr), MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
            if (!NT_SUCCESS(status)) {
                std::cout << encrypt("ntqvm on mbi fail with status: 0x") << status << std::endl;
                break;
            }

            curr_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

            if (mbi.State != MEM_COMMIT)
                continue;

            if (curr_addr >= (reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll)) && curr_addr <= (reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll) + mod_info.SizeOfImage)) // skip main module exe range
                continue;

            std::cout << encrypt("current address: 0x") << std::hex << curr_addr << std::endl;

            auto unsigned_module_detection = [&]() -> void
            {

                if (mbi.AllocationProtect == PAGE_EXECUTE_WRITECOPY) 
                {
                    MEMORY_MAPPED_FILE_NAME_INFORMATION mfn;

                    const auto status = sys(NTSTATUS, NtQueryVirtualMemory).call(proc_handle, reinterpret_cast<void*>(curr_addr), MemoryMappedFilenameInformation, &mfn, sizeof(mfn), nullptr);
                    if (NT_SUCCESS(status)) {

                        std::string file_name = util::device_path_to_dos_path(util::wstring_to_string(mfn.Buffer));

                        if (!verify_dll(util::string_to_wstring(file_name).c_str())) {
                            std::cout << encrypt("winverify failed and cat signature not found, unsigned module loaded: ") << file_name << std::endl;
                        }
                    }
                }

            };

            unsigned_module_detection();

            auto scan_malicious_pages = [&]()
            {

                if (is_matching_type(mbi))
                {
                    auto region_base_and_size = get_region_and_size(mbi.BaseAddress);
                    auto rwx_region_base = get<0>(region_base_and_size);
                    auto rwx_region_size = get<1>(region_base_and_size);
                    for (auto const& [key, value] : pattern_map) {
                        auto addr = util::ida_pattern_scan(proc_handle, rwx_region_base, rwx_region_size, value.c_str());
                        if (addr) { // crt stub pattern: 48 8B C4 48 89 58 20 4C 89 40 18 89 50 10 48 89 48 08 56 57 41 56 48 83 EC 40 49 8B F0 8B FA 4C 8B F1 85 D2 75 0F 39 15 ? ? ? ? 7F 07 33 C0 E9 ? ? ? ? // dll manifest: 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e
                            std::cout << key.c_str() << encrypt(" stub ") << encrypt("found at address : 0x") << addr << std::endl;
                            malicious_regions.push_back(region_base_and_size);
                        }
                    }

                }
            };

            scan_malicious_pages();

            util::sleep(10);

        }

        util::remove_duplicates_vector(malicious_regions);

        std::cout << encrypt("Done Scanning: ") << 
            (malicious_regions.empty() ? encrypt("No Malicious Regions Found").decrypt() : encrypt("Number of Potentially Malicious Regions Found: ").decrypt() + std::to_string(malicious_regions.size()))
            << std::endl;

        if (!malicious_regions.empty()) {
            std::cout << encrypt("Dumping Memory Regions:") << std::endl;
            print_malicious_regions();
            dump_malicious_regions();
        }

        return 1;
    }
};