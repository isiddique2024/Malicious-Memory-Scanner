#include "verification/verification.hpp"
#include "report.hpp"

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

    types::memory_data_list malicious_regions;

    bool found_malicious_page = false;

    std::unordered_map<std::string, std::string> pattern_map = {
        {"CRT_DLL_STUB", encrypt("48 8B C4 48 89 58 20 4C 89 40 18 89 50 10 48 89 48 08 56 57 41 56 48 83 EC 40 49 8B F0 8B FA 4C 8B F1 85 D2 75 0F 39 15 ? ? ? ? 7F 07 33 C0 E9 ? ? ? ?").decrypt()},
        {"DLL_MANIFEST_STUB", encrypt("3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E").decrypt()}
    };

    auto is_matching_type(const MEMORY_BASIC_INFORMATION& mbi) -> bool
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

    auto get_region_info(PVOID addr) -> types::memory_data
    {
        MEMORY_BASIC_INFORMATION mbi;
        auto mbi_status = sys(NTSTATUS, NtQueryVirtualMemory).call(proc_handle, addr, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);

        MEMORY_REGION_INFORMATION mri;
        auto mri_status = sys(NTSTATUS, NtQueryVirtualMemory).call(proc_handle, addr, MemoryRegionInformation, &mri, sizeof(mri), nullptr);
        return std::make_tuple(mbi, mri, std::optional<std::string>());
    }

    public: 

    implants_scanner(void* proc_handle, unsigned long pid) : proc_handle(proc_handle), pid(pid) {};

    auto full_scan() -> types::memory_data_list
    {
        auto mod = util::get_remote_module_handle(pid);
        MODULEINFO mod_info;

        const auto status = fn(K32GetModuleInformation).get()(proc_handle, mod, &mod_info, sizeof(mod_info)); // replace with something of ntapi
        if (!status) {
            std::cout << encrypt("K32GetModuleInformation failed with status: 0x") << fn(GetLastError).get()() << std::endl;
            return {};
        }

        // get minimum/maximum usermode address
        SYSTEM_BASIC_INFORMATION sbi;
        auto ntqsi_status = sys(NTSTATUS, NtQuerySystemInformation).call(SystemBasicInformation, &sbi, sizeof(sbi), nullptr);
        if (!NT_SUCCESS(ntqsi_status)) {
            std::cout << encrypt("ntqsi on sbi fail with status: 0x ") << status << std::endl;
            return {};
        }

        auto curr_addr = sbi.MinimumUserModeAddress;
        const auto max_addr = sbi.MaximumUserModeAddress;
        MEMORY_BASIC_INFORMATION mbi;

        while (curr_addr < max_addr)
        {
            const auto mbi_status = sys(NTSTATUS, NtQueryVirtualMemory).call(proc_handle, reinterpret_cast<void*>(curr_addr), MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);
            if (!NT_SUCCESS(mbi_status)) {
                std::cout << encrypt("ntqvm on mbi fail with status: 0x") << status << std::endl;
                return {};
            }

            if (mbi.State != MEM_COMMIT) {
                curr_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }

            if (curr_addr >= (reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll)) && curr_addr <= (reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll) + mod_info.SizeOfImage)) { // skip main module exe range
                curr_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }

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
                            auto info = get_region_info(reinterpret_cast<void*>(curr_addr));
                            auto base = std::get<0>(info).AllocationBase;
                            auto commit_size = std::get<1>(info).CommitSize;
                            std::get<2>(info) = file_name;
                            std::cout << encrypt("unsigned module loaded: ") << std::get<2>(info).value() << std::endl;
                            malicious_regions.push_back(info);
                        }
                    }
                }

            };

            unsigned_module_detection();

            auto scan_executable_pages = [&]()
            {

                if (is_matching_type(mbi))
                {
                    auto info = get_region_info(mbi.BaseAddress);
                    
                    for (auto const& [type, signature] : pattern_map) {
                        auto allocation_address = reinterpret_cast<uintptr_t>(std::get<1>(info).AllocationBase);
                        auto size_of_region = std::get<1>(info).CommitSize;
                        auto addr = util::ida_pattern_scan(proc_handle, allocation_address, size_of_region, signature.c_str());

                        if (!addr) 
                            continue;

                        malicious_regions.push_back(info);

                        std::cout << type << encrypt(" stub ") << encrypt("found at address : 0x") << addr << std::endl;

                    }

                }
            };

            scan_executable_pages();

            curr_addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

            util::sleep(1);
        }

        return malicious_regions;
    }
};