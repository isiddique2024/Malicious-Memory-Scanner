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

    struct module_info 
    {
        std::wstring dll_path;
        void* address;
    };

    std::vector<module_info> module_path_list;
    types::report_list malicious_regions;

    auto generate_report(void* addr) -> types::report
    {
        MEMORY_BASIC_INFORMATION mbi;
        const auto mbi_status = sys<NTSTATUS>(
            "NtQueryVirtualMemory", 
            proc_handle, 
            addr, 
            MemoryBasicInformation, 
            &mbi, 
            sizeof(mbi), 
            nullptr
        );

        MEMORY_REGION_INFORMATION mri;
        const auto mri_status = sys<NTSTATUS>(
            "NtQueryVirtualMemory", 
            proc_handle, 
            addr, 
            MemoryRegionInformation, 
            &mri, 
            sizeof(mri), 
            nullptr
        );

        types::report report = {};

        report.memory_info.mbi = mbi;
        report.memory_info.mri = mri;

        return report;
    }

    public: 

    implants_scanner(void* proc_handle, unsigned long pid) : proc_handle(proc_handle), pid(pid) {};

    auto full_scan() -> types::report_list
    {
        PMEMORY_WORKING_SET_INFORMATION wsi = nullptr;
        const auto wsi_status = util::mem::get_proc_working_set_info(proc_handle, &wsi);
        if (!NT_SUCCESS(wsi_status)) 
        {
            std::cerr << encrypt("Failed to get working set information for process") << std::endl;
            return {};
        }

        for (auto i = 0; i < wsi->NumberOfEntries; i++)
        {
            const auto current_address = wsi->WorkingSetInfo[i].VirtualPage << 12;
            const auto protection = wsi->WorkingSetInfo[i].Protection;
            const auto shared = wsi->WorkingSetInfo[i].Shared;

            //std::cout << "curr address: 0x" << std::hex << current_address << std::endl;

            if (util::mem::is_executable(protection, shared)) 
            {
                std::cout << encrypt("\033[31mExecutable Memory at Address: 0x") << std::hex << current_address << encrypt("\033[0m") << std::endl;

                auto report = generate_report(reinterpret_cast<void*>(current_address));

                const auto found_signature = signatures::find_dll_signatures(proc_handle, report);
                const auto found_packer = signatures::find_packer_signatures(proc_handle, report);
                const auto pageguard_or_noaccess = report.memory_info.pageguard_or_noaccess;

                if (found_signature || found_packer || pageguard_or_noaccess) {

                    report.pe.valid_header = util::mem::validate_header(proc_handle, report);
                    malicious_regions.push_back(report);
                }
            }

            auto unsigned_module_detection = [&]() -> void
            {
                MEMORY_MAPPED_FILE_NAME_INFORMATION mfn;
                const auto mmfni_status = sys<NTSTATUS>(
                    "NtQueryVirtualMemory", 
                    proc_handle, 
                    reinterpret_cast<void*>(current_address), 
                    MemoryMappedFilenameInformation, 
                    &mfn, 
                    sizeof(mfn), 
                    nullptr
                );

                if (NT_SUCCESS(mmfni_status))
                {
                    const auto file_name = util::str::device_path_to_dos_path(util::str::wstring_to_string(mfn.Buffer));
                    const auto wfile_name = util::str::string_to_wstring(file_name);
                    if (util::str::ends_with_dll(file_name))
                    {
                        // dont add to module_path_list if it already exists in there
                        auto it = std::find_if(module_path_list.begin(), module_path_list.end(),
                            [&wfile_name](const auto& mod) {
                                return mod.dll_path == wfile_name;
                            }
                        );

                        if (it == module_path_list.end()) {
                            module_info mod = {};
                            mod.dll_path = wfile_name;
                            mod.address = reinterpret_cast<void*>(current_address);

                            module_path_list.push_back(mod);
                        }
                    }
                }
            };

            unsigned_module_detection();
                
        }

        std::cout << std::endl << encrypt("Finished Scanning Executable Memory, Verifying Loaded Modules:") << std::endl << std::endl;

        if (!module_path_list.empty()) 
        {
            for (const auto& module : module_path_list) 
            {
                std::wcout << module.dll_path << std::endl;
                if (!verification::verify_dll(module.dll_path))
                {
                    auto report = generate_report(reinterpret_cast<void*>(module.address));
                    report.dll_path = util::str::wstring_to_string(module.dll_path);
                    signatures::find_packer_signatures(proc_handle, report);
                    report.pe.valid_header = util::mem::validate_header(proc_handle, report);
                    malicious_regions.push_back(report);

                    std::cout << std::endl << encrypt("\033[31mUnsigned Module Loaded : ") << report.dll_path.value() << "\033[0m" << std::endl << std::endl;
                }
            }
        }

        return malicious_regions;
    }
};