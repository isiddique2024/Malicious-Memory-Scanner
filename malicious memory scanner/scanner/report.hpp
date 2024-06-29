#pragma once
namespace report 
{
    auto remove_duplicates(auto& report) -> void
    {
        auto compare = [](const auto& lhs, const auto& rhs) {
            return lhs.dll_path < rhs.dll_path;
        };

        auto equal = [](const auto& lhs, const auto& rhs) {
            return lhs.dll_path == rhs.dll_path;
        };

        std::sort(report.begin(), report.end(), compare);
        auto last = std::unique(report.begin(), report.end(), equal);
        report.erase(last, report.end());
    }

    auto protection_to_string(unsigned long protect) -> std::string
    {
        switch (protect)
        {
            case PAGE_EXECUTE: return encrypt("\033[31m X \033[0m").decrypt();
            case PAGE_EXECUTE_READ: return encrypt("\033[31m RX \033[0m").decrypt();
            case PAGE_EXECUTE_READWRITE: return encrypt("\033[31m RWX \033[0m").decrypt();
            case PAGE_EXECUTE_WRITECOPY: return encrypt("\033[33m WCX \033[0m").decrypt();
            case PAGE_NOACCESS: return encrypt("\033[31m NA \033[0m").decrypt();
            case PAGE_READONLY: return encrypt(" R ").decrypt();
            case PAGE_READWRITE: return encrypt(" RW ").decrypt();
            case PAGE_WRITECOPY: return encrypt("\033[33m WC \033[0m").decrypt();
            case PAGE_GUARD: return encrypt("\033[0m G \033[0m").decrypt();
            case PAGE_NOCACHE: return encrypt(" NC ").decrypt();
            case PAGE_WRITECOMBINE: return encrypt("\033[33m WC \033[0m").decrypt();
            default: return encrypt(" UNKNOWN ").decrypt();
        };
    }

    auto type_to_string(unsigned long type) -> std::string 
    {
        switch (type) 
        {
            case MEM_IMAGE: return encrypt("Yes (MEM_IMAGE)").decrypt();
            case MEM_MAPPED: return encrypt("Yes (MEM_MAPPED)").decrypt();
            case MEM_PRIVATE: return encrypt("No (MEM_PRIVATE)").decrypt();
        };
    }

    auto dump_malicious_regions(void* proc_handle, unsigned long pid, types::report_list& malicious_regions) -> void
    {
        const auto dir_name = encrypt("memory_dumps").decrypt();
        auto create_dir = [&](const auto& dir_name)
        {
            return (imp<int>("_mkdir",dir_name) == 0 || errno == EEXIST) ? true : (std::cerr << encrypt("Failed to create memory dump directory: ").decrypt() << dir_name << std::endl, false);
        };

        if (!create_dir(dir_name)) {
            return;
        }

        auto region_idx = 0;

        for (const auto& region : malicious_regions) 
        {
            const auto base_address = region.memory_info.mbi.AllocationBase;
            const auto region_size = region.memory_info.mri.CommitSize;
            std::vector<char> buffer(region_size);
            unsigned long bytes_read;

            const auto status = sys<NTSTATUS>(
                "NtReadVirtualMemory", 
                proc_handle, 
                reinterpret_cast<void*>(base_address), 
                buffer.data(), 
                region_size, 
                &bytes_read
            );

            if (!NT_SUCCESS(status)) 
            {
                std::cerr << encrypt("Failed to read memory at address: 0x") << std::hex << base_address
                    << encrypt(" Error: ") << status << std::endl;
                continue;
            }

            const auto file_name = std::string(dir_name) + encrypt("/").decrypt() 
                + encrypt("pid_").decrypt() + std::to_string(pid) + encrypt("_dmp_").decrypt()
                + std::to_string(region_idx) + encrypt(".bin").decrypt();
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

    auto print_malicious_regions(types::report_list& malicious_regions) -> void
    {
        std::cout << encrypt("----------------------------------------").decrypt() << std::endl;
        for (const auto& region : malicious_regions)
        {
            const auto& mbi = region.memory_info.mbi;
            const auto& mri = region.memory_info.mri;
            const auto& dll_path = region.dll_path;
            const auto& found_signatures = region.pe.found_signatures;
            const auto& packed_with = region.pe.packed_with;

            std::cout << encrypt("Shared: ") << type_to_string(mbi.Type) << std::endl;
            std::cout << encrypt("Allocation Base: 0x") << std::hex << reinterpret_cast<uintptr_t>(mbi.AllocationBase) << std::endl;
            std::cout << encrypt("Base Address: 0x") << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << std::endl;
            std::cout << encrypt("Region Size: 0x") << std::hex << mbi.RegionSize << std::endl;
            std::cout << encrypt("Commit Size: 0x") << std::hex << mri.CommitSize << std::endl;
            std::cout << encrypt("Allocated Protection:") << protection_to_string(mbi.AllocationProtect) << std::endl;
            std::cout << encrypt("Current Protection:") << protection_to_string(mbi.Protect) << std::endl;
            std::cout << encrypt("Found Header:") << (region.pe.valid_header ? encrypt(" Yes").decrypt() : encrypt("\033[31m No \033[0m").decrypt()) << std::endl;
            std::cout << encrypt("Has PAGE_GUARD or PAGE_NOACCESS Flags:") << (region.memory_info.pageguard_or_noaccess ? encrypt("\033[31m Yes \033[0m").decrypt() : encrypt(" No").decrypt()) << std::endl;

            if (dll_path.has_value()) {
                std::cout << encrypt("Unsigned Module Path: ") << dll_path.value() << std::endl;
            }

            if (!found_signatures.empty()) {
                std::cout << encrypt("Found Signatures = {");
                for (const auto& sig : found_signatures) {
                    std::cout << sig;

                    if (&sig != &found_signatures.back())
                        std::cout << encrypt(", ");
                }
                std::cout << encrypt(" }") << std::endl;
            }

            if (packed_with.has_value()) {
                std::cout << encrypt("Packed With: \033[31m") << packed_with.value() << encrypt("\033[0m") << std::endl;
            }

            std::cout << encrypt("----------------------------------------") << std::endl;
        }
    }
}