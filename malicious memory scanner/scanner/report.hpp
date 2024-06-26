#pragma once
namespace report {
    __forceinline auto dump_malicious_regions(void* proc_handle, unsigned long pid, types::memory_data_list& malicious_regions) -> void
    {
        auto dir_name = encrypt("memory_dumps").decrypt();
        auto create_dir = [&](const auto& dir_name)
        {
            return (fn(_mkdir).get()(dir_name) == 0 || errno == EEXIST) ? true : (std::cerr << "Failed to create memory dump directory: " << dir_name << std::endl, false);
        };

        if (!create_dir(dir_name)) {
            return;
        }

        auto region_idx = 0;

        for (const auto& region : malicious_regions) 
        {
            auto base_address = std::get<1>(region).AllocationBase;
            auto region_size = std::get<1>(region).CommitSize;
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

    __forceinline auto print_malicious_regions(types::memory_data_list& malicious_regions) -> void
    {
        for (const auto& region : malicious_regions)
        {
            std::cout << "\033[31m" << "Allocation Base: 0x" << std::hex << get<1>(region).AllocationBase
                << " Commit Size: 0x" << std::hex << get<1>(region).CommitSize
                << "\033[0m ";

                if (std::get<2>(region).has_value()) {
                    std::cout << "Dll Path: " << std::get<2>(region).value();
                }

                std::cout << std::endl;
        }
    }
}