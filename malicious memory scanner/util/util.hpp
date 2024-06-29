namespace util 
{
    namespace proc {
        auto open_process(unsigned long pid, void*& handle) -> NTSTATUS
        {
            CLIENT_ID cid;
            cid.UniqueProcess = reinterpret_cast<HANDLE>(pid);
            cid.UniqueThread = 0;

            OBJECT_ATTRIBUTES object_attributes;
            InitializeObjectAttributes(&object_attributes, 0, 0, 0, 0);

            const auto status = sys<NTSTATUS>(
                "NtOpenProcess", 
                &handle, 
                PROCESS_ALL_ACCESS, 
                &object_attributes, 
                &cid
            );

            return status;
        }
        auto sleep(unsigned long milliseconds) -> void
        {
            LARGE_INTEGER interval;
            interval.QuadPart = -(LONGLONG)milliseconds * 10000LL;

            sys<NTSTATUS>(
                "NtDelayExecution", 
                FALSE, 
                &interval
            );
        }


    }
    namespace str {
        auto device_path_to_dos_path(const auto& device_path) -> std::string
        {
            char drive[3] = " :";
            std::string dos_path;
            for (drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++) {
                char target_path[512] = { 0 }; //MAX_PATH
                if (imp<DWORD>("QueryDosDeviceA", drive, target_path, 512)) {
                    // Check if the devicePath starts with the target path
                    if (device_path.find(target_path) == 0) {
                        dos_path = device_path;
                        // Replace the `\Device\HarddiskVolumeX` part with the DOS drive letter
                        dos_path.replace(0, strlen(target_path), drive);
                        return dos_path;
                    }
                }
            }
            return device_path;
        }

        auto ends_with_dll(const std::string& str) -> bool
        {
            const std::string suffix = encrypt(".dll").decrypt();
            if (str.length() >= suffix.length()) {
                return (0 == str.compare(str.length() - suffix.length(), suffix.length(), suffix));
            }
            else {
                return false;
            }
        }

        auto wstring_to_string(const auto& wstr) -> std::string
        {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            return converter.to_bytes(wstr);
        }

        auto string_to_wstring(const auto& str) -> std::wstring
        {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            return converter.from_bytes(str);
        }
    }

    namespace mem {
        auto is_executable(const auto& protection, const auto& shared) -> bool
        {
            if (!shared)
            {
                switch (protection)
                {
                case 2:  // Executable.
                case 3:  // Executable and read-only.
                case 7:  // Executable and copy-on-write.
                case 10: // Non-cacheable and executable.
                case 11: // Non-cacheable, executable, and read-only.
                case 15: // Non-cacheable, executable, and copy-on-write.
                case 18: // Guard page and executable.
                case 19: // Guard page, executable, and read-only.
                case 23: // Guard page, executable, and copy-on-write.
                case 26: // Non-cacheable, guard page, and executable.
                case 27: // Non-cacheable, guard page, executable, and read-only.
                case 31: // Non-cacheable, guard page, executable, and copy-on-write.
                    return true;
                default:
                    break;
                }
            }

            switch (protection)
            {
            case 6:  // Executable and read/write.
            case 14: // Non-cacheable, executable, and read/write.
            case 22: // Guard page, executable, and read/write.
            case 30: // Non-cacheable, guard page, executable, and read/write.
                return true;
            default:
                return false;
            }
        }

        // thank you process hacker
        __forceinline auto get_proc_working_set_info(void* proc_handle, PMEMORY_WORKING_SET_INFORMATION* wsi) -> NTSTATUS
        {

            NTSTATUS status;
            uintptr_t buffer_size = 0x8000;

            std::unique_ptr<unsigned char[]> buffer(new unsigned char[buffer_size]);

            while ((status = sys<NTSTATUS>(
                "NtQueryVirtualMemory",
                proc_handle,
                NULL,
                MemoryWorkingSetInformation,
                buffer.get(),
                buffer_size,
                NULL
            )) == STATUS_INFO_LENGTH_MISMATCH)
            {
                buffer_size *= 2;

                if (buffer_size > LARGE_BUFFER_SIZE)
                    return STATUS_INSUFFICIENT_RESOURCES;

                buffer.reset(new unsigned char[buffer_size]);
            }

            if (!NT_SUCCESS(status))
            {
                return status;
            }

            *wsi = reinterpret_cast<PMEMORY_WORKING_SET_INFORMATION>(buffer.release());

            return status;
        }

        auto validate_header(void* process_handle, types::report& report) -> bool
        {
            unsigned char buffer[0x1000]; // size of PE header
            const auto base = report.memory_info.mbi.AllocationBase;
            const auto status = sys<NTSTATUS>(
                "NtReadVirtualMemory", 
                process_handle, 
                base, 
                buffer, 
                sizeof(buffer), 
                nullptr
            );

            if (!NT_SUCCESS(status)) {
                std::cerr << encrypt("Failed to read memory at address: ") << base << "\n";
                return false;
            }

            const auto header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
            if (header->e_magic != IMAGE_DOS_SIGNATURE) {
                std::cerr << encrypt("Invalid PE header") << std::endl;
                return false;
            }

            return true;
        }

        __forceinline auto ida_pattern_scan(void* proc_handle, types::report& report, const char* signature) -> uintptr_t
        {
            static auto pattern_to_byte = [](const char* pattern)
            {
                auto bytes = std::vector<char>{};
                const auto start = const_cast<char*>(pattern);
                const auto end = const_cast<char*>(pattern) + strlen(pattern);

                for (auto current = start; current < end; ++current)
                {
                    if (*current == '?')
                    {
                        ++current;
                        if (*current == '?')
                            ++current;
                        bytes.push_back('\?');
                    }
                    else
                    {
                        bytes.push_back(strtoul(current, &current, 16));
                    }
                }
                return bytes;
            };
            const auto base = report.memory_info.mri.AllocationBase;
            const auto commit_size = report.memory_info.mri.CommitSize;
            const auto pattern_bytes = pattern_to_byte(signature);
            const auto pattern_length = pattern_bytes.size();
            const auto data = pattern_bytes.data();
            std::vector<char> bytes_buffer(report.memory_info.mri.CommitSize);

            const auto status = sys<NTSTATUS>(
                "NtReadVirtualMemory", 
                proc_handle, 
                base,
                bytes_buffer.data(), 
                commit_size,
                NULL
            );

            if (!NT_SUCCESS(status))
            {
                if (status == 0x8000000D)
                {
                    std::cerr << encrypt("\033[31mFailed to read memory at address: 0x") << std::hex << report.memory_info.mri.AllocationBase
                        << encrypt(", PAGE_GUARD or PAGE_NOACCESS Found\033[0m") << std::endl;
                    report.memory_info.pageguard_or_noaccess = true;
                    return 0;
                }

                std::cerr << encrypt("\033[31mFailed to read memory at address: 0x\033[0m") << std::hex << report.memory_info.mri.AllocationBase
                    << encrypt(", Error Code: ") << status << std::endl;

                return 0;
            }

            for (auto i = 0; i <= commit_size - pattern_length; i++)
            {
                auto found = true;
                for (auto j = 0; j < pattern_length; j++)
                {
                    char a = '\?';
                    char b = bytes_buffer[i + j];
                    found &= data[j] == a || data[j] == b;
                }
                if (found)
                {
                    return reinterpret_cast<uintptr_t>(base) + i;
                }
            }

            return 0;
        }

    }
    namespace console {
        auto enable_console_color_support() -> void
        {
            const auto console_handle = imp<HANDLE>("GetStdHandle", STD_OUTPUT_HANDLE);
            if (console_handle == INVALID_HANDLE_VALUE) {
                std::cerr << encrypt("Failed to get console handle") << std::endl;
                return;
            }
            unsigned long mode;
            if (!(imp<BOOL>("GetConsoleMode", console_handle, &mode))) 
            {
                std::cerr << encrypt("Failed to get console mode") << std::endl;
                return;
            }

            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if (!(imp<BOOL>("SetConsoleMode", console_handle, mode))) {
                std::cerr << encrypt("Failed to set console mode") << std::endl;
                return;
            }
        }
    }


}