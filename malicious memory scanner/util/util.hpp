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

            const auto status = sys(NTSTATUS, NtOpenProcess).call(&handle, PROCESS_ALL_ACCESS, &object_attributes, &cid);

            return status;
        }
        auto sleep(unsigned long milliseconds) -> void
        {
            LARGE_INTEGER interval;
            interval.QuadPart = -(LONGLONG)milliseconds * 10000LL;
            sys(NTSTATUS, NtDelayExecution).cached_call(FALSE, &interval);
        }


    }
    namespace str 
    {
        auto device_path_to_dos_path(const auto& device_path) -> std::string
        {
            char drive[3] = " :";
            std::string dos_path;
            for (drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++) {
                char target_path[512] = { 0 }; //MAX_PATH
                if (fn(QueryDosDeviceA).cached()(drive, target_path, 512)) {
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
            const std::string suffix = ".dll";
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
        // thank you process hacker
        auto get_proc_working_set_info(void* proc_handle, PMEMORY_WORKING_SET_INFORMATION* wsi) -> NTSTATUS
        {

            NTSTATUS status;
            uintptr_t buffer_size = 0x8000;

            std::unique_ptr<unsigned char[]> buffer(new unsigned char[buffer_size]);

            while ((status = sys(NTSTATUS, NtQueryVirtualMemory).call(
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
            const auto base = report.mbi.AllocationBase;
            if (!NT_SUCCESS(sys(NTSTATUS, NtReadVirtualMemory).call(process_handle, base, buffer, sizeof(buffer), nullptr))) {
                std::cerr << "Failed to read memory at address: " << base << "\n";
                return false;
            }

            const auto header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
            if (header->e_magic != IMAGE_DOS_SIGNATURE) {
                std::cerr << "Invalid PE header" << std::endl;
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

            const auto pattern_bytes = pattern_to_byte(signature);
            const auto pattern_length = pattern_bytes.size();
            const auto data = pattern_bytes.data();
            std::vector<char> bytes_buffer(report.mri.CommitSize);

            auto status = sys(NTSTATUS, NtReadVirtualMemory).call(proc_handle, report.mri.AllocationBase, bytes_buffer.data(), report.mri.CommitSize, NULL);
            if (!NT_SUCCESS(status))
            {
                if (status == 0x8000000D)
                {
                    report.pageguard_or_noaccess = true;
                }

                std::cerr << encrypt("Failed to read memory at address: 0x") << std::hex << report.mri.AllocationBase
                    << encrypt(", Error Code: ") << status << std::endl;

                return 0;
            }

            for (auto i = 0; i <= report.mri.CommitSize - pattern_length; i++)
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
                    return reinterpret_cast<uintptr_t>(report.mri.AllocationBase) + i;
                }
            }

            return 0;
        }

    }
    namespace console {
        auto enable_console_color_support() -> void
        {
            auto console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if (console_handle == INVALID_HANDLE_VALUE) {
                std::cerr << "Failed to get console handle" << std::endl;
                return;
            }
            unsigned long mode;
            if (!GetConsoleMode(console_handle, &mode)) {
                std::cerr << "Failed to get console mode" << std::endl;
                return;
            }

            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if (!SetConsoleMode(console_handle, mode)) {
                std::cerr << "Failed to set console mode" << std::endl;
                return;
            }
        }
    }


}