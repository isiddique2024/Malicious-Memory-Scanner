namespace util 
{

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

    auto device_path_to_dos_path(const auto& device_path) -> std::string
    {
        char drive[3] = " :";
        std::string dos_path;
        for (drive[0] = 'A'; drive[0] <= 'Z'; drive[0]++) {
            char target_path[MAX_PATH] = { 0 };
            if (fn(QueryDosDeviceA).cached()(drive, target_path, MAX_PATH)) {
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

    auto get_remote_module_handle(unsigned long pid) -> HMODULE
    {
        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        MODULEENTRY32 me32;
        HMODULE mainModuleHandle = NULL;
        uintptr_t mainModuleBaseAddr = (uintptr_t)-1;

        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hModuleSnap == INVALID_HANDLE_VALUE) {
            std::cerr << "CreateToolhelp32Snapshot failed. Error Code: " << GetLastError() << std::endl;
            return 0;
        }

        me32.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hModuleSnap, &me32)) {
            do {
                if ((uintptr_t)me32.modBaseAddr < mainModuleBaseAddr) {
                    mainModuleBaseAddr = (uintptr_t)me32.modBaseAddr;
                    mainModuleHandle = me32.hModule;
                }
            } while (Module32Next(hModuleSnap, &me32));
        }
        else {
            std::cerr << "Module32First failed. Error Code: " << GetLastError() << std::endl;
        }

        sys(NTSTATUS, NtClose).call(hModuleSnap);
        return mainModuleHandle;
    }

    __forceinline auto ida_pattern_scan(void* proc_handle, types::report& report, const char* signature) -> uintptr_t
    {
        static auto pattern_to_byte = [](const char* pattern)
            {
                auto bytes = std::vector<char>{};
                auto start = const_cast<char*>(pattern);
                auto end = const_cast<char*>(pattern) + strlen(pattern);

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

        auto pattern_bytes = pattern_to_byte(signature);
        auto pattern_length = pattern_bytes.size();
        auto data = pattern_bytes.data();
        std::vector<char> bytes_buffer(report.mri.CommitSize);

        auto status = sys(NTSTATUS, NtReadVirtualMemory).call(proc_handle, report.mri.AllocationBase, bytes_buffer.data(), report.mri.CommitSize, NULL);
        if (!NT_SUCCESS(status))
        {
            if (status == 0x8000000d)
            {
                report.pageguard_or_noaccess = true;
            }

            std::cerr << encrypt("Failed to read memory at address: 0x") << std::hex << report.mri.AllocationBase
                << encrypt(", Error Code: ") << status << std::endl;

            return 0;
        }

        for (uintptr_t i = 0; i <= report.mri.CommitSize - pattern_length; i++)
        {
            bool found = true;
            for (uintptr_t j = 0; j < pattern_length; j++)
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


    auto found_header(void* process_handle, types::report& report) -> bool
    {
        unsigned char buffer[0x1000]; // size of PE header
        auto base = report.mbi.AllocationBase;
        if (!NT_SUCCESS(sys(NTSTATUS, NtReadVirtualMemory).call(process_handle, base, buffer, sizeof(buffer), nullptr))) {
            std::cerr << "Failed to read memory at address: " << base << "\n";
            return false;
        }

        auto header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
        if (header->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Invalid PE header" << std::endl;
            return false;
        }

        return true;
    }

    auto enable_console_color_support() -> void
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to get console handle" << std::endl;
            return;
        }
        DWORD mode;
        if (!GetConsoleMode(hConsole, &mode)) {
            std::cerr << "Failed to get console mode" << std::endl;
            return;
        }

        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (!SetConsoleMode(hConsole, mode)) {
            std::cerr << "Failed to set console mode" << std::endl;
            return;
        }
    }

    auto remove_duplicates_vector(types::report_list& report) -> void
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


}