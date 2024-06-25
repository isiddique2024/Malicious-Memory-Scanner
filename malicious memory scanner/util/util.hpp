namespace util 
{

    __forceinline auto open_process(unsigned long pid, void*& handle) -> NTSTATUS 
    {
        CLIENT_ID cid;
        cid.UniqueProcess = reinterpret_cast<HANDLE>(pid);
        cid.UniqueThread = 0;

        OBJECT_ATTRIBUTES object_attributes;
        InitializeObjectAttributes(&object_attributes, 0, 0, 0, 0);

        const auto status = sys(NTSTATUS, NtOpenProcess).call(&handle, PROCESS_ALL_ACCESS, &object_attributes, &cid);

        return status;
    }
    __forceinline auto sleep(unsigned long milliseconds) -> void
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -(LONGLONG)milliseconds * 10000LL;
        sys(NTSTATUS, NtDelayExecution).cached_call(FALSE, &interval);
    }

    __forceinline std::string device_path_to_dos_path(const std::string& device_path) {
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

    __forceinline std::string wstring_to_string(const std::wstring& wstr) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        return converter.to_bytes(wstr);
    }

    __forceinline std::wstring string_to_wstring(const std::string& str) {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.from_bytes(str);
    }

    __forceinline auto get_remote_module_handle(unsigned long pid) -> HMODULE
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

    __forceinline auto ida_pattern_scan(void* proc_handle, uintptr_t base, uintptr_t image_size, const char* signature) -> uintptr_t
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
        std::vector<char> bytes_buffer(image_size);

        auto status = sys(NTSTATUS, NtReadVirtualMemory).call(proc_handle, base, bytes_buffer.data(), image_size, NULL);
        if (!NT_SUCCESS(status))
        {
            std::cerr << encrypt("Failed to read memory at address: 0x") << std::hex << base
                << encrypt(", Error Code: ") << status << std::endl;
            /*std::cerr << encrypt("Failed to read virtual memory, potential PAGE_GUARD or PAGE_NOACCESS flag found, Error Status:") << status << std::endl;*/
            return 0;
        }

        for (uintptr_t i = 0; i <= image_size - pattern_length; i++)
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
                return base + i;
            }
        }

        return 0;
    }

    __forceinline auto enable_console_color_support() {
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
        }
    }

    __forceinline auto remove_duplicates_vector(std::vector<std::tuple<uintptr_t, SIZE_T>>& vec) -> void
    {
        std::sort(vec.begin(), vec.end());
        const auto last = std::unique(vec.begin(), vec.end());
        vec.erase(last, vec.end());
    }


}