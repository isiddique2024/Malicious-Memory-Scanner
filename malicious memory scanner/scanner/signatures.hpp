#pragma once
namespace signatures {


    std::unordered_map<std::string, std::string> dll_signatures =
    {
        {encrypt("CRT").decrypt(), encrypt("48 8B C4 48 89 58 20 4C 89 40 18 89 50 10 48 89 48 08 56 57 41 56 48 83 EC 40 49 8B F0 8B FA 4C 8B F1 85 D2 75 0F 39 15 ? ? ? ? 7F 07 33 C0 E9 ? ? ? ?").decrypt()},
        {encrypt("DLL MANIFEST").decrypt(), encrypt("3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E").decrypt()}
    };

    std::unordered_map<std::string, std::string> packer_signatures =
    {
        {encrypt("VMProtect").decrypt(), encrypt("2E 76 6D 70 30").decrypt()},
        {encrypt("Themida").decrypt(), encrypt("2E 74 68 65 6D 69 64 61").decrypt()},
        {encrypt("Code Virtualizer").decrypt(), encrypt("2E 76 6C 69 7A 65 72").decrypt()},
        {encrypt("UPX0").decrypt(), encrypt("55 50 58 30").decrypt()},
        {encrypt("UPX1").decrypt(), encrypt("55 50 58 31").decrypt()}
    };

    __forceinline auto find_dll_signatures(void* proc_handle, types::report& report) -> bool
    {
        for (const auto& [type, signature] : dll_signatures)
        {
            const auto allocation_address = reinterpret_cast<uintptr_t>(report.memory_info.mri.AllocationBase);
            const auto size_of_region = report.memory_info.mri.CommitSize;

            const auto pattern_found = util::mem::ida_pattern_scan(proc_handle, report, signature.c_str()); 

            if (pattern_found)
            {
                report.pe.found_signatures.push_back(type.c_str());

                std::cout << type << encrypt(" stub ") << encrypt("found at address : 0x") << pattern_found << std::endl;

                return true;
            }
        }
        return false;
    }

    __forceinline auto find_packer_signatures(void* proc_handle, types::report& report) -> bool 
    {
        for (const auto& [type, signature] : packer_signatures)
        {
            const auto pattern_found = util::mem::ida_pattern_scan(proc_handle, report, signature.c_str());

            if (pattern_found)
            {
                report.pe.packed_with = type;

                std::cout << encrypt("0x") << std::hex << report.memory_info.mri.AllocationBase << encrypt(" packed with : ") << report.pe.packed_with.value() << std::endl;

                return true;
            }
        }
        return false;
    }
}