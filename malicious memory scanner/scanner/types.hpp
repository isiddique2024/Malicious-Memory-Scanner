#pragma once

namespace types 
{
	struct report {
		MEMORY_BASIC_INFORMATION mbi;
		MEMORY_REGION_INFORMATION mri;
		std::optional<std::string> dll_path;
		std::vector<std::string> found_signatures;
		std::optional<std::string> packed_with;
		bool valid_header;
		bool pageguard_or_noaccess;
	};

	using report_list = std::vector<report>;

}

namespace signatures 
{

	std::unordered_map<std::string, std::string> packed_section =
	{
		{encrypt("VMProtect").decrypt(), encrypt(".vmp0").decrypt()},
		{encrypt("Themida").decrypt(), encrypt(".themida").decrypt()},
		{encrypt("Code Virtualizer").decrypt(), encrypt(".vlizer").decrypt()},
		{encrypt("UPX0").decrypt(), encrypt("UPX0").decrypt()},
		{encrypt("UPX1").decrypt(), encrypt("UPX1").decrypt()},
	};
}