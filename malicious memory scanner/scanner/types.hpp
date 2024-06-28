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
