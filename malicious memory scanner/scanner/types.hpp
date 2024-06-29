#pragma once

namespace types 
{
	struct report 
	{
		struct
		{
			MEMORY_BASIC_INFORMATION mbi;
			MEMORY_REGION_INFORMATION mri;
			bool pageguard_or_noaccess;
		}memory_info;

		struct
		{
			std::vector<std::string> found_signatures;
			std::optional<std::string> packed_with;
			bool valid_header;
			bool valid_iat;
		}pe;

		std::optional<std::string> dll_path;
	};

	using report_list = std::vector<report>;

}
