#pragma once

namespace types {
	using memory_data = std::tuple<MEMORY_BASIC_INFORMATION, MEMORY_REGION_INFORMATION, std::optional<std::string>>; // MEMORY_BASIC_INFORMATION, MEMORY_REGION_INFORMATION, Dll Path (Optional)
	using memory_data_list = std::vector<memory_data>;
}