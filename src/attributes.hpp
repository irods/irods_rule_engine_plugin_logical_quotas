#ifndef IRODS_LOGICAL_QUOTAS_ATTRIBUTES_HPP
#define IRODS_LOGICAL_QUOTAS_ATTRIBUTES_HPP

#include <fmt/format.h>

#include <string>

namespace irods
{
	class attributes final
	{
	  public:
		attributes(const std::string& _namespace,
		           const std::string& _maximum_number_of_data_objects,
		           const std::string& _maximum_size_in_bytes,
		           const std::string& _total_number_of_data_objects,
		           const std::string& _total_size_in_bytes)
			: maximum_number_of_data_objects_{fmt::format("{}::{}", _namespace, _maximum_number_of_data_objects)}
			, maximum_size_in_bytes_{fmt::format("{}::{}", _namespace, _maximum_size_in_bytes)}
			, total_number_of_data_objects_{fmt::format("{}::{}", _namespace, _total_number_of_data_objects)}
			, total_size_in_bytes_{fmt::format("{}::{}", _namespace, _total_size_in_bytes)}
		{
		}

		// clang-format off
		const std::string& maximum_number_of_data_objects() const { return maximum_number_of_data_objects_; }
		const std::string& maximum_size_in_bytes() const          { return maximum_size_in_bytes_; }
		const std::string& total_number_of_data_objects() const   { return total_number_of_data_objects_; }
		const std::string& total_size_in_bytes() const            { return total_size_in_bytes_; }
		// clang-format on

	  private:
		std::string maximum_number_of_data_objects_;
		std::string maximum_size_in_bytes_;
		std::string total_number_of_data_objects_;
		std::string total_size_in_bytes_;
	}; // class attributes
} // namespace irods

#endif // IRODS_LOGICAL_QUOTAS_ATTRIBUTES_HPP
