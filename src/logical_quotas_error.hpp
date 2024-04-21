#ifndef IRODS_LOGICAL_QUOTAS_LOGICAL_QUOTAS_ERROR_HPP
#define IRODS_LOGICAL_QUOTAS_LOGICAL_QUOTAS_ERROR_HPP

#include <stdexcept>

namespace irods
{
	class logical_quotas_error : public std::runtime_error
	{
	  public:
		using error_code_type = int;

		logical_quotas_error(const char* _msg, error_code_type _error_code) noexcept
			: std::runtime_error{_msg}
			, error_code_{_error_code}
		{
		}

		auto error_code() const noexcept -> error_code_type
		{
			return error_code_;
		}

	  private:
		error_code_type error_code_;
	};
} // namespace irods

#endif // IRODS_LOGICAL_QUOTAS_LOGICAL_QUOTAS_ERROR_HPP
