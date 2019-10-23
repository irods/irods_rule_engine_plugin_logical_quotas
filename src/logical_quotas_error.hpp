#ifndef IRODS_LOGICAL_QUOTAS_ERROR_HPP
#define IRODS_LOGICAL_QUOTAS_ERROR_HPP

#include <stdexcept>

namespace irods
{
    class logical_quotas_error
        : public std::runtime_error
    {
    public:
        logical_quotas_error(const char* _msg, int _error_code) noexcept
            : std::runtime_error{_msg}
            , error_code_{_error_code}
        {
        }

        int error_code() const noexcept
        {
            return error_code_;
        }

    private:
        int error_code_;
    };
} // namespace irods

#endif // IRODS_LOGICAL_QUOTAS_ERROR_HPP
