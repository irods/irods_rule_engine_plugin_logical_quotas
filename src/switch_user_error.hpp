#ifndef IRODS_LOGICAL_QUOTAS_SWITCH_USER_ERROR_HPP
#define IRODS_LOGICAL_QUOTAS_SWITCH_USER_ERROR_HPP

#include "logical_quotas_error.hpp"

namespace irods
{
    class switch_user_error
        : public logical_quotas_error
    {
    public:
        using logical_quotas_error::logical_quotas_error;
    };
} // namespace irods

#endif // IRODS_LOGICAL_QUOTAS_SWITCH_USER_ERROR_HPP
