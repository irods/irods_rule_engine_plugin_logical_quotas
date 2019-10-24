#ifndef IRODS_LOGICAL_QUOTAS_INSTANCE_CONFIGURATION_HPP
#define IRODS_LOGICAL_QUOTAS_INSTANCE_CONFIGURATION_HPP

#include "attributes.hpp"

namespace irods
{
    class instance_configuration final
    {
    public:
        instance_configuration(attributes _attrs) noexcept
            : attrs_{std::move(_attrs)}
        {
        }

        const attributes& attributes() const noexcept
        {
            return attrs_;
        }

    private:
        class attributes attrs_;
    }; // class instance_config
} // namespace irods

#endif // IRODS_LOGICAL_QUOTAS_INSTANCE_CONFIGURATION_HPP
