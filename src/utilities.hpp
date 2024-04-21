#ifndef IRODS_LOGICAL_QUOTAS_UTILITIES_HPP
#define IRODS_LOGICAL_QUOTAS_UTILITIES_HPP

#include "logical_quotas_error.hpp"

#include <irods/irods_re_plugin.hpp>
#include <irods/irods_error.hpp>

inline auto get_rei(irods::callback& _effect_handler) -> ruleExecInfo_t&
{
	ruleExecInfo_t* rei{};

	if (const auto result = _effect_handler("unsafe_ms_ctx", &rei); !result.ok()) {
		const auto error_code = static_cast<irods::logical_quotas_error::error_code_type>(result.code());
		throw irods::logical_quotas_error{
			"Logical Quotas Policy: Failed to get rule execution information", error_code};
	}

	return *rei;
}

#endif // IRODS_LOGICAL_QUOTAS_UTILITIES_HPP
