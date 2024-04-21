#include "handler.hpp"

#include "logical_quotas_error.hpp"
#include "utilities.hpp"

#include <irods/client_connection.hpp>
#include <irods/execCmd.h>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_state_table.h>
#include <irods/msParam.h>
#include <irods/genQuery.h>
#include <irods/objDesc.hpp>
#include <irods/rodsDef.h>
#include <irods/irods_query.hpp>
#include <irods/irods_logger.hpp>
#include <irods/query_builder.hpp>
#include <irods/irods_get_l1desc.hpp>
#include <irods/modAVUMetadata.h>
#include <irods/rodsErrorTable.h>
#include <irods/replica.hpp>
#include <irods/scoped_client_identity.hpp>
#include <irods/scoped_permission.hpp>
#include <irods/filesystem.hpp>

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include <irods/filesystem.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <vector>
#include <tuple>
#include <functional>
#include <stdexcept>
#include <algorithm>

namespace
{
	// clang-format off
	namespace fs                 = irods::experimental::filesystem;
	namespace log                = irods::experimental::log;

	using size_type              = irods::handler::size_type;
	using quotas_info_type       = std::unordered_map<std::string, size_type>;
	using file_position_map_type = std::unordered_map<std::string, irods::handler::file_position_type>;
	// clang-format on

	//
	// Classes
	//

	class parent_path
	{
	  public:
		explicit parent_path(const fs::path& _p)
			: p_{_p}
		{
		}

		parent_path(const parent_path&) = delete;
		auto operator=(const parent_path&) -> parent_path& = delete;

		auto of(const fs::path& _child) -> bool
		{
			if (p_ == _child) {
				return false;
			}

			auto p_iter = std::begin(p_);
			auto p_last = std::end(p_);
			auto c_iter = std::begin(_child);
			auto c_last = std::end(_child);

			for (; p_iter != p_last && c_iter != c_last && *p_iter == *c_iter; ++p_iter, ++c_iter)
				;

			return (p_iter == p_last);
		}

	  private:
		const fs::path& p_;
	}; // class parent_path

	//
	// Function Prototypes
	//

	auto get_monitored_collection_info(rsComm_t& _conn, const irods::attributes& _attrs, const fs::path& _p)
		-> quotas_info_type;

	auto throw_if_maximum_number_of_data_objects_violation(const irods::attributes& _attrs,
	                                                       const quotas_info_type& _tracking_info,
	                                                       size_type _delta) -> void;

	auto throw_if_maximum_size_in_bytes_violation(const irods::attributes& _attrs,
	                                              const quotas_info_type& _tracking_info,
	                                              size_type _delta) -> void;

	auto is_monitored_collection(rsComm_t& _conn, const irods::attributes& _attrs, const fs::path& _p) -> bool;

	auto get_monitored_parent_collection(rsComm_t& _conn, const irods::attributes& _attrs, fs::path _p)
		-> std::optional<fs::path>;

	auto compute_data_object_count_and_size(rsComm_t& _conn, fs::path _p) -> std::tuple<size_type, size_type>;

	auto update_data_object_count_and_size(rsComm_t& _conn,
	                                       const irods::attributes& _attrs,
	                                       const fs::path& _collection,
	                                       const quotas_info_type& _info,
	                                       size_type _data_objects_delta,
	                                       size_type _size_in_bytes_delta) -> void;

	auto unset_metadata_impl(const std::string& _instance_name,
	                         std::list<boost::any>& _rule_arguments,
	                         irods::callback& _effect_handler,
	                         std::unordered_map<std::string, irods::instance_configuration>& _instance_configs,
	                         std::function<std::vector<const std::string*>(const irods::attributes& _attrs)> _func)
		-> irods::error;

	template <typename T>
	auto get_pointer(std::list<boost::any>& _rule_arguments, int _index = 2) -> T*;

	template <typename Function>
	auto for_each_monitored_collection(rsComm_t& _conn,
	                                   const irods::attributes& _attrs,
	                                   fs::path _collection,
	                                   Function _func) -> void;

	template <typename Value, typename Map>
	auto get_attribute_value(const Map& _map, std::string_view _key) -> Value;

	auto get_instance_config(const irods::instance_configuration_map& _map, std::string_view _key)
		-> const irods::instance_configuration&;

	auto make_unique_id(fs::path _p) -> std::string;

	auto throw_if_string_cannot_be_cast_to_an_integer(const std::string& s, const std::string& error_msg) -> void;

	auto is_group(rsComm_t& _conn, const std::string_view _entity_name) -> bool;

	auto log_logical_quotas_exception(const irods::logical_quotas_error& e, irods::callback& _effect_handler)
		-> irods::error;

	auto log_irods_exception(const irods::exception& e, irods::callback& _effect_handler) -> irods::error;

	auto log_exception(const std::exception& e, irods::callback& _effect_handler) -> irods::error;

	//
	// Function Implementations
	//

	auto get_monitored_collection_info(rsComm_t& _conn, const irods::attributes& _attrs, const fs::path& _p)
		-> quotas_info_type
	{
		quotas_info_type info;

		const auto gql =
			fmt::format("select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = '{}'", _p.c_str());

		for (auto&& row : irods::query{&_conn, gql}) {
			// clang-format off
			if      (_attrs.maximum_number_of_data_objects() == row[0]) { info[_attrs.maximum_number_of_data_objects()] = std::stoll(row[1]); }
			else if (_attrs.maximum_size_in_bytes() == row[0])          { info[_attrs.maximum_size_in_bytes()] = std::stoll(row[1]); }
			else if (_attrs.total_number_of_data_objects() == row[0])   { info[_attrs.total_number_of_data_objects()] = std::stoll(row[1]); }
			else if (_attrs.total_size_in_bytes() == row[0])            { info[_attrs.total_size_in_bytes()] = std::stoll(row[1]); }
			// clang-format on
		}

		return info;
	}

	auto throw_if_maximum_number_of_data_objects_violation(const irods::attributes& _attrs,
	                                                       const quotas_info_type& _tracking_info,
	                                                       size_type _delta) -> void
	{
		const auto& max_attr_name = _attrs.maximum_number_of_data_objects();

		if (const auto iter = _tracking_info.find(max_attr_name); iter != std::end(_tracking_info)) {
			const auto total = get_attribute_value<size_type>(_tracking_info, _attrs.total_number_of_data_objects());

			if (total + _delta > iter->second) {
				throw irods::logical_quotas_error{
					"Logical Quotas Policy Violation: Adding object exceeds maximum number of objects limit",
					SYS_NOT_ALLOWED};
			}
		}
	}

	auto throw_if_maximum_size_in_bytes_violation(const irods::attributes& _attrs,
	                                              const quotas_info_type& _tracking_info,
	                                              size_type _delta) -> void
	{
		const auto& max_attr_name = _attrs.maximum_size_in_bytes();

		if (const auto iter = _tracking_info.find(max_attr_name); iter != std::end(_tracking_info)) {
			const auto total = get_attribute_value<size_type>(_tracking_info, _attrs.total_size_in_bytes());

			if (total + _delta > iter->second) {
				throw irods::logical_quotas_error{
					"Logical Quotas Policy Violation: Adding object exceeds maximum data size in bytes limit",
					SYS_NOT_ALLOWED};
			}
		}
	}

	auto is_monitored_collection(rsComm_t& _conn, const irods::attributes& _attrs, const fs::path& _p) -> bool
	{
		const auto gql =
			fmt::format("select META_COLL_ATTR_NAME where COLL_NAME = '{}' and META_COLL_ATTR_NAME = '{}' || = '{}'",
		                _p.c_str(),
		                _attrs.total_number_of_data_objects(),
		                _attrs.total_size_in_bytes());

		for (auto&& row : irods::query{&_conn, gql}) {
			return true;
		}

		return false;
	}

	auto get_monitored_parent_collection(rsComm_t& _conn, const irods::attributes& _attrs, fs::path _p)
		-> std::optional<fs::path>
	{
		for (; !_p.empty(); _p = _p.parent_path()) {
			if (is_monitored_collection(_conn, _attrs, _p)) {
				return _p;
			}
			else if ("/" == _p) {
				break;
			}
		}

		return std::nullopt;
	}

	auto compute_data_object_count_and_size(rsComm_t& _conn, fs::path _p) -> std::tuple<size_type, size_type>
	{
		size_type objects = 0;
		size_type bytes = 0;

		const auto gql =
			fmt::format("select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = '{0}' || like '{0}/%'", _p.c_str());

		for (auto&& row : irods::query{&_conn, gql}) {
			objects = !row[0].empty() ? std::stoll(row[0]) : 0;
			bytes = !row[1].empty() ? std::stoll(row[1]) : 0;
		}

		return {objects, bytes};
	}

	auto update_data_object_count_and_size(rsComm_t& _conn,
	                                       const irods::attributes& _attrs,
	                                       const fs::path& _collection,
	                                       const quotas_info_type& _info,
	                                       size_type _data_objects_delta,
	                                       size_type _size_in_bytes_delta) -> void
	{
		if (0 != _data_objects_delta) {
			const auto& objects_attr = _attrs.total_number_of_data_objects();

			if (const auto iter = _info.find(objects_attr); std::end(_info) != iter) {
				const auto new_object_count = std::to_string(iter->second + _data_objects_delta);
				fs::server::set_metadata(_conn, _collection, {objects_attr, new_object_count});
			}
		}

		if (0 != _size_in_bytes_delta) {
			const auto& size_attr = _attrs.total_size_in_bytes();

			if (const auto iter = _info.find(size_attr); std::end(_info) != iter) {
				const auto new_size_in_bytes = std::to_string(iter->second + _size_in_bytes_delta);
				fs::server::set_metadata(_conn, _collection, {size_attr, new_size_in_bytes});
			}
		}
	}

	auto unset_metadata_impl(const std::string& _instance_name,
	                         const irods::instance_configuration_map& _instance_configs,
	                         std::list<boost::any>& _rule_arguments,
	                         irods::callback& _effect_handler,
	                         std::function<std::vector<const std::string*>(const irods::attributes& _attrs)> _func)
		-> irods::error
	{
		try {
			auto args_iter = std::begin(_rule_arguments);
			const auto& path = *boost::any_cast<std::string*>(*args_iter);

			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;

			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
			const auto info = get_monitored_collection_info(conn, attrs, path);

			irods::experimental::client_connection client_conn;
			for (auto&& attribute_name : _func(attrs)) {
				if (const auto iter = info.find(*attribute_name); iter != std::end(info)) {
					const auto value = get_attribute_value<size_type>(info, *attribute_name);
					fs::client::remove_metadata(fs::admin, client_conn, path, {*attribute_name, std::to_string(value)});
				}
			}
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return SUCCESS();
	}

	template <typename T>
	auto get_pointer(std::list<boost::any>& _rule_arguments, int _index) -> T*
	{
		return boost::any_cast<T*>(*std::next(std::begin(_rule_arguments), _index));
	}

	template <typename Function>
	auto for_each_monitored_collection(rsComm_t& _conn,
	                                   const irods::attributes& _attrs,
	                                   fs::path _collection,
	                                   Function _func) -> void
	{
		for (auto collection = get_monitored_parent_collection(_conn, _attrs, _collection.parent_path()); collection;
		     collection = get_monitored_parent_collection(_conn, _attrs, collection->parent_path()))
		{
			auto info = get_monitored_collection_info(_conn, _attrs, *collection);
			_func(*collection, info);
		}
	}

	template <typename Value, typename Map>
	auto get_attribute_value(const Map& _map, std::string_view _key) -> Value
	{
		if (const auto iter = _map.find(_key.data()); std::end(_map) != iter) {
			return iter->second;
		}

		throw std::runtime_error{fmt::format("Logical Quotas Policy: Failed to find metadata [{}]", _key)};
	}

	auto get_instance_config(const irods::instance_configuration_map& _map, std::string_view _key)
		-> const irods::instance_configuration&
	{
		try {
			return _map.at(_key.data());
		}
		catch (const std::out_of_range&) {
			throw std::runtime_error{fmt::format("Logical Quotas Policy: Failed to find configuration for "
			                                     "rule engine plugin instance [{}]",
			                                     _key)};
		}
	}

	auto make_unique_id(fs::path _p) -> std::string
	{
		std::string id = "irods_logical_quotas-";
		id += std::to_string(std::hash<std::string>{}(_p.c_str()));
		id += "-";
		id += std::to_string(getpid());

		return id;
	}

	auto throw_if_string_cannot_be_cast_to_an_integer(const std::string& s, const std::string& error_msg) -> void
	{
		try {
			std::stoll(s); // TODO Could be replaced with std::from_chars when it is available.
		}
		catch (const std::invalid_argument&) {
			throw std::invalid_argument{error_msg};
		}
		catch (const std::out_of_range&) {
			throw std::out_of_range{error_msg};
		}
	}

	auto is_group(rsComm_t& _conn, const std::string_view _entity_name) -> bool
	{
		const auto gql = fmt::format("select USER_TYPE where USER_NAME = '{}'", _entity_name);

		for (auto&& row : irods::query{&_conn, gql}) {
			return "rodsgroup" == row[0];
		}

		return false;
	}

	auto log_logical_quotas_exception(const irods::logical_quotas_error& e, irods::callback& _effect_handler)
		-> irods::error
	{
		log::rule_engine::error(e.what());
		addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, e.error_code(), e.what());
		return ERROR(e.error_code(), e.what());
	}

	auto log_irods_exception(const irods::exception& e, irods::callback& _effect_handler) -> irods::error
	{
		log::rule_engine::error(e.what());
		addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, e.code(), e.client_display_what());
		return e;
	}

	auto log_exception(const std::exception& e, irods::callback& _effect_handler) -> irods::error
	{
		log::rule_engine::error(e.what());
		addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, RE_RUNTIME_ERROR, e.what());
		return ERROR(RE_RUNTIME_ERROR, e.what());
	}

	auto get_quota_value_for_collection(RcComm& _conn, const std::string& _coll_path, const std::string& _quota_name)
		-> std::tuple<std::string, irods::error>
	{
		auto ret_error = SUCCESS();

		std::string value_out;

		// Query will be performed using client connection, ie. with administrative privilege.

		// Initialize query conditions and column for selection.
		GenQueryInp input{};
		GenQueryOut* output{};
		addInxIval(&input.selectInp, COL_META_COLL_ATTR_VALUE, 0);
		addInxVal(&input.sqlCondInp, COL_COLL_NAME, fmt::format("= '{}'", _coll_path).c_str());
		addInxVal(&input.sqlCondInp, COL_META_COLL_ATTR_NAME, fmt::format("= '{}'", _quota_name).c_str());

		input.maxRows = MAX_SQL_ROWS;

		while (true) {
			if (const int ec = rcGenQuery(&_conn, &input, &output); ec < 0) {
				if (ec != CAT_NO_ROWS_FOUND) {
					ret_error = ERROR(ec, "rcGenQuery failed.");
				}
				break;
			}

			for (int row = 0; row < output->rowCnt; ++row) {
				for (int attr = 0; attr < output->attriCnt; ++attr) {
					const SqlResult* sql_result = &output->sqlResult[attr];
					const char* value = sql_result->value + (row * sql_result->len);
					value_out = value;
				}
			}

			if (output->continueInx <= 0) {
				break;
			}
			input.continueInx = output->continueInx;

			clearGenQueryOut(output);
		}

		clearGenQueryInp(&input);
		freeGenQueryOut(&output);

		return std::make_tuple(value_out, ret_error);
	}

} // anonymous namespace

namespace irods::handler
{
	auto logical_quotas_get_collection_status(const std::string& _instance_name,
	                                          const instance_configuration_map& _instance_configs,
	                                          std::list<boost::any>& _rule_arguments,
	                                          MsParamArray* _ms_param_array,
	                                          irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			auto args_iter = std::begin(_rule_arguments);
			const auto& path = *boost::any_cast<std::string*>(*args_iter);

			if (!is_monitored_collection(conn, attrs, path)) {
				auto msg = fmt::format("Logical Quotas Policy: [{}] is not a monitored collection.", path);
				log::rule_engine::error(msg);
				constexpr auto ec = SYS_INVALID_INPUT_PARAM;
				addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, ec, msg.c_str());
				return ERROR(ec, std::move(msg));
			}

			auto quota_status = nlohmann::json::object(); // Holds the current quota values.

			// Fetch the current quota values for the collection.
			irods::experimental::client_connection client_conn;
			for (const auto& quota_name : {attrs.maximum_number_of_data_objects(),
			                               attrs.maximum_size_in_bytes(),
			                               attrs.total_number_of_data_objects(),
			                               attrs.total_size_in_bytes()})
			{
				auto [result, err] =
					get_quota_value_for_collection(static_cast<RcComm&>(client_conn), path, quota_name);
				if (!err.ok()) {
					return err;
				}
				quota_status[quota_name] = std::move(result);
			}

			// "_ms_param_array" points to a valid object depending on how the rule is invoked. If the implementation
			// is invoked via exec_rule, then this parameter will be null. If invoked via exec_rule_text or
			// exec_rule_expression, this parameter will point to a valid object. The exec_rule_text/expression
			// functions reply on this parameter to return information back to the client.
			if (_ms_param_array) {
				if (auto* msp = getMsParamByLabel(_ms_param_array, "ruleExecOut"); msp) {
					// Free any resources previously associated with the parameter.
					if (msp->type) {
						std::free(msp->type);
					}
					if (msp->inOutStruct) {
						std::free(msp->inOutStruct);
					}

					// Set the correct type information and allocate enough memory for that type.
					msp->type = strdup(ExecCmdOut_MS_T);
					msp->inOutStruct = std::malloc(sizeof(ExecCmdOut));

					auto* out = static_cast<ExecCmdOut*>(msp->inOutStruct);
					std::memset(out, 0, sizeof(ExecCmdOut));

					// Copy the JSON string into the output object.
					const auto json_string = quota_status.dump();
					const auto buffer_size = json_string.size() + 1;
					out->stdoutBuf.len = buffer_size;
					out->stdoutBuf.buf = std::malloc(sizeof(char) * buffer_size);
					std::memcpy(out->stdoutBuf.buf, json_string.data(), buffer_size);
				}
				else {
					auto* out = static_cast<ExecCmdOut*>(std::malloc(sizeof(ExecCmdOut)));
					std::memset(out, 0, sizeof(ExecCmdOut));

					// Copy the JSON string into the output object.
					const auto json_string = quota_status.dump();
					const auto buffer_size = json_string.size() + 1;
					out->stdoutBuf.len = buffer_size;
					out->stdoutBuf.buf = std::malloc(sizeof(char) * buffer_size);
					std::memcpy(out->stdoutBuf.buf, json_string.data(), buffer_size);

					addMsParamToArray(_ms_param_array, "ruleExecOut", ExecCmdOut_MS_T, out, nullptr, 0);
				}
			}
			// If "_ms_param_array" is not set, then the rule must have been invoked via exec_rule. The client must
			// provide a second variable so that the results can be returned.
			else if (_rule_arguments.size() == 2) {
				*boost::any_cast<std::string*>(*std::next(args_iter)) = quota_status.dump();
			}
			else {
				return ERROR(RE_UNABLE_TO_WRITE_VAR, "Logical Quotas Policy: Missing output variable for status.");
			}
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return SUCCESS();
	}

	auto logical_quotas_start_monitoring_collection(const std::string& _instance_name,
	                                                const instance_configuration_map& _instance_configs,
	                                                std::list<boost::any>& _rule_arguments,
	                                                MsParamArray* _ms_param_array,
	                                                irods::callback& _effect_handler) -> irods::error
	{
		return logical_quotas_recalculate_totals(
			_instance_name, _instance_configs, _rule_arguments, _ms_param_array, _effect_handler);
	}

	auto logical_quotas_stop_monitoring_collection(const std::string& _instance_name,
	                                               const instance_configuration_map& _instance_configs,
	                                               std::list<boost::any>& _rule_arguments,
	                                               MsParamArray* _ms_param_array,
	                                               irods::callback& _effect_handler) -> irods::error
	{
		return unset_metadata_impl(
			_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
				return std::vector{&_attrs.total_number_of_data_objects(), &_attrs.total_size_in_bytes()};
			});
	}

	auto logical_quotas_count_total_number_of_data_objects(const std::string& _instance_name,
	                                                       const instance_configuration_map& _instance_configs,
	                                                       std::list<boost::any>& _rule_arguments,
	                                                       MsParamArray* _ms_param_array,
	                                                       irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto args_iter = std::begin(_rule_arguments);
			const auto& path = *boost::any_cast<std::string*>(*args_iter);

			auto& rei = get_rei(_effect_handler);

			std::vector args{path + '%'};
			auto query = irods::experimental::query_builder{}
			                 .type(irods::experimental::query_type::specific)
			                 .bind_arguments(args)
			                 .build<RsComm>(*rei.rsComm, "logical_quotas_count_data_objects_recursive");

			std::string objects;
			for (auto&& row : query) {
				objects = row[0];
			}

			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			irods::experimental::client_connection conn;
			fs::client::set_metadata(
				fs::admin, conn, path, {attrs.total_number_of_data_objects(), objects.empty() ? "0" : objects});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return SUCCESS();
	}

	auto logical_quotas_count_total_size_in_bytes(const std::string& _instance_name,
	                                              const instance_configuration_map& _instance_configs,
	                                              std::list<boost::any>& _rule_arguments,
	                                              MsParamArray* _ms_param_array,
	                                              irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto args_iter = std::begin(_rule_arguments);
			const auto& path = *boost::any_cast<std::string*>(*args_iter);

			auto& rei = get_rei(_effect_handler);

			std::vector args{path + '%'};
			auto query = irods::experimental::query_builder{}
			                 .type(irods::experimental::query_type::specific)
			                 .bind_arguments(args)
			                 .build<RsComm>(*rei.rsComm, "logical_quotas_sum_data_object_sizes_recursive");

			std::string bytes;
			for (auto&& row : query) {
				bytes = row[0];
			}

			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			irods::experimental::client_connection conn;
			fs::client::set_metadata(fs::admin, conn, path, {attrs.total_size_in_bytes(), bytes.empty() ? "0" : bytes});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return SUCCESS();
	}

	auto logical_quotas_recalculate_totals(const std::string& _instance_name,
	                                       const instance_configuration_map& _instance_configs,
	                                       std::list<boost::any>& _rule_arguments,
	                                       MsParamArray* _ms_param_array,
	                                       irods::callback& _effect_handler) -> irods::error
	{
		auto functions = {logical_quotas_count_total_number_of_data_objects, logical_quotas_count_total_size_in_bytes};

		for (auto&& f : functions) {
			if (const auto error =
			        f(_instance_name, _instance_configs, _rule_arguments, _ms_param_array, _effect_handler);
			    !error.ok())
			{
				return error;
			}
		}

		return SUCCESS();
	}

	auto logical_quotas_set_maximum_number_of_data_objects(const std::string& _instance_name,
	                                                       const instance_configuration_map& _instance_configs,
	                                                       std::list<boost::any>& _rule_arguments,
	                                                       MsParamArray* _ms_param_array,
	                                                       irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto args_iter = std::begin(_rule_arguments);
			const auto& path = *boost::any_cast<std::string*>(*args_iter);

			const auto& max_objects = *boost::any_cast<std::string*>(*++args_iter);
			const auto msg = fmt::format(
				"Logical Quotas Policy: Invalid value for maximum number of data objects [{}]", max_objects);
			throw_if_string_cannot_be_cast_to_an_integer(max_objects, msg);
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			irods::experimental::client_connection client_conn;
			fs::client::set_metadata(
				fs::admin, client_conn, path, {attrs.maximum_number_of_data_objects(), max_objects});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return SUCCESS();
	}

	auto logical_quotas_set_maximum_size_in_bytes(const std::string& _instance_name,
	                                              const instance_configuration_map& _instance_configs,
	                                              std::list<boost::any>& _rule_arguments,
	                                              MsParamArray* _ms_param_array,
	                                              irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto args_iter = std::begin(_rule_arguments);
			const auto& path = *boost::any_cast<std::string*>(*args_iter);

			const auto& max_bytes = *boost::any_cast<std::string*>(*++args_iter);
			const auto msg =
				fmt::format("Logical Quotas Policy: Invalid value for maximum size in bytes [{}]", max_bytes);
			throw_if_string_cannot_be_cast_to_an_integer(max_bytes, msg);
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			irods::experimental::client_connection client_conn;
			fs::client::set_metadata(fs::admin, client_conn, path, {attrs.maximum_size_in_bytes(), max_bytes});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return SUCCESS();
	}

	auto logical_quotas_unset_maximum_number_of_data_objects(const std::string& _instance_name,
	                                                         const instance_configuration_map& _instance_configs,
	                                                         std::list<boost::any>& _rule_arguments,
	                                                         MsParamArray* _ms_param_array,
	                                                         irods::callback& _effect_handler) -> irods::error
	{
		return unset_metadata_impl(
			_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
				return std::vector{&_attrs.maximum_number_of_data_objects()};
			});
	}

	auto logical_quotas_unset_maximum_size_in_bytes(const std::string& _instance_name,
	                                                const instance_configuration_map& _instance_configs,
	                                                std::list<boost::any>& _rule_arguments,
	                                                MsParamArray* _ms_param_array,
	                                                irods::callback& _effect_handler) -> irods::error
	{
		return unset_metadata_impl(
			_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
				return std::vector{&_attrs.maximum_size_in_bytes()};
			});
	}

	auto logical_quotas_unset_total_number_of_data_objects(const std::string& _instance_name,
	                                                       const instance_configuration_map& _instance_configs,
	                                                       std::list<boost::any>& _rule_arguments,
	                                                       MsParamArray* _ms_param_array,
	                                                       irods::callback& _effect_handler) -> irods::error
	{
		return unset_metadata_impl(
			_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
				return std::vector{&_attrs.total_number_of_data_objects()};
			});
	}

	auto logical_quotas_unset_total_size_in_bytes(const std::string& _instance_name,
	                                              const instance_configuration_map& _instance_configs,
	                                              std::list<boost::any>& _rule_arguments,
	                                              MsParamArray* _ms_param_array,
	                                              irods::callback& _effect_handler) -> irods::error
	{
		return unset_metadata_impl(
			_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
				return std::vector{&_attrs.total_size_in_bytes()};
			});
	}

	auto pep_api_data_obj_copy::reset() noexcept -> void
	{
		data_objects_ = 0;
		size_in_bytes_ = 0;
	}

	auto pep_api_data_obj_copy::pre(const std::string& _instance_name,
	                                const instance_configuration_map& _instance_configs,
	                                std::list<boost::any>& _rule_arguments,
	                                MsParamArray* _ms_param_array,
	                                irods::callback& _effect_handler) -> irods::error
	{
		reset(); // Not needed necessarily, but here for completeness.

		try {
			auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath);
			    fs::server::is_data_object(status)) {
				data_objects_ = 1;
				size_in_bytes_ = fs::server::data_object_size(conn, input->srcDataObjInp.objPath);
			}
			else if (fs::server::is_collection(status)) {
				std::tie(data_objects_, size_in_bytes_) =
					compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
			}
			else {
				throw logical_quotas_error{"Logical Quotas Policy: Invalid object type", INVALID_OBJECT_TYPE};
			}

			for_each_monitored_collection(
				conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs](auto& _collection, const auto& _info) {
					throw_if_maximum_number_of_data_objects_violation(attrs, _info, data_objects_);
					throw_if_maximum_size_in_bytes_violation(attrs, _info, size_in_bytes_);
				});
		}
		catch (const logical_quotas_error& e) {
			return log_logical_quotas_exception(e, _effect_handler);
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_copy::post(const std::string& _instance_name,
	                                 const instance_configuration_map& _instance_configs,
	                                 std::list<boost::any>& _rule_arguments,
	                                 MsParamArray* _ms_param_array,
	                                 irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			for_each_monitored_collection(conn,
			                              attrs,
			                              input->destDataObjInp.objPath,
			                              [&conn, &attrs](const auto& _collection, const auto& _info) {
											  update_data_object_count_and_size(
												  conn, attrs, _collection, _info, data_objects_, size_in_bytes_);
										  });
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_create_pre(const std::string& _instance_name,
	                                 const instance_configuration_map& _instance_configs,
	                                 std::list<boost::any>& _rule_arguments,
	                                 MsParamArray* _ms_param_array,
	                                 irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			for_each_monitored_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
				throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
			});
		}
		catch (const logical_quotas_error& e) {
			return log_logical_quotas_exception(e, _effect_handler);
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_create_post(const std::string& _instance_name,
	                                  const instance_configuration_map& _instance_configs,
	                                  std::list<boost::any>& _rule_arguments,
	                                  MsParamArray* _ms_param_array,
	                                  irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			for_each_monitored_collection(
				conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
					update_data_object_count_and_size(conn, attrs, _collection, _info, 1, 0);
				});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_put::reset() noexcept -> void
	{
		size_diff_ = 0;
		forced_overwrite_ = false;
	}

	auto pep_api_data_obj_put::pre(const std::string& _instance_name,
	                               const instance_configuration_map& _instance_configs,
	                               std::list<boost::any>& _rule_arguments,
	                               MsParamArray* _ms_param_array,
	                               irods::callback& _effect_handler) -> irods::error
	{
		reset();

		try {
			auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			if (fs::server::exists(*rei.rsComm, input->objPath)) {
				forced_overwrite_ = true;
				const size_type existing_size = fs::server::data_object_size(conn, input->objPath);
				size_diff_ = static_cast<size_type>(input->dataSize) - existing_size;

				for_each_monitored_collection(
					conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, auto& _info) {
						throw_if_maximum_size_in_bytes_violation(attrs, _info, size_diff_);
					});
			}
			else {
				for_each_monitored_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
					throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
					throw_if_maximum_size_in_bytes_violation(attrs, _info, input->dataSize);
				});
			}
		}
		catch (const logical_quotas_error& e) {
			return log_logical_quotas_exception(e, _effect_handler);
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_put::post(const std::string& _instance_name,
	                                const instance_configuration_map& _instance_configs,
	                                std::list<boost::any>& _rule_arguments,
	                                MsParamArray* _ms_param_array,
	                                irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			if (forced_overwrite_) {
				for_each_monitored_collection(
					conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
						update_data_object_count_and_size(conn, attrs, _collection, _info, 0, size_diff_);
					});
			}
			else {
				for_each_monitored_collection(
					conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
						update_data_object_count_and_size(conn, attrs, _collection, _info, 1, input->dataSize);
					});
			}
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_rename::reset() noexcept -> void
	{
		data_objects_ = 0;
		size_in_bytes_ = 0;
	}

	auto pep_api_data_obj_rename::pre(const std::string& _instance_name,
	                                  const instance_configuration_map& _instance_configs,
	                                  std::list<boost::any>& _rule_arguments,
	                                  MsParamArray* _ms_param_array,
	                                  irods::callback& _effect_handler) -> irods::error
	{
		reset();

		try {
			auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);

			// The parent of both paths are the same, then this operation is simply a rename of the
			// source data object or collection. In this case, there is nothing to do.
			if (fs::path{input->srcDataObjInp.objPath}.parent_path() ==
			    fs::path{input->destDataObjInp.objPath}.parent_path()) {
				return CODE(RULE_ENGINE_CONTINUE);
			}

			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath);
			    fs::server::is_data_object(status)) {
				data_objects_ = 1;
				size_in_bytes_ = fs::server::data_object_size(conn, input->srcDataObjInp.objPath);
			}
			else if (fs::server::is_collection(status)) {
				std::tie(data_objects_, size_in_bytes_) =
					compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
			}
			else {
				throw logical_quotas_error{"Logical Quotas Policy: Invalid object type", INVALID_OBJECT_TYPE};
			}

			const auto in_violation = [&](const auto&, const auto& _info) {
				throw_if_maximum_number_of_data_objects_violation(attrs, _info, data_objects_);
				throw_if_maximum_size_in_bytes_violation(attrs, _info, size_in_bytes_);
			};

			auto src_path = get_monitored_parent_collection(conn, attrs, input->srcDataObjInp.objPath);
			auto dst_path = get_monitored_parent_collection(conn, attrs, input->destDataObjInp.objPath);

			if (src_path && dst_path) {
				if (*src_path == *dst_path) {
					return CODE(RULE_ENGINE_CONTINUE);
				}

				// Moving object(s) from a parent collection to a child collection.
				if (parent_path{*src_path}.of(*dst_path)) {
					for_each_monitored_collection(
						conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
							// Return immediately if "_collection" is equal to "*src_path". At this point,
						    // there is no need to check if any quotas will be violated. The totals will not
						    // change for parents of the source collection.
							if (_collection == *src_path) {
								return;
							}

							throw_if_maximum_number_of_data_objects_violation(attrs, _info, data_objects_);
							throw_if_maximum_size_in_bytes_violation(attrs, _info, size_in_bytes_);
						});
				}
				// Moving object(s) from a child collection to a parent collection.
				else if (parent_path{*dst_path}.of(*src_path)) {
					for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, in_violation);
				}
				// Moving objects(s) between unrelated collection trees.
				else {
					for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, in_violation);
				}
			}
			else if (dst_path) {
				using namespace std::string_literals;
				for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, in_violation);
			}
		}
		catch (const logical_quotas_error& e) {
			return log_logical_quotas_exception(e, _effect_handler);
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_rename::post(const std::string& _instance_name,
	                                   const instance_configuration_map& _instance_configs,
	                                   std::list<boost::any>& _rule_arguments,
	                                   MsParamArray* _ms_param_array,
	                                   irods::callback& _effect_handler) -> irods::error
	{
		// There is no change in state, therefore return immediately.
		if (0 == data_objects_ && 0 == size_in_bytes_) {
			return CODE(RULE_ENGINE_CONTINUE);
		}

		try {
			auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
			auto src_path = get_monitored_parent_collection(conn, attrs, input->srcDataObjInp.objPath);
			auto dst_path = get_monitored_parent_collection(conn, attrs, input->destDataObjInp.objPath);

			// Cases
			// ~~~~~
			// * src_path and dst_path are monitored paths.
			//   - src_path and dst_path are the same path
			//     + Do nothing
			//
			//   - src_path is the parent of dst_path
			//     + Update dst_path's metadata
			//
			//   - dst_path is the parent of src_path
			//     + Update the src_path's metadata
			//
			// * src_path is monitored, but dst_path is not.
			//   - Update the src_path's metadata
			//
			// * dst_path is monitored, but src_path is not.
			//   - Update the dst_path's metadata
			//
			// * src_path and dst_path are not monitored paths.
			//   - Do nothing

			if (src_path && dst_path) {
				if (*src_path == *dst_path) {
					return CODE(RULE_ENGINE_CONTINUE);
				}

				// Moving object(s) from a parent collection to a child collection.
				if (parent_path{*src_path}.of(*dst_path)) {
					auto info = get_monitored_collection_info(conn, attrs, *dst_path);
					update_data_object_count_and_size(conn, attrs, *dst_path, info, data_objects_, size_in_bytes_);
				}
				// Moving object(s) from a child collection to a parent collection.
				else if (parent_path{*dst_path}.of(*src_path)) {
					auto info = get_monitored_collection_info(conn, attrs, *src_path);
					update_data_object_count_and_size(conn, attrs, *src_path, info, -data_objects_, -size_in_bytes_);
				}
				// Moving objects(s) between unrelated collection trees.
				else {
					for_each_monitored_collection(
						conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
							update_data_object_count_and_size(
								conn, attrs, _collection, _info, data_objects_, size_in_bytes_);
						});

					for_each_monitored_collection(
						conn, attrs, input->srcDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
							update_data_object_count_and_size(
								conn, attrs, _collection, _info, -data_objects_, -size_in_bytes_);
						});
				}
			}
			else if (src_path) {
				for_each_monitored_collection(
					conn, attrs, input->srcDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
						update_data_object_count_and_size(
							conn, attrs, _collection, _info, -data_objects_, -size_in_bytes_);
					});
			}
			else if (dst_path) {
				for_each_monitored_collection(
					conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
						update_data_object_count_and_size(
							conn, attrs, _collection, _info, data_objects_, size_in_bytes_);
					});
			}
		}
		catch (const logical_quotas_error& e) {
			return log_logical_quotas_exception(e, _effect_handler);
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_unlink::reset() noexcept -> void
	{
		size_in_bytes_ = 0;
	}

	auto pep_api_data_obj_unlink::pre(const std::string& _instance_name,
	                                  const instance_configuration_map& _instance_configs,
	                                  std::list<boost::any>& _rule_arguments,
	                                  MsParamArray* _ms_param_array,
	                                  irods::callback& _effect_handler) -> irods::error
	{
		reset();

		try {
			auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			if (auto collection = get_monitored_parent_collection(conn, attrs, input->objPath); collection) {
				size_in_bytes_ = fs::server::data_object_size(conn, input->objPath);
			}
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_unlink::post(const std::string& _instance_name,
	                                   const instance_configuration_map& _instance_configs,
	                                   std::list<boost::any>& _rule_arguments,
	                                   MsParamArray* _ms_param_array,
	                                   irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			for_each_monitored_collection(
				conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
					update_data_object_count_and_size(conn, attrs, _collection, _info, -1, -size_in_bytes_);
				});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_open_pre(const std::string& _instance_name,
	                               const instance_configuration_map& _instance_configs,
	                               std::list<boost::any>& _rule_arguments,
	                               MsParamArray* _ms_param_array,
	                               irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			if (O_CREAT == (input->openFlags & O_CREAT)) {
				if (!fs::server::exists(*rei.rsComm, input->objPath)) {
					for_each_monitored_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
						throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
					});
				}
			}
			// Opening an existing data object for reading is fine as long as it does not result in
			// the creation of a new data object.
			else if (O_RDONLY == (input->openFlags & O_ACCMODE)) {
				return CODE(RULE_ENGINE_CONTINUE);
			}

			// Because streaming operations can result in byte quotas being exceeded, the REP must
			// verify that the quotas have not been violated by a previous streaming operation. This
			// is because the REP does not track bytes written during streaming operations.
			for_each_monitored_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
				// We only need to check the byte count here. If the rest of the REP is implemented
				// correctly, then the data object count should be in line already.
				throw_if_maximum_size_in_bytes_violation(attrs, _info, 0);
			});
		}
		catch (const logical_quotas_error& e) {
			return log_logical_quotas_exception(e, _effect_handler);
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_close::reset() noexcept -> void
	{
		path_.clear();
	}

	auto pep_api_data_obj_close::pre(const std::string& _instance_name,
	                                 const instance_configuration_map& _instance_configs,
	                                 std::list<boost::any>& _rule_arguments,
	                                 MsParamArray* _ms_param_array,
	                                 irods::callback& _effect_handler) -> irods::error
	{
		reset();

		try {
			auto* input = get_pointer<openedDataObjInp_t>(_rule_arguments);
			const auto& l1desc = irods::get_l1desc(input->l1descInx);

			// Return immediately if the client opened an existing data object for reading.
			// This avoids unnecessary catalog updates.
			if (const auto flags = l1desc.dataObjInp->openFlags;
			    O_RDONLY == (flags & O_ACCMODE) && O_CREAT != (flags & O_CREAT)) {
				return CODE(RULE_ENGINE_CONTINUE);
			}

			path_ = l1desc.dataObjInfo->objPath;
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_data_obj_close::post(const std::string& _instance_name,
	                                  const instance_configuration_map& _instance_configs,
	                                  std::list<boost::any>& _rule_arguments,
	                                  MsParamArray* _ms_param_array,
	                                  irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			// If the path is empty, either the pre-PEP detected that the client opened an
			// existing data object for reading and returned early, or an error occurred.
			// This avoids unnecessary catalog updates.
			if (path_.empty()) {
				return CODE(RULE_ENGINE_CONTINUE);
			}

			for_each_monitored_collection(conn, attrs, path_, [&](auto& _collection, const auto& _info) {
				std::string p = fs::path{path_}.parent_path();
				std::list<boost::any> args{&p};
				const auto err = logical_quotas_recalculate_totals(
					_instance_name, _instance_configs, args, _ms_param_array, _effect_handler);

				if (!err.ok()) {
					THROW(err.code(), err.result());
				}
			});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_mod_avu_metadata_pre(const std::string& _instance_name,
	                                  const instance_configuration_map& _instance_configs,
	                                  std::list<boost::any>& _rule_arguments,
	                                  MsParamArray* _ms_param_array,
	                                  irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto* input = get_pointer<modAVUMetadataInp_t>(_rule_arguments);

			if (std::string_view{"add"} != input->arg0 || !fs::server::is_collection(conn, input->arg2)) {
				return CODE(RULE_ENGINE_CONTINUE);
			}

			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			const auto attr_list = {&attrs.maximum_number_of_data_objects(),
			                        &attrs.maximum_size_in_bytes(),
			                        &attrs.total_number_of_data_objects(),
			                        &attrs.total_size_in_bytes()};

			const auto iter = std::find_if(
				std::begin(attr_list),
				std::end(attr_list),
				[attr_name = std::string_view{input->arg3}](const std::string* _attr) { return *_attr == attr_name; });

			if (iter != std::end(attr_list)) {
				const auto gql = fmt::format("select META_COLL_ATTR_NAME "
				                             "where COLL_NAME = '{}' and META_COLL_ATTR_NAME = '{}'",
				                             input->arg2,
				                             **iter);

				if (irods::query{&conn, gql}.size() > 0) {
					return ERROR(SYS_NOT_ALLOWED, "Logical Quotas Policy: Metadata attribute name already defined.");
				}
			}
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_replica_close::reset() noexcept -> void
	{
		path_.clear();
	}

	auto pep_api_replica_close::pre(const std::string& _instance_name,
	                                const instance_configuration_map& _instance_configs,
	                                std::list<boost::any>& _rule_arguments,
	                                MsParamArray* _ms_param_array,
	                                irods::callback& _effect_handler) -> irods::error
	{
		reset();

		try {
			auto* input = get_pointer<BytesBuf>(_rule_arguments);
			const auto json_input = nlohmann::json::parse(std::string_view(static_cast<char*>(input->buf), input->len));
			const auto& l1desc = irods::get_l1desc(json_input.at("fd").get<int>());

			// Return immediately if the client opened an existing data object for reading.
			// This avoids unnecessary catalog updates.
			if (const auto flags = l1desc.dataObjInp->openFlags;
			    O_RDONLY == (flags & O_ACCMODE) && O_CREAT != (flags & O_CREAT)) {
				return CODE(RULE_ENGINE_CONTINUE);
			}

			path_ = l1desc.dataObjInfo->objPath;
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_replica_close::post(const std::string& _instance_name,
	                                 const instance_configuration_map& _instance_configs,
	                                 std::list<boost::any>& _rule_arguments,
	                                 MsParamArray* _ms_param_array,
	                                 irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			// If the path is empty, either the pre-PEP detected that the client opened an
			// existing data object for reading and returned early, or an error occurred.
			// This avoids unnecessary catalog updates.
			if (path_.empty()) {
				return CODE(RULE_ENGINE_CONTINUE);
			}

			for_each_monitored_collection(conn, attrs, path_, [&](auto& _collection, const auto& _info) {
				std::string p = fs::path{path_}.parent_path();
				std::list<boost::any> args{&p};
				const auto err = logical_quotas_recalculate_totals(
					_instance_name, _instance_configs, args, _ms_param_array, _effect_handler);

				if (!err.ok()) {
					THROW(err.code(), err.result());
				}
			});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_rm_coll::reset() noexcept -> void
	{
		data_objects_ = 0;
		size_in_bytes_ = 0;
	}

	auto pep_api_rm_coll::pre(const std::string& _instance_name,
	                          const instance_configuration_map& _instance_configs,
	                          std::list<boost::any>& _rule_arguments,
	                          MsParamArray* _ms_param_array,
	                          irods::callback& _effect_handler) -> irods::error
	{
		reset();

		try {
			auto* input = get_pointer<collInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			if (auto collection = get_monitored_parent_collection(conn, attrs, input->collName); collection) {
				std::tie(data_objects_, size_in_bytes_) = compute_data_object_count_and_size(conn, input->collName);
			}
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_rm_coll::post(const std::string& _instance_name,
	                           const instance_configuration_map& _instance_configs,
	                           std::list<boost::any>& _rule_arguments,
	                           MsParamArray* _ms_param_array,
	                           irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto* input = get_pointer<collInp_t>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;
			const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

			for_each_monitored_collection(
				conn, attrs, input->collName, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
					update_data_object_count_and_size(conn, attrs, _collection, _info, -data_objects_, -size_in_bytes_);
				});
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_touch::reset() noexcept -> void
	{
		path_.clear();
		exists_ = false;
	}

	auto pep_api_touch::pre(const std::string& _instance_name,
	                        const instance_configuration_map& _instance_configs,
	                        std::list<boost::any>& _rule_arguments,
	                        MsParamArray* _ms_param_array,
	                        irods::callback& _effect_handler) -> irods::error
	{
		reset();

		try {
			auto* input = get_pointer<BytesBuf>(_rule_arguments);
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;

			const auto json_input = nlohmann::json::parse(std::string_view(static_cast<char*>(input->buf), input->len));
			path_ = json_input.at("logical_path").get<std::string>();
			exists_ = fs::server::exists(conn, path_);
		}
		catch (const fs::filesystem_error& e) {
			rodsLog(LOG_ERROR, e.what());
			addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, e.code().value(), e.what());
			return ERROR(e.code().value(), e.what());
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto pep_api_touch::post(const std::string& _instance_name,
	                         const instance_configuration_map& _instance_configs,
	                         std::list<boost::any>& _rule_arguments,
	                         MsParamArray* _ms_param_array,
	                         irods::callback& _effect_handler) -> irods::error
	{
		try {
			auto& rei = get_rei(_effect_handler);
			auto& conn = *rei.rsComm;

			// Verify that the target object was created. This is necessary because the touch API
			// does not always result in a new data object (i.e. no_create JSON option).
			if (!exists_ && fs::server::exists(conn, path_)) {
				const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

				for_each_monitored_collection(
					conn, attrs, path_, [&conn, &attrs](const auto& _collection, const auto& _info) {
						update_data_object_count_and_size(conn, attrs, _collection, _info, 1, 0);
					});
			}
		}
		catch (const fs::filesystem_error& e) {
			rodsLog(LOG_ERROR, e.what());
			addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, e.code().value(), e.what());
			return ERROR(e.code().value(), e.what());
		}
		catch (const irods::exception& e) {
			return log_irods_exception(e, _effect_handler);
		}
		catch (const std::exception& e) {
			return log_exception(e, _effect_handler);
		}

		return CODE(RULE_ENGINE_CONTINUE);
	}
} // namespace irods::handler
