#include "instance_configuration.hpp"

#include "handler.hpp"
#include "utilities.hpp"

#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_get_full_path_for_config_file.hpp>
#include <irods/irods_logger.hpp>
#include <irods/irods_rs_comm_query.hpp>
#include <irods/msParam.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>

#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <boost/any.hpp>

#include <map>
#include <algorithm>
#include <iterator>

namespace
{
	// clang-format off
	namespace handler = irods::handler;
	namespace log     = irods::experimental::log;

	using json        = nlohmann::json;

	irods::instance_configuration_map instance_configs;

	using handler_type = std::function<irods::error(const std::string&,
			                           const irods::instance_configuration_map&,
			                           std::list<boost::any>&,
			                           MsParamArray*,
			                           irods::callback&)>;

	using handler_map_type = std::map<std::string_view, handler_type>;

	const handler_map_type logical_quotas_handlers{
		{"logical_quotas_count_total_number_of_data_objects",   handler::logical_quotas_count_total_number_of_data_objects},
		{"logical_quotas_count_total_size_in_bytes",            handler::logical_quotas_count_total_size_in_bytes},
		{"logical_quotas_recalculate_totals",                   handler::logical_quotas_recalculate_totals},
		{"logical_quotas_set_maximum_number_of_data_objects",   handler::logical_quotas_set_maximum_number_of_data_objects},
		{"logical_quotas_set_maximum_size_in_bytes",            handler::logical_quotas_set_maximum_size_in_bytes},
		{"logical_quotas_start_monitoring_collection",          handler::logical_quotas_start_monitoring_collection},
		{"logical_quotas_get_collection_status",                handler::logical_quotas_get_collection_status},
		{"logical_quotas_stop_monitoring_collection",           handler::logical_quotas_stop_monitoring_collection},
		{"logical_quotas_unset_maximum_number_of_data_objects", handler::logical_quotas_unset_maximum_number_of_data_objects},
		{"logical_quotas_unset_maximum_size_in_bytes",          handler::logical_quotas_unset_maximum_size_in_bytes},
		{"logical_quotas_unset_total_number_of_data_objects",   handler::logical_quotas_unset_total_number_of_data_objects},
		{"logical_quotas_unset_total_size_in_bytes",            handler::logical_quotas_unset_total_size_in_bytes}
	};

	const handler_map_type pep_handlers{
		{"pep_api_data_obj_close_post",           handler::pep_api_data_obj_close::post},
		{"pep_api_data_obj_close_pre",            handler::pep_api_data_obj_close::pre},
		{"pep_api_data_obj_copy_post",            handler::pep_api_data_obj_copy::post},
		{"pep_api_data_obj_copy_pre",             handler::pep_api_data_obj_copy::pre},
		{"pep_api_data_obj_create_and_stat_post", handler::pep_api_data_obj_create_post},
		{"pep_api_data_obj_create_and_stat_pre",  handler::pep_api_data_obj_create_pre},
		{"pep_api_data_obj_create_post",          handler::pep_api_data_obj_create_post},
		{"pep_api_data_obj_create_pre",           handler::pep_api_data_obj_create_pre},
		{"pep_api_data_obj_open_and_stat_pre",    handler::pep_api_data_obj_open_pre},
		{"pep_api_data_obj_open_pre",             handler::pep_api_data_obj_open_pre},
		{"pep_api_data_obj_put_post",             handler::pep_api_data_obj_put::post},
		{"pep_api_data_obj_put_pre",              handler::pep_api_data_obj_put::pre},
		{"pep_api_data_obj_rename_post",          handler::pep_api_data_obj_rename::post},
		{"pep_api_data_obj_rename_pre",           handler::pep_api_data_obj_rename::pre},
		{"pep_api_data_obj_unlink_post",          handler::pep_api_data_obj_unlink::post},
		{"pep_api_data_obj_unlink_pre",           handler::pep_api_data_obj_unlink::pre},
		{"pep_api_mod_avu_metadata_pre",          handler::pep_api_mod_avu_metadata_pre},
		{"pep_api_replica_close_post",            handler::pep_api_replica_close::post},
		{"pep_api_replica_close_pre",             handler::pep_api_replica_close::pre},
		{"pep_api_replica_open_pre",              handler::pep_api_data_obj_open_pre},
		{"pep_api_rm_coll_post",                  handler::pep_api_rm_coll::post},
		{"pep_api_rm_coll_pre",                   handler::pep_api_rm_coll::pre},
		{"pep_api_touch_post",                    handler::pep_api_touch::post},
		{"pep_api_touch_pre",                     handler::pep_api_touch::pre}
	};
	// clang-format on

	//
	// Rule Engine Plugin
	//

	template <typename... Args>
	using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

	auto start(irods::default_re_ctx&, const std::string& _instance_name) -> irods::error
	{
		std::string config_path;

		if (auto error = irods::get_full_path_for_config_file("server_config.json", config_path); !error.ok()) {
			const char* msg = "Server configuration not found";

			// clang-format off
			log::rule_engine::error({{"rule_engine_plugin", "logical_quotas"},
					                 {"rule_engine_plugin_function", __func__},
					                 {"log_message", msg}});
			// clang-format on

			return ERROR(SYS_CONFIG_FILE_ERR, msg);
		}

		// clang-format off
		log::rule_engine::trace({{"rule_engine_plugin", "logical_quotas"},
				                 {"rule_engine_plugin_function", __func__},
				                 {"log_message", "Reading plugin configuration ..."}});
		// clang-format on

		json config;

		{
			std::ifstream config_file{config_path};
			config_file >> config;
		}

		try {
			const auto get_prop = [](const json& _config, auto&& _name) -> std::string {
				using name_type = decltype(_name);

				try {
					return _config.at(std::forward<name_type>(_name)).template get<std::string>();
				}
				catch (...) {
					throw std::runtime_error{fmt::format("Logical Quotas Policy: Failed to find rule engine "
					                                     "plugin configuration property [{}]",
					                                     std::forward<name_type>(_name))};
				}
			};

			for (const auto& re :
			     config.at(irods::KW_CFG_PLUGIN_CONFIGURATION).at(irods::KW_CFG_PLUGIN_TYPE_RULE_ENGINE)) {
				if (_instance_name == re.at(irods::KW_CFG_INSTANCE_NAME).get<std::string>()) {
					const auto& plugin_config = re.at(irods::KW_CFG_PLUGIN_SPECIFIC_CONFIGURATION);

					const auto& attr_names = [&plugin_config] {
						try {
							return plugin_config.at("metadata_attribute_names");
						}
						catch (...) {
							throw std::runtime_error{
								fmt::format("Logical Quotas Policy: Failed to find rule engine "
							                "plugin configuration property [metadata_attribute_names]")};
						}
					}();

					irods::instance_configuration instance_config{
						{get_prop(plugin_config, "namespace"),
					     get_prop(attr_names, "maximum_number_of_data_objects"),
					     get_prop(attr_names, "maximum_size_in_bytes"),
					     get_prop(attr_names, "total_number_of_data_objects"),
					     get_prop(attr_names, "total_size_in_bytes")}};

					instance_configs.insert_or_assign(_instance_name, instance_config);

					return SUCCESS();
				}
			}
		}
		catch (const std::exception& e) {
			// clang-format off
			log::rule_engine::error({{"rule_engine_plugin", "logical_quotas"},
					                 {"rule_engine_plugin_function", __func__},
					                 {"log_message", "Bad rule engine plugin configuration"}});
			// clang-format on

			return ERROR(SYS_CONFIG_FILE_ERR, e.what());
		}

		return ERROR(SYS_CONFIG_FILE_ERR, "[logical_quotas] Bad rule engine plugin configuration");
	}

	auto rule_exists(const std::string& _instance_name,
	                 irods::default_re_ctx&,
	                 const std::string& _rule_name,
	                 bool& _exists) -> irods::error
	{
		_exists = (logical_quotas_handlers.find(_rule_name) != std::end(logical_quotas_handlers) ||
		           pep_handlers.find(_rule_name) != std::end(pep_handlers));
		return SUCCESS();
	}

	auto list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules) -> irods::error
	{
		std::transform(std::begin(logical_quotas_handlers),
		               std::end(logical_quotas_handlers),
		               std::back_inserter(_rules),
		               [](auto _v) { return std::string{_v.first}; });

		std::transform(std::begin(pep_handlers), std::end(pep_handlers), std::back_inserter(_rules), [](auto _v) {
			return std::string{_v.first};
		});

		return SUCCESS();
	}

	auto exec_rule(const std::string& _instance_name,
	               irods::default_re_ctx&,
	               const std::string& _rule_name,
	               std::list<boost::any>& _rule_arguments,
	               irods::callback _effect_handler) -> irods::error
	{
		if (const auto iter = pep_handlers.find(_rule_name); iter != std::end(pep_handlers)) {
			return (iter->second)(_instance_name, instance_configs, _rule_arguments, nullptr, _effect_handler);
		}

		if (const auto iter = logical_quotas_handlers.find(_rule_name); iter != std::end(logical_quotas_handlers)) {
			return (iter->second)(_instance_name, instance_configs, _rule_arguments, nullptr, _effect_handler);
		}

		log::rule_engine::error(fmt::format("Rule not supported in rule engine plugin [rule => {}]", _rule_name));

		return CODE(RULE_ENGINE_CONTINUE);
	}

	auto exec_rule_text_impl(const std::string& _instance_name,
	                         std::string_view _rule_text,
	                         MsParamArray* _ms_param_array,
	                         irods::callback _effect_handler) -> irods::error
	{
		log::rule_engine::debug("_rule_text => [{}]", _rule_text);

		// irule <text>
		if (_rule_text.find("@external rule {") != std::string_view::npos) {
			const auto start = _rule_text.find_first_of('{') + 1;
			const auto end = _rule_text.rfind(" }");

			if (end == std::string_view::npos) {
				auto msg = fmt::format("Received malformed rule text. "
				                       "Expected closing curly brace following rule text [{}].",
				                       _rule_text);
				log::rule_engine::error(msg);
				return ERROR(SYS_INVALID_INPUT_PARAM, std::move(msg));
			}

			_rule_text = _rule_text.substr(start, end - start);
		}
		// irule -F <script>
		else if (const auto external_pos = _rule_text.find("@external\n"); external_pos != std::string_view::npos) {
			// If there are opening and closing curly braces following the "@external\n" prefix, then we
			// can assume that the rule text most likely represents a JSON string.
			if (const auto start = _rule_text.find_first_of('{'); start != std::string_view::npos) {
				const auto end = _rule_text.rfind(" }");

				if (end == std::string_view::npos) {
					auto msg = fmt::format("Received malformed rule text. "
					                       "Expected closing curly brace following rule text [{}].",
					                       _rule_text);
					log::rule_engine::error(msg);
					return ERROR(SYS_INVALID_INPUT_PARAM, std::move(msg));
				}

				_rule_text = _rule_text.substr(start, end - start);
			}
			// Otherwise, the rule text must represent something else. In this case, simply strip the
			// "@external\n" prefix from the rule text and let the JSON parser throw an exception if the
			// rule text cannot be parsed. This allows the REP to fail without causing the agent to crash.
			else {
				_rule_text = _rule_text.substr(external_pos + 10);
			}
		}

		log::rule_engine::debug("_rule_text => [{}]", _rule_text);

		try {
			const auto json_args = json::parse(_rule_text);

			log::rule_engine::debug({{"function", __func__}, {"json_arguments", json_args.dump()}});

			const auto& op = json_args.at("operation").get_ref<const std::string&>();

			if (const auto iter = logical_quotas_handlers.find(op); iter != std::end(logical_quotas_handlers)) {
				auto collection = json_args.at("collection").get<std::string>();

				std::list<boost::any> args{&collection};
				std::string value;

				// clang-format off
				if (op == "logical_quotas_set_maximum_number_of_data_objects" ||
					op == "logical_quotas_set_maximum_size_in_bytes")
				{
					value = json_args.at("value").get<std::string>();
					args.push_back(&value);
				}
				// clang-format on

				return (iter->second)(_instance_name, instance_configs, args, _ms_param_array, _effect_handler);
			}

			return ERROR(INVALID_OPERATION, fmt::format("Invalid operation [{}]", op));
		}
		catch (const json::parse_error& e) {
			// clang-format off
			log::rule_engine::error({{"rule_engine_plugin", "logical_quotas"},
					                 {"rule_engine_plugin_function", __func__},
					                 {"log_message", e.what()}});
			// clang-format on

			return ERROR(USER_INPUT_FORMAT_ERR, e.what());
		}
		catch (const json::type_error& e) {
			// clang-format off
			log::rule_engine::error({{"rule_engine_plugin", "logical_quotas"},
					                 {"rule_engine_plugin_function", __func__},
					                 {"log_message", e.what()}});
			// clang-format on

			return ERROR(SYS_INTERNAL_ERR, e.what());
		}
		catch (const std::exception& e) {
			// clang-format off
			log::rule_engine::error({{"rule_engine_plugin", "logical_quotas"},
					                 {"rule_engine_plugin_function", __func__},
					                 {"log_message", e.what()}});
			// clang-format on

			return ERROR(SYS_INTERNAL_ERR, e.what());
		}
		catch (...) {
			// clang-format off
			log::rule_engine::error({{"rule_engine_plugin", "logical_quotas"},
					                 {"rule_engine_plugin_function", __func__},
					                 {"log_message", "Unknown error"}});
			// clang-format on

			return ERROR(SYS_UNKNOWN_ERROR, "Unknown error");
		}
	}
} //namespace

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C" auto plugin_factory(const std::string& _instance_name, const std::string& _context) -> pluggable_rule_engine*
{
	const auto no_op = [](auto...) { return SUCCESS(); };

	const auto rule_exists_wrapper = [_instance_name](
										 irods::default_re_ctx& _ctx, const std::string& _rule_name, bool& _exists) {
		return rule_exists(_instance_name, _ctx, _rule_name, _exists);
	};

	const auto exec_rule_wrapper = [_instance_name](irods::default_re_ctx& _ctx,
	                                                const std::string& _rule_name,
	                                                std::list<boost::any>& _rule_arguments,
	                                                irods::callback _effect_handler) {
		return exec_rule(_instance_name, _ctx, _rule_name, _rule_arguments, _effect_handler);
	};

	const auto exec_rule_text_wrapper = [_instance_name](irods::default_re_ctx& _ctx,
	                                                     const std::string& _rule_text,
	                                                     msParamArray_t* _ms_params,
	                                                     const std::string& _out_desc,
	                                                     irods::callback _effect_handler) {
		if (const auto& rei = get_rei(_effect_handler); !irods::is_privileged_client(*rei.rsComm)) {
			return ERROR(CAT_INSUFFICIENT_PRIVILEGE_LEVEL, "Logical Quotas Policy: Insufficient privileges");
		}

		return exec_rule_text_impl(_instance_name, _rule_text, _ms_params, _effect_handler);
	};

	const auto exec_rule_expression_wrapper = [_instance_name](irods::default_re_ctx& _ctx,
	                                                           const std::string& _rule_text,
	                                                           msParamArray_t* _ms_params,
	                                                           irods::callback _effect_handler) {
		return exec_rule_text_impl(_instance_name, _rule_text, _ms_params, _effect_handler);
	};

	auto* re = new pluggable_rule_engine{_instance_name, _context};

	re->add_operation("start", operation<const std::string&>{start});
	re->add_operation("stop", operation<const std::string&>{no_op});
	re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists_wrapper});
	re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
	re->add_operation(
		"exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule_wrapper});
	re->add_operation(
		"exec_rule_text",
		operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{exec_rule_text_wrapper});
	re->add_operation("exec_rule_expression",
	                  operation<const std::string&, msParamArray_t*, irods::callback>{exec_rule_expression_wrapper});

	return re;
}
