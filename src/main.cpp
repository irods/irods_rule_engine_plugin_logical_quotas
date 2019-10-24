#include "instance_configuration.hpp"
#include "handler.hpp"

#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_get_full_path_for_config_file.hpp>
//#include <irods/irods_get_l1desc.hpp>
//#include <irods/irods_at_scope_exit.hpp>
//#include <irods/irods_query.hpp>
#include <irods/irods_logger.hpp>
//#include <irods/irods_state_table.h>
//#include <irods/modAVUMetadata.h>
//#include <irods/msParam.h>
//#include <irods/objDesc.hpp>
//#include <irods/objInfo.h>
//#include <irods/dataObjInpOut.h>
//#include <irods/rcConnect.h>
//#include <irods/rcMisc.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>

#include <boost/any.hpp>

#include <json.hpp>

//#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace
{
    // clang-format off
    using log  = irods::experimental::log;
    using json = nlohmann::json;
    // clang-format on

    irods::instance_configuration_map instance_configs;

    // This is a "sorted" list of the supported PEPs.
    // This will allow us to do binary search on the list for lookups.
    constexpr std::array<std::string_view, 28> peps{
        "logical_quotas_count_total_number_of_data_objects",
        "logical_quotas_count_total_size_in_bytes",
        "logical_quotas_recalculate_totals",
        "logical_quotas_set_maximum_number_of_data_objects",
        "logical_quotas_set_maximum_size_in_bytes",
        "logical_quotas_start_monitoring_collection",
        "logical_quotas_stop_monitoring_collection",
        "logical_quotas_unset_maximum_number_of_data_objects",
        "logical_quotas_unset_maximum_size_in_bytes",
        "logical_quotas_unset_total_number_of_data_objects",
        "logical_quotas_unset_total_size_in_bytes",
        "pep_api_data_obj_copy_post",
        "pep_api_data_obj_copy_pre",
        "pep_api_data_obj_open_and_stat_post",
        "pep_api_data_obj_open_and_stat_pre",
        "pep_api_data_obj_open_post",
        "pep_api_data_obj_open_pre",
        "pep_api_data_obj_put_post",
        "pep_api_data_obj_put_pre",
        "pep_api_data_obj_rename_post",
        "pep_api_data_obj_rename_pre",
        "pep_api_data_obj_unlink_post",
        "pep_api_data_obj_unlink_pre",
        "pep_api_data_obj_write_post",
        "pep_api_data_obj_write_pre",
        "pep_api_mod_avu_metadata_pre",
        "pep_api_rm_coll_post",
        "pep_api_rm_coll_pre"
    };

    //
    // Rule Engine Plugin
    //

    template <typename ...Args>
    using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

    irods::error start(irods::default_re_ctx&, const std::string& _instance_name)
    {
        std::string config_path;

        if (auto error = irods::get_full_path_for_config_file("server_config.json", config_path);
            !error.ok())
        {
            const auto msg = fmt::format("Server configuration not found [path => {}]", config_path);

            // clang-format off
            log::rule_engine::error({{"rule_engine_plugin", "logical_quotas"},
                                     {"rule_engine_plugin_function", __func__},
                                     {"log_message", msg}});
            // clang-format on

            return ERROR(SYS_CONFIG_FILE_ERR, msg.c_str());
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
            for (const auto& re : config.at(irods::CFG_PLUGIN_CONFIGURATION_KW).at(irods::PLUGIN_TYPE_RULE_ENGINE)) {
                if (_instance_name == re.at(irods::CFG_INSTANCE_NAME_KW).get<std::string>()) {
                    const auto& plugin_config = re.at(irods::CFG_PLUGIN_SPECIFIC_CONFIGURATION_KW);
                    const auto& attr_names = plugin_config.at("metadata_attribute_names");

                    irods::instance_configuration instance_config{{plugin_config.at("namespace").get<std::string>(),
                                                                   attr_names.at("maximum_number_of_data_objects").get<std::string>(),
                                                                   attr_names.at("maximum_size_in_bytes").get<std::string>(),
                                                                   attr_names.at("total_number_of_data_objects").get<std::string>(),
                                                                   attr_names.at("total_size_in_bytes").get<std::string>()}};

                    instance_configs.insert_or_assign(_instance_name, instance_config);

                    return SUCCESS();
                }
            }
        }
        catch (const std::exception& e) {
            // clang-format off
            log::rule_engine::error({{"rule_engine_plugin", "logical_quotas"},
                                     {"rule_engine_plugin_function", __func__},
                                     {"log_message", e.what()}});
            // clang-format on

            return ERROR(SYS_CONFIG_FILE_ERR, e.what());
        }

        return ERROR(SYS_CONFIG_FILE_ERR, "[logical_quotas] Bad rule engine plugin configuration");
    }

    irods::error rule_exists(const std::string& _instance_name,
                             irods::default_re_ctx&,
                             const std::string& _rule_name,
                             bool& _exists)
    {
        _exists = std::binary_search(std::begin(peps), std::end(peps), _rule_name);
        return SUCCESS();
    }

    irods::error list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules)
    {
        _rules.insert(std::end(_rules), std::begin(peps), std::end(peps));
        return SUCCESS();
    }

    irods::error exec_rule(const std::string& _instance_name,
                           irods::default_re_ctx&,
                           const std::string& _rule_name,
                           std::list<boost::any>& _rule_arguments,
                           irods::callback _effect_handler)
    {
        namespace handler = irods::handler;

        using handler_type = std::function<irods::error(const std::string&,
                                                        const irods::instance_configuration_map&,
                                                        std::list<boost::any>&,
                                                        irods::callback&)>;

        constexpr auto next_int = [] { static int i = 0; return i++; };

        static const std::map<std::string_view, handler_type> handlers{
            {peps[next_int()], handler::logical_quotas_count_total_number_of_data_objects},
            {peps[next_int()], handler::logical_quotas_count_total_size_in_bytes},
            {peps[next_int()], handler::logical_quotas_recalculate_totals},
            {peps[next_int()], handler::logical_quotas_set_maximum_number_of_data_objects},
            {peps[next_int()], handler::logical_quotas_set_maximum_size_in_bytes},
            {peps[next_int()], handler::logical_quotas_start_monitoring_collection},
            {peps[next_int()], handler::logical_quotas_stop_monitoring_collection},
            {peps[next_int()], handler::logical_quotas_unset_maximum_number_of_data_objects},
            {peps[next_int()], handler::logical_quotas_unset_maximum_size_in_bytes},
            {peps[next_int()], handler::logical_quotas_unset_total_number_of_data_objects},
            {peps[next_int()], handler::logical_quotas_unset_total_size_in_bytes},
            {peps[next_int()], handler::pep_api_data_obj_copy_post},
            {peps[next_int()], handler::pep_api_data_obj_copy_pre},
            {peps[next_int()], handler::pep_api_data_obj_open::post},
            {peps[next_int()], handler::pep_api_data_obj_open::post},
            {peps[next_int()], handler::pep_api_data_obj_open::pre},
            {peps[next_int()], handler::pep_api_data_obj_open::pre},
            {peps[next_int()], handler::pep_api_data_obj_put::post},
            {peps[next_int()], handler::pep_api_data_obj_put::pre},
            {peps[next_int()], handler::pep_api_data_obj_rename_post},
            {peps[next_int()], handler::pep_api_data_obj_rename_pre},
            {peps[next_int()], handler::pep_api_data_obj_unlink::post},
            {peps[next_int()], handler::pep_api_data_obj_unlink::pre},
            {peps[next_int()], handler::pep_api_data_obj_write::post},
            {peps[next_int()], handler::pep_api_data_obj_write::pre},
            {peps[next_int()], handler::pep_api_mod_avu_metadata_pre},
            {peps[next_int()], handler::pep_api_rm_coll::post},
            {peps[next_int()], handler::pep_api_rm_coll::pre}
        };

        if (auto iter = handlers.find(_rule_name); std::end(handlers) != iter) {
            return (iter->second)(_instance_name, instance_configs, _rule_arguments, _effect_handler);
        }

        log::rule_engine::error(fmt::format("Rule not supported in rule engine plugin [rule => {}]", _rule_name));

        return CODE(RULE_ENGINE_CONTINUE);
    }

    irods::error exec_rule_text_impl(const std::string& _instance_name,
                                     std::string_view _rule_text,
                                     irods::callback _effect_handler)
    {
        log::rule_engine::debug({{"_rule_text", std::string{_rule_text}}});

        // irule <text>
        if (const auto pos = _rule_text.find("@external rule {"); pos != std::string::npos) {
            const auto start = _rule_text.find_first_of('{') + 1;
            _rule_text = _rule_text.substr(start, _rule_text.rfind(" }") - start);

            log::rule_engine::debug({{"_rule_text", std::string{_rule_text}}});
        }
        // irule -F <script>
        else if (const auto pos = _rule_text.find("@external"); pos != std::string::npos) {
            const auto start = _rule_text.find_first_of('{');
            _rule_text = _rule_text.substr(start, _rule_text.rfind(" }") - start);

            log::rule_engine::debug({{"_rule_text", std::string{_rule_text}}});
        }

        try {
            const auto json_args = json::parse(_rule_text);

            log::rule_engine::debug({{"function", __func__}, {"json_arguments", json_args.dump()}});

            namespace handler = irods::handler;

            using handler_type = std::function<irods::error(const std::string&,
                                                            const irods::instance_configuration_map&,
                                                            std::list<boost::any>&,
                                                            irods::callback&)>;

            constexpr auto next_int = [] { static int i = 0; return i++; };

            static const std::map<std::string_view, handler_type> handlers{
                {peps[next_int()], handler::logical_quotas_count_total_number_of_data_objects},
                {peps[next_int()], handler::logical_quotas_count_total_size_in_bytes},
                {peps[next_int()], handler::logical_quotas_recalculate_totals},
                {peps[next_int()], handler::logical_quotas_set_maximum_number_of_data_objects},
                {peps[next_int()], handler::logical_quotas_set_maximum_size_in_bytes},
                {peps[next_int()], handler::logical_quotas_start_monitoring_collection},
                {peps[next_int()], handler::logical_quotas_stop_monitoring_collection},
                {peps[next_int()], handler::logical_quotas_unset_maximum_number_of_data_objects},
                {peps[next_int()], handler::logical_quotas_unset_maximum_size_in_bytes},
                {peps[next_int()], handler::logical_quotas_unset_total_number_of_data_objects},
                {peps[next_int()], handler::logical_quotas_unset_total_size_in_bytes}
            };

            const auto op = json_args.at("operation").get<std::string>();

            if (auto iter = handlers.find(op); std::end(handlers) != iter) {
                std::list<boost::any> args{json_args.at("collection").get<std::string>() };

                if (op == "logical_quotas_set_maximum_number_of_data_objects") {
                    args.push_back(json_args.at("maximum_number_of_data_objects").get<std::string>());
                }
                else if (op == "logical_quotas_set_maximum_size_in_bytes") {
                    args.push_back(json_args.at("maximum_size_in_bytes").get<std::string>());
                }

                return (iter->second)(_instance_name, instance_configs, args, _effect_handler);
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
} // namespace (anonymous)

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> pluggable_rule_engine*
{
    // clang-format off
    const auto no_op = [](auto...) { return SUCCESS(); };

    const auto rule_exists_wrapper = [_instance_name](irods::default_re_ctx& _ctx,
                                                      const std::string& _rule_name,
                                                      bool& _exists)
    {
        return rule_exists(_instance_name, _ctx, _rule_name, _exists);
    };

    const auto exec_rule_wrapper = [_instance_name](irods::default_re_ctx& _ctx,
                                                    const std::string& _rule_name,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback _effect_handler)
    {
        return exec_rule(_instance_name, _ctx, _rule_name, _rule_arguments, _effect_handler);
    };

    const auto exec_rule_text_wrapper = [_instance_name](irods::default_re_ctx& _ctx,
                                                         const std::string& _rule_text,
                                                         msParamArray_t* _ms_params,
                                                         const std::string& _out_desc,
                                                         irods::callback _effect_handler)
    {
        return exec_rule_text_impl(_instance_name, _rule_text, _effect_handler);
    };

    const auto exec_rule_expression_wrapper = [_instance_name](irods::default_re_ctx& _ctx,
                                                               const std::string& _rule_text,
                                                               msParamArray_t* _ms_params,
                                                               irods::callback _effect_handler)
    {
        return exec_rule_text_impl(_instance_name, _rule_text, _effect_handler);
    };
    // clang-format on

    auto* re = new pluggable_rule_engine{_instance_name, _context};

    re->add_operation("start", operation<const std::string&>{start});
    re->add_operation("stop", operation<const std::string&>{no_op});
    re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists_wrapper});
    re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
    re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule_wrapper});
    re->add_operation("exec_rule_text", operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{exec_rule_text_wrapper});
    re->add_operation("exec_rule_expression", operation<const std::string&, msParamArray_t*, irods::callback>{exec_rule_expression_wrapper});

    return re;
}

