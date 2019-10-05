#include "optional"
#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_get_full_path_for_config_file.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_query.hpp>
#include <irods/irods_logger.hpp>
#include <irods/filesystem.hpp>
#include <irods/msParam.h>
#include <irods/objDesc.hpp>
#include <irods/objInfo.h>
#include <irods/dataObjInpOut.h>
#include <irods/rcConnect.h>
#include <irods/rcMisc.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>

#include <boost/any.hpp>
#include <boost/filesystem.hpp>

#include <json.hpp>

#include <stdexcept>
#include <string>
#include <string_view>
#include <array>
#include <algorithm>
#include <iterator>
#include <functional>
#include <list>
#include <optional>
#include <unordered_map>
#include <tuple>

namespace
{
    namespace fs = irods::experimental::filesystem;

    // clang-format off
    using json               = nlohmann::json;
    using log                = irods::experimental::log;
    using tracking_info_type = std::unordered_map<std::string, std::uint64_t>;
    // clang-format on

    struct logical_quotas_violation
        : public std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    // clang-format off
    // TODO This must be configurable.
    const char* maximum_object_count_key       = "logical_quotas::maximum_object_count";
    const char* maximum_data_size_in_bytes_key = "logical_quotas::maximum_data_size_in_bytes";
    const char* current_object_count_key       = "logical_quotas::current_object_count";
    const char* current_data_size_in_bytes_key = "logical_quotas::current_data_size_in_bytes";
    // clang-format on

    // This is a "sorted" list of the supported PEPs.
    // This will allow us to do binary search on the list for lookups.
    // TODO Need to add POSIX/streaming support (open, read, write, close).
    constexpr std::array<const char*, 12> peps{
        "logical_quotas_init",
        "logical_quotas_remove",
        "pep_api_data_obj_copy_post",
        "pep_api_data_obj_copy_pre",
        "pep_api_data_obj_put_post",
        "pep_api_data_obj_put_pre",
        "pep_api_data_obj_rename_post",
        "pep_api_data_obj_rename_pre",
        "pep_api_data_obj_unlink_post",
        "pep_api_data_obj_unlink_pre",
        "pep_api_rm_coll_post",
        "pep_api_rm_coll_pre"
    };

    namespace util
    {
        void concat_impl(std::string&)
        {
        }

        template <typename Head, typename ...Tail>
        void concat_impl(std::string& _dst, Head&& _head, Tail&&... _tail)
        {
            _dst += std::forward<Head>(_head);
            concat_impl(_dst, std::forward<Tail>(_tail)...);
        }

        template <typename ...Args>
        std::string concat(Args&&... _args)
        {
            std::string result;
            concat_impl(result, std::forward<Args>(_args)...);
            return result;
        }

        ruleExecInfo_t& get_rei(irods::callback& _effect_handler)
        {
            ruleExecInfo_t* rei{};

            if (const auto result = _effect_handler("unsafe_ms_ctx", &rei); !result.ok()) {
                THROW(result.code(), "failed to get rule execution info");
            }

            return *rei;
        }

        template <typename Function>
        auto switch_user(ruleExecInfo_t& _rei, Function _func) -> decltype(_func())
        {
            auto& auth_flag = _rei.rsComm->clientUser.authInfo.authFlag;
            const auto old_auth_flag = auth_flag;

            // Elevate privileges.
            auth_flag = LOCAL_PRIV_USER_AUTH;

            // Restore authorization flags on exit.
            irods::at_scope_exit<std::function<void()>> at_scope_exit{
                [&auth_flag, old_auth_flag] { auth_flag = old_auth_flag; }
            };

            return _func();
        }

        void log_exception_message(const char* _msg, irods::callback& _effect_handler)
        {
            rodsLog(LOG_ERROR, "%s", _msg);
            addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, RE_RUNTIME_ERROR, _msg);
        }

        template <typename T>
        T* get_input_object_ptr(std::list<boost::any>& _rule_arguments, int _index = 0)
        {
            return boost::any_cast<T*>(*std::next(std::begin(_rule_arguments), _index + 2));
        }

        tracking_info_type get_tracked_collection_info(rsComm_t& _conn, const fs::path& _p)
        {
            log::rule_engine::debug("in get_tracked_collection_info");

            tracking_info_type info;

            std::string gql = "select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = '";
            gql += _p;
            gql += "'";

            for (auto&& row : irods::query{&_conn, gql}) {
                // clang-format off
                if      (maximum_object_count_key == row[0])       { info[maximum_object_count_key] = std::stoull(row[1]); }
                else if (maximum_data_size_in_bytes_key == row[0]) { info[maximum_data_size_in_bytes_key] = std::stoull(row[1]); }
                else if (current_object_count_key == row[0])       { info[current_object_count_key] = std::stoull(row[1]); }
                else if (current_data_size_in_bytes_key == row[0]) { info[current_data_size_in_bytes_key] = std::stoull(row[1]); }
                // clang-format on
            }

            return info;
        }

        void throw_if_maximum_count_violation(const tracking_info_type& _tracking_info, std::uint64_t _delta)
        {
            if (_tracking_info.at(current_object_count_key) + _delta > _tracking_info.at(maximum_object_count_key)) {
                throw logical_quotas_violation{"Policy Violation: Adding object exceeds maximum number of objects limit"};
            }
        }

        void throw_if_maximum_size_in_bytes_violation(const tracking_info_type& _tracking_info, std::uint64_t _delta)
        {
            if (_tracking_info.at(current_data_size_in_bytes_key) + _delta > _tracking_info.at(maximum_data_size_in_bytes_key)) {
                throw logical_quotas_violation{"Policy Violation: Adding object exceeds maximum data size in bytes limit"};
            }
        }

        bool is_tracked_collection(rsComm_t& _conn, const fs::path& _p)
        {
            log::rule_engine::debug("in is_tracked_collection");

            std::string gql = "select META_COLL_ATTR_NAME where COLL_NAME = '";
            gql += _p;
            gql += "' and META_COLL_ATTR_NAME = '";
            gql += maximum_object_count_key;
            gql += "'"; 

            for (auto&& row : irods::query{&_conn, gql}) {
                return true;
            }

            return false;
        }

        std::optional<fs::path> get_tracked_parent_collection(rsComm_t& _conn, fs::path _p)
        {
            for (; !_p.empty(); _p = _p.parent_path()) {
                if (is_tracked_collection(_conn, _p)) {
                    return _p;
                }
            }

            return std::nullopt;
        }

        std::tuple<std::uint64_t, std::uint64_t> compute_data_object_count_and_size(rsComm_t& _conn, fs::path _p)
        {
            std::uint64_t objects = 0;
            std::uint64_t bytes = 0;

            std::string gql = "select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = '";
            gql += _p;
            gql += "' || like '";
            gql += _p;
            gql += "/%'";

            for (auto&& row : irods::query{&_conn, gql}) {
                objects = std::stoull(row[0]);
                bytes = std::stoull(row[1]);
            }

            return {objects, bytes};
        }

        template <typename Function>
        void for_each_tracked_collection(rsComm_t& _conn, fs::path _collection, Function _func)
        {
            for (auto tracked_collection = util::get_tracked_parent_collection(_conn, _collection);
                 tracked_collection;
                 tracked_collection = util::get_tracked_parent_collection(_conn, tracked_collection->parent_path()))
            {
                auto tracked_info = util::get_tracked_collection_info(_conn, *tracked_collection);
                _func(*tracked_collection, tracked_info);
            }
        }
    } // namespace util

    //
    // PEP Handlers
    //

    namespace handler
    {
        irods::error logical_quotas_init(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            // clang-format off
            log::rule_engine::debug({{"rule_engine_plugin", "logical_quotas"},
                                     {"rule_engine_plugin_function", __func__}});
            // clang-format on

            try
            {
                auto args_iter = std::begin(_rule_arguments);

                const auto path = boost::any_cast<std::string>(*args_iter);

                std::string objects;
                std::string bytes;

                std::string gql = "select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = '";
                gql += path;
                gql += "' || like '";
                gql += path;
                gql += "/%'";

                auto& rei = util::get_rei(_effect_handler);

                for (auto&& row : irods::query{rei.rsComm, gql}) {
                    objects = row[0];
                    bytes = row[1];
                }

                const auto max_objects = std::to_string(boost::any_cast<std::uint64_t>(*++args_iter));
                const auto max_bytes = std::to_string(boost::any_cast<std::uint64_t>(*++args_iter));

                fs::server::set_metadata(*rei.rsComm, path, {maximum_object_count_key,       max_objects});
                fs::server::set_metadata(*rei.rsComm, path, {maximum_data_size_in_bytes_key, max_bytes});
                fs::server::set_metadata(*rei.rsComm, path, {current_object_count_key,       objects.empty() ? "0" : objects});
                fs::server::set_metadata(*rei.rsComm, path, {current_data_size_in_bytes_key, bytes.empty() ? "0" : bytes});
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return SUCCESS();
        }
        
        irods::error logical_quotas_remove(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            // clang-format off
            log::rule_engine::debug({{"rule_engine_plugin", "logical_quotas"},
                                     {"rule_engine_plugin_function", __func__}});
            // clang-format on

            try
            {
                //auto coll_path = util::get_input_object_ptr<std::string>(_rule_arguments);
                //auto max_number_of_objects = util::get_input_object_ptr<std::string>(_rule_arguments, 1);
                //auto max_size_in_bytes = util::get_input_object_ptr<std::string>(_rule_arguments, 2);

            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return SUCCESS();
        }
        
        irods::error pep_api_data_obj_copy_pre(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                //auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_copy_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                //auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_put_pre(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
                auto& rei = util::get_rei(_effect_handler);
                auto& conn = *rei.rsComm;

                if (!fs::server::exists(*rei.rsComm, input->objPath)) {
                    util::for_each_tracked_collection(conn, input->objPath, [input](auto&, auto& _info) {
                        util::throw_if_maximum_count_violation(_info, 1);
                        util::throw_if_maximum_size_in_bytes_violation(_info, input->dataSize);
                    });
                }
            }
            catch (const logical_quotas_violation& e) {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
            }
            catch (const std::exception& e) {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_put_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
                auto& rei = util::get_rei(_effect_handler);
                auto& conn = *rei.rsComm;

                util::for_each_tracked_collection(conn, input->objPath, [&conn, input](const auto& _collection, auto& _info) {
                    const auto new_object_count = std::to_string(_info[current_object_count_key] + 1);
                    fs::server::set_metadata(conn, _collection, {current_object_count_key, new_object_count});

                    const auto new_size_in_bytes = std::to_string(_info[current_data_size_in_bytes_key] + input->dataSize);
                    fs::server::set_metadata(conn, _collection, {current_data_size_in_bytes_key, new_size_in_bytes});
                });
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_rename_pre(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                //auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_rename_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                //auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_unlink_pre(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                //auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_unlink_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                //auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        class pep_api_rm_coll
        {
        public:
            static irods::error pre(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<collInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;

                    if (auto tracked_collection = util::get_tracked_parent_collection(conn, input->collName); tracked_collection) {
                        auto info = util::get_tracked_collection_info(conn, *tracked_collection);
                        std::tie(data_objects_, size_in_bytes_) = util::compute_data_object_count_and_size(conn, input->collName);
                    }
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

            static irods::error post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<collInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;

                    util::for_each_tracked_collection(conn, input->collName, [&conn, input](const auto& _collection, auto& _info) {
                        const auto new_object_count = std::to_string(_info[current_object_count_key] - data_objects_);
                        fs::server::set_metadata(conn, _collection, {current_object_count_key, new_object_count});

                        const auto new_size_in_bytes = std::to_string(_info[current_data_size_in_bytes_key] - size_in_bytes_);
                        fs::server::set_metadata(conn, _collection, {current_data_size_in_bytes_key, new_size_in_bytes});
                    });
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

        private:
            inline static std::uint64_t data_objects_ = 0;
            inline static std::uint64_t size_in_bytes_ = 0;
        }; // class pep_api_rm_coll
    } // namespace handler

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
            std::string msg = "Server configuration not found [path => ";
            msg += config_path;
            msg += ']';

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
            // Iterate over the list of rule engine plugins until the Passthrough REP is found.
            //for (const auto& re : config.at(irods::CFG_PLUGIN_CONFIGURATION_KW).at(irods::PLUGIN_TYPE_RULE_ENGINE)) {
                //if (_instance_name == re.at(irods::CFG_INSTANCE_NAME_KW).get<std::string>()) {
                    // Fill the "pep_configs" plugin variable with objects containing the values
                    // defined in the "return_codes_for_peps" configuration. Each object in the list
                    // will contain a regular expression and a code.
                    //for (const auto& e : re.at(irods::CFG_PLUGIN_SPECIFIC_CONFIGURATION_KW).at("return_codes_for_peps")) {
                        //pep_configs[_instance_name].push_back({std::regex{e.at("regex").get<std::string>()}, e.at("code").get<int>()});
                    //}

                    return SUCCESS();
                //}
            //}
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
        log::rule_engine::debug("In rule_exists");

        auto b = std::cbegin(peps);
        auto e = std::cend(peps);

        _exists = std::binary_search(b, e, _rule_name.c_str(), [](const auto* _lhs, const auto* _rhs) {
            return strcmp(_lhs, _rhs) < 0;
        });

        log::rule_engine::debug({{"rule_name", _rule_name}, {"rule_exists", std::to_string(_exists)}});

        return SUCCESS();
    }

    irods::error list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules)
    {
        log::rule_engine::debug("In list_rules");
        _rules.insert(std::end(_rules), std::begin(peps), std::end(peps));
        return SUCCESS();
    }

    irods::error exec_rule(const std::string& _instance_name,
                           irods::default_re_ctx&,
                           const std::string& _rule_name,
                           std::list<boost::any>& _rule_arguments,
                           irods::callback _effect_handler)
    {
        log::rule_engine::debug("In exec_rule");

        constexpr auto next_int = [] { static int i = 0; return i++; };

        using handler_t = std::function<irods::error(std::list<boost::any>&, irods::callback&)>;

        static const std::map<std::string, handler_t> handlers{
#if 0
            {peps[0], handler::logical_quotas_init},
            {peps[1], handler::logical_quotas_remove},
            {peps[2], handler::pep_api_data_obj_copy_post},
            {peps[3], handler::pep_api_data_obj_copy_pre},
            {peps[4], handler::pep_api_data_obj_put_post},
            {peps[5], handler::pep_api_data_obj_put_pre},
            {peps[6], handler::pep_api_data_obj_rename_post},
            {peps[7], handler::pep_api_data_obj_rename_pre},
            {peps[8], handler::pep_api_data_obj_unlink_post},
            {peps[9], handler::pep_api_data_obj_unlink_pre},
            {peps[10], handler::pep_api_rm_coll::post},
            {peps[11], handler::pep_api_rm_coll::pre}
#else
            {peps[next_int()], handler::logical_quotas_init},
            {peps[next_int()], handler::logical_quotas_remove},
            {peps[next_int()], handler::pep_api_data_obj_copy_post},
            {peps[next_int()], handler::pep_api_data_obj_copy_pre},
            {peps[next_int()], handler::pep_api_data_obj_put_post},
            {peps[next_int()], handler::pep_api_data_obj_put_pre},
            {peps[next_int()], handler::pep_api_data_obj_rename_post},
            {peps[next_int()], handler::pep_api_data_obj_rename_pre},
            {peps[next_int()], handler::pep_api_data_obj_unlink_post},
            {peps[next_int()], handler::pep_api_data_obj_unlink_pre},
            {peps[next_int()], handler::pep_api_rm_coll::post},
            {peps[next_int()], handler::pep_api_rm_coll::pre}
#endif
        };

        auto iter = handlers.find(_rule_name);

        if (std::end(handlers) != iter) {
            log::rule_engine::debug("Found handler. Processing request ...");
            return (iter->second)(_rule_arguments, _effect_handler);
        }

        const auto* msg = "[irods_rule_engine_plugin-logical_quotas][rule => %s] "
                          "rule not supported in rule engine plugin";

        rodsLog(LOG_ERROR, msg, _rule_name.c_str());

        // DO NOT BLOCK RULE ENGINE PLUGINS THAT FOLLOW THIS ONE!
        //return CODE(RULE_ENGINE_CONTINUE);
        log::rule_engine::debug("No handler found. Returned SUCCESS()");
        return SUCCESS();
    }

    irods::error exec_rule_text_impl(const std::string& _instance_name,
                                     std::string_view _rule_text,
                                     irods::callback _effect_handler)
    {
        log::rule_engine::debug({{"_rule_text", std::string{_rule_text}}});

        if (const auto pos = _rule_text.find("@external rule {"); pos != std::string::npos) {
            const auto start = _rule_text.find_first_of('{') + 1;
            _rule_text = _rule_text.substr(start, _rule_text.rfind(" }") - start);

            log::rule_engine::debug({{"_rule_text", std::string{_rule_text}}});
        }

        try {
            const auto json_args = json::parse(_rule_text);

            log::rule_engine::debug({{"function", __func__}, {"json_arguments", json_args.dump()}});

            // This function only supports the following operations:
            // - logical_quotas_init
            // - logical_quotas_remove

            if (const auto op = json_args.at("operation").get<std::string>(); op == "logical_quotas_init") {
                std::list<boost::any> args{
                    json_args.at("collection").get<std::string>(),
                    json_args.at("maximum_number_of_objects").get<std::uint64_t>(),
                    json_args.at("maximum_size_in_bytes").get<std::uint64_t>()
                };

                return handler::logical_quotas_init(args, _effect_handler);
            }
            else if (op == "logical_quotas_remove") {
                std::list<boost::any> args;
                return handler::logical_quotas_remove(args, _effect_handler);
            }
            else {
                return ERROR(INVALID_OPERATION, "Invalid operation [" + op + ']');
            }
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

        return SUCCESS();
    }

#if 0
    irods::error exec_rule_text(const std::string& _instance_name,
                               irods::default_re_ctx&,
                               const std::string& _rule_text,
                               msParamArray_t*,
                               const std::string&,
                               irods::callback _effect_handler)
    {
        return SUCCESS();
    }

    irods::error exec_rule_expression(const std::string& _instance_name,
                                      irods::default_re_ctx&,
                                      const std::string& _rule_text,
                                      msParamArray_t*,
                                      irods::callback _effect_handler)
    {
        return SUCCESS();
    }
#endif
} // namespace (anonymous)

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C"
pluggable_rule_engine* plugin_factory(const std::string& _instance_name,
                                      const std::string& _context)
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
        //return exec_rule_text(_instance_name, _ctx, _rule_text, _ms_params, _out_desc, _effect_handler);
    };

    const auto exec_rule_expression_wrapper = [_instance_name](irods::default_re_ctx& _ctx,
                                                               const std::string& _rule_text,
                                                               msParamArray_t* _ms_params,
                                                               irods::callback _effect_handler)
    {
        return exec_rule_text_impl(_instance_name, _rule_text, _effect_handler);
        //return exec_rule_expression(_instance_name, _ctx, _rule_text, _ms_params, _effect_handler);
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

