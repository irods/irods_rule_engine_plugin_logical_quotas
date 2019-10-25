#include "handler.hpp"

#include "logical_quotas_error.hpp"
#include "switch_user_error.hpp"

#include <irods/irods_query.hpp>
#include <irods/filesystem.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_get_l1desc.hpp>
#include <irods/modAVUMetadata.h>
#include <irods/rodsLog.h>

#include <fmt/format.h>
#include <boost/optional.hpp>

#include <string>
#include <vector>
#include <functional>
#include <tuple>

namespace
{
    // clang-format off
    namespace fs           = irods::experimental::filesystem;

    using size_type        = irods::handler::size_type;
    using quotas_info_type = std::unordered_map<std::string, size_type>;
    // clang-format on

    //
    // Function Prototypes
    //

    auto get_rei(irods::callback& _effect_handler) -> ruleExecInfo_t&;

    auto get_collection_id(rsComm_t& _conn, fs::path _p) -> boost::optional<std::string>;

    auto get_collection_user_id(rsComm_t& _conn, const std::string& _collection_id) -> boost::optional<std::string>;

    auto get_collection_username(rsComm_t& _conn, fs::path _p) -> boost::optional<std::string>;

    auto get_monitored_collection_info(rsComm_t& _conn,
                                       const irods::attributes& _attrs,
                                       const fs::path& _p) -> quotas_info_type;

    auto throw_if_maximum_number_of_data_objects_violation(const irods::attributes& _attrs,
                                                           const quotas_info_type& _tracking_info,
                                                           size_type _delta) -> void;

    auto throw_if_maximum_size_in_bytes_violation(const irods::attributes& _attrs,
                                                  const quotas_info_type& _tracking_info,
                                                  size_type _delta) -> void;

    auto is_monitored_collection(rsComm_t& _conn,
                                 const irods::attributes& _attrs,
                                 const fs::path& _p) -> bool;

    auto get_monitored_parent_collection(rsComm_t& _conn,
                                         const irods::attributes& _attrs,
                                         fs::path _p) -> boost::optional<fs::path>;

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
                             std::function<std::vector<const std::string*> (const irods::attributes& _attrs)> _func) -> irods::error;

    auto log_exception_message(const char* _msg, irods::callback& _effect_handler) -> void;

    template <typename T>
    auto get_pointer(std::list<boost::any>& _rule_arguments, int _index = 2) -> T*;

    template <typename Function>
    auto switch_user(ruleExecInfo_t& _rei, const std::string& _username, Function _func) -> void;

    template <typename Function>
    auto for_each_monitored_collection(rsComm_t& _conn,
                                       const irods::attributes& _attrs,
                                       fs::path _collection,
                                       Function _func) -> void;

    //
    // Function Implementations
    //

    auto get_rei(irods::callback& _effect_handler) -> ruleExecInfo_t&
    {
        ruleExecInfo_t* rei{};

        const auto result = _effect_handler("unsafe_ms_ctx", &rei);

        if (!result.ok()) {
            const auto error_code = static_cast<irods::logical_quotas_error::error_code_type>(result.code());
            throw irods::logical_quotas_error{"Failed to get rule execution information", error_code};
        }

        return *rei;
    }

    auto get_collection_id(rsComm_t& _conn, fs::path _p) -> boost::optional<std::string>
    {
        const auto gql = fmt::format("select COLL_ID where COLL_NAME = '{}'", _p.c_str());

        for (auto&& row : irods::query<rsComm_t>{&_conn, gql}) {
            return row[0];
        }

        return boost::none;
    }

    auto get_collection_user_id(rsComm_t& _conn, const std::string& _collection_id) -> boost::optional<std::string>
    {
        const auto gql = fmt::format("select COLL_ACCESS_USER_ID where COLL_ACCESS_COLL_ID = '{}' and COLL_ACCESS_NAME = 'own'", _collection_id);

        for (auto&& row : irods::query<rsComm_t>{&_conn, gql}) {
            return row[0];
        }

        return boost::none;
    }

    auto get_collection_username(rsComm_t& _conn, fs::path _p) -> boost::optional<std::string>
    {
        auto coll_id = get_collection_id(_conn, _p);

        if (!coll_id) {
            return boost::none;
        }

        auto user_id = get_collection_user_id(_conn, *coll_id);

        if (!user_id) {
            return boost::none;
        }

        const auto gql = fmt::format("select USER_NAME where USER_ID = '{}'", *user_id);

        for (auto&& row : irods::query<rsComm_t>{&_conn, gql}) {
            return row[0];
        }

        return boost::none;
    }

    auto get_monitored_collection_info(rsComm_t& _conn, const irods::attributes& _attrs, const fs::path& _p) -> quotas_info_type
    {
        quotas_info_type info;

        const auto gql = fmt::format("select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = '{}'", _p.c_str());

        for (auto&& row : irods::query<rsComm_t>{&_conn, gql}) {
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

        if (_tracking_info.find(max_attr_name) != std::end(_tracking_info)) {
            if (_tracking_info.at(_attrs.total_number_of_data_objects()) + _delta > _tracking_info.at(max_attr_name)) {
                throw irods::logical_quotas_error{"Policy Violation: Adding object exceeds maximum number of objects limit", SYS_RESC_QUOTA_EXCEEDED};
            }
        }
    }

    auto throw_if_maximum_size_in_bytes_violation(const irods::attributes& _attrs,
                                                  const quotas_info_type& _tracking_info,
                                                  size_type _delta) -> void
    {
        const auto& max_attr_name = _attrs.maximum_size_in_bytes();

        if (_tracking_info.find(max_attr_name) != std::end(_tracking_info)) {
            if (_tracking_info.at(_attrs.total_size_in_bytes()) + _delta > _tracking_info.at(max_attr_name)) {
                throw irods::logical_quotas_error{"Policy Violation: Adding object exceeds maximum data size in bytes limit", SYS_RESC_QUOTA_EXCEEDED};
            }
        }
    }

    auto is_monitored_collection(rsComm_t& _conn, const irods::attributes& _attrs, const fs::path& _p) -> bool
    {
        const auto gql = fmt::format("select META_COLL_ATTR_NAME where COLL_NAME = '{}' and META_COLL_ATTR_NAME = '{}' || = '{}'",
                                     _p.c_str(),
                                     _attrs.total_number_of_data_objects(),
                                     _attrs.total_size_in_bytes());

        for (auto&& row : irods::query<rsComm_t>{&_conn, gql}) {
            return true;
        }

        return false;
    }

    auto get_monitored_parent_collection(rsComm_t& _conn, const irods::attributes& _attrs, fs::path _p) -> boost::optional<fs::path>
    {
        for (; !_p.empty(); _p = _p.parent_path()) {
            if (is_monitored_collection(_conn, _attrs, _p)) {
                return _p;
            }
            else if ("/" == _p) {
                break;
            }
        }

        return boost::none;
    }

    auto compute_data_object_count_and_size(rsComm_t& _conn, fs::path _p) -> std::tuple<size_type, size_type>
    {
        size_type objects = 0;
        size_type bytes = 0;

        const auto gql = fmt::format("select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = '{0}' || like '{0}/%'", _p.c_str());

        for (auto&& row : irods::query<rsComm_t>{&_conn, gql}) {
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
            const auto new_object_count = std::to_string(_info.at(_attrs.total_number_of_data_objects()) + _data_objects_delta);
            fs::server::set_metadata(_conn, _collection, {_attrs.total_number_of_data_objects(), new_object_count});
        }

        if (0 != _size_in_bytes_delta) {
            const auto new_size_in_bytes = std::to_string(_info.at(_attrs.total_size_in_bytes()) + _size_in_bytes_delta);
            fs::server::set_metadata(_conn, _collection, {_attrs.total_size_in_bytes(), new_size_in_bytes});
        }
    }

    auto unset_metadata_impl(const std::string& _instance_name,
                             const irods::instance_configuration_map& _instance_configs,
                             std::list<boost::any>& _rule_arguments,
                             irods::callback& _effect_handler,
                             std::function<std::vector<const std::string*> (const irods::attributes& _attrs)> _func) -> irods::error
    {
        try
        {
            auto args_iter = std::begin(_rule_arguments);
            const auto path = boost::any_cast<std::string>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            auto username = get_collection_username(conn, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto& attrs = _instance_configs.at(_instance_name).attributes();

                if (!is_monitored_collection(conn, attrs, path)) {
                    throw std::runtime_error{fmt::format("Logical Quotas Policy: [{}] is not a monitored collection", path)};
                }

                const auto info = get_monitored_collection_info(conn, attrs, path);

                try {
                    for (auto&& attribute_name : _func(attrs)) {
                        fs::server::remove_metadata(conn, path, {*attribute_name,  std::to_string(info.at(*attribute_name))});
                    }
                }
                catch (const std::out_of_range& e) {
                    rodsLog(LOG_ERROR, e.what());
                    throw std::runtime_error{"Logical Quotas Policy: Missing key"};
                }
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }

    auto log_exception_message(const char* _msg, irods::callback& _effect_handler) -> void
    {
        rodsLog(LOG_ERROR, _msg);
        addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, RE_RUNTIME_ERROR, _msg);
    }

    template <typename T>
    auto get_pointer(std::list<boost::any>& _rule_arguments, int _index) -> T*
    {
        return boost::any_cast<T*>(*std::next(std::begin(_rule_arguments), _index));
    }

    template <typename Function>
    auto switch_user(ruleExecInfo_t& _rei, const std::string& _username, Function _func) -> void
    {
        auto& user = _rei.rsComm->clientUser;

        if (user.authInfo.authFlag < LOCAL_PRIV_USER_AUTH) {
            throw irods::switch_user_error{"Logical Quotas Policy: Insufficient privileges", SYS_NO_API_PRIV};
        }

        const std::string old_username = user.userName;

        rstrcpy(user.userName, _username.data(), NAME_LEN);

        irods::at_scope_exit<std::function<void()>> at_scope_exit{[&user, &old_username] {
            rstrcpy(user.userName, old_username.c_str(), MAX_NAME_LEN);
        }};

        _func();
    }

    template <typename Function>
    auto for_each_monitored_collection(rsComm_t& _conn,
                                       const irods::attributes& _attrs,
                                       fs::path _collection,
                                       Function _func) -> void
    {
        for (auto collection = get_monitored_parent_collection(_conn, _attrs, _collection);
             collection;
             collection = get_monitored_parent_collection(_conn, _attrs, collection->parent_path()))
        {
            auto info = get_monitored_collection_info(_conn, _attrs, *collection);
            _func(*collection, info);
        }
    }
} // anonymous namespace

//
// Handlers
//

namespace irods {
namespace handler {

    auto logical_quotas_start_monitoring_collection(const std::string& _instance_name,
                                                    const instance_configuration_map& _instance_configs,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error
    {
        return logical_quotas_recalculate_totals(_instance_name, _instance_configs, _rule_arguments, _effect_handler);
    }
    
    auto logical_quotas_stop_monitoring_collection(const std::string& _instance_name,
                                                   const instance_configuration_map& _instance_configs,
                                                   std::list<boost::any>& _rule_arguments,
                                                   irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
            return std::vector<const std::string*>{&_attrs.total_number_of_data_objects(), &_attrs.total_size_in_bytes()};
        });
    }

    auto logical_quotas_count_total_number_of_data_objects(const std::string& _instance_name,
                                                           const instance_configuration_map& _instance_configs,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto args_iter = std::begin(_rule_arguments);
            const auto path = boost::any_cast<std::string>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto username = get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto gql = fmt::format("select count(DATA_NAME) where COLL_NAME = '{0}' || like '{0}/%'", path);
                std::string objects;

                for (auto&& row : irods::query<rsComm_t>{rei.rsComm, gql}) {
                    objects = row[0];
                }

                const auto& attrs = _instance_configs.at(_instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.total_number_of_data_objects(),  objects.empty() ? "0" : objects});
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }

    auto logical_quotas_count_total_size_in_bytes(const std::string& _instance_name,
                                                  const instance_configuration_map& _instance_configs,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto args_iter = std::begin(_rule_arguments);
            const auto path = boost::any_cast<std::string>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto username = get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto gql = fmt::format("select sum(DATA_SIZE) where COLL_NAME = '{0}' || like '{0}/%'", path);
                std::string bytes;

                for (auto&& row : irods::query<rsComm_t>{rei.rsComm, gql}) {
                    bytes = row[0];
                }

                const auto& attrs = _instance_configs.at(_instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.total_size_in_bytes(), bytes.empty() ? "0" : bytes});
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }

    auto logical_quotas_recalculate_totals(const std::string& _instance_name,
                                           const instance_configuration_map& _instance_configs,
                                           std::list<boost::any>& _rule_arguments,
                                           irods::callback& _effect_handler) -> irods::error
    {
        auto functions = {logical_quotas_count_total_number_of_data_objects,
                          logical_quotas_count_total_size_in_bytes};

        for (auto&& f : functions) {
            const auto error = f(_instance_name, _instance_configs, _rule_arguments, _effect_handler);

            if (!error.ok()) {
                return error;
            }
        }

        return SUCCESS();
    }

    auto logical_quotas_set_maximum_number_of_data_objects(const std::string& _instance_name,
                                                           const instance_configuration_map& _instance_configs,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto args_iter = std::begin(_rule_arguments);
            const auto path = boost::any_cast<std::string>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto username = get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto max_objects = std::to_string(boost::any_cast<size_type>(*++args_iter));
                const auto& attrs = _instance_configs.at(_instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.maximum_number_of_data_objects(), max_objects});
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }

    auto logical_quotas_set_maximum_size_in_bytes(const std::string& _instance_name,
                                                  const instance_configuration_map& _instance_configs,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto args_iter = std::begin(_rule_arguments);
            const auto path = boost::any_cast<std::string>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto username = get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto max_bytes = std::to_string(boost::any_cast<size_type>(*++args_iter));
                const auto& attrs = _instance_configs.at(_instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.maximum_size_in_bytes(), max_bytes});
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }

    auto logical_quotas_unset_maximum_number_of_data_objects(const std::string& _instance_name,
                                                             const instance_configuration_map& _instance_configs,
                                                             std::list<boost::any>& _rule_arguments,
                                                             irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
            return std::vector<const std::string*>{&_attrs.maximum_number_of_data_objects()};
        });
    }

    auto logical_quotas_unset_maximum_size_in_bytes(const std::string& _instance_name,
                                                    const instance_configuration_map& _instance_configs,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
            return std::vector<const std::string*>{&_attrs.maximum_size_in_bytes()};
        });
    }

    auto logical_quotas_unset_total_number_of_data_objects(const std::string& _instance_name,
                                                           const instance_configuration_map& _instance_configs,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
            return std::vector<const std::string*>{&_attrs.total_number_of_data_objects()};
        });
    }

    auto logical_quotas_unset_total_size_in_bytes(const std::string& _instance_name,
                                                  const instance_configuration_map& _instance_configs,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
            return std::vector<const std::string*>{&_attrs.total_size_in_bytes()};
        });
    }

    auto pep_api_data_obj_copy_pre(const std::string& _instance_name,
                                   const instance_configuration_map& _instance_configs,
                                   std::list<boost::any>& _rule_arguments,
                                   irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            const auto& instance_config = _instance_configs.at(_instance_name);
            auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_config.attributes();

            for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](auto& _collection, const auto& _info) {
                const auto status = fs::server::status(conn, input->srcDataObjInp.objPath);

                if (fs::server::is_data_object(status)) {
                    throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
                    throw_if_maximum_size_in_bytes_violation(attrs, _info, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                }
                else if (fs::server::is_collection(status)) {
                    const auto result = compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                    throw_if_maximum_number_of_data_objects_violation(attrs, _info, std::get<0>(result));
                    throw_if_maximum_size_in_bytes_violation(attrs, _info, std::get<1>(result));
                }
                else {
                    throw logical_quotas_error{"Logical Quotas Policy: Invalid object type", SYS_INTERNAL_ERR};
                }
            });
        }
        catch (const logical_quotas_error& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_copy_post(const std::string& _instance_name,
                                    const instance_configuration_map& _instance_configs,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();

            for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                const auto status = fs::server::status(conn, input->srcDataObjInp.objPath);

                if (fs::server::is_data_object(status)) {
                    update_data_object_count_and_size(conn, attrs, _collection, _info, 1, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                }
                else if (fs::server::is_collection(status)) {
                    const auto result = compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                    update_data_object_count_and_size(conn, attrs, _collection, _info, std::get<0>(result), std::get<1>(result));
                }
                else {
                    throw logical_quotas_error{"Logical Quotas Policy: Invalid object type", SYS_INTERNAL_ERR};
                }
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    bool pep_api_data_obj_open::increment_object_count_ = false;

    auto pep_api_data_obj_open::pre(const std::string& _instance_name,
                                    const instance_configuration_map& _instance_configs,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler) -> irods::error
    {
        try {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& instance_config = _instance_configs.at(_instance_name);
            const auto& attrs = instance_config.attributes();

            if (!fs::server::exists(*rei.rsComm, input->objPath)) {
                increment_object_count_ = true;

                for_each_monitored_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
                    throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
                });
            }
        }
        catch (const logical_quotas_error& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_open::post(const std::string& _instance_name,
                                     const instance_configuration_map& _instance_configs,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();

            if (increment_object_count_) {
                for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                    update_data_object_count_and_size(conn, attrs, _collection, _info, 1, 0);
                });
            }
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    size_type pep_api_data_obj_put::size_diff_ = 0;
    bool pep_api_data_obj_put::forced_overwrite_ = false;

    auto pep_api_data_obj_put::pre(const std::string& _instance_name,
                                   const instance_configuration_map& _instance_configs,
                                   std::list<boost::any>& _rule_arguments,
                                   irods::callback& _effect_handler) -> irods::error
    {
        try {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& instance_config = _instance_configs.at(_instance_name);
            const auto& attrs = instance_config.attributes();

            if (fs::server::exists(*rei.rsComm, input->objPath)) {
                forced_overwrite_ = true;
                const size_type existing_size = fs::server::data_object_size(conn, input->objPath);
                size_diff_ = static_cast<size_type>(input->dataSize) - existing_size;

                for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, auto& _info) {
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
            log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_put::post(const std::string& _instance_name,
                                    const instance_configuration_map& _instance_configs,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();

            if (forced_overwrite_) {
                for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                    update_data_object_count_and_size(conn, attrs, _collection, _info, 0, size_diff_);
                });
            }
            else {
                for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                    update_data_object_count_and_size(conn, attrs, _collection, _info, 1, input->dataSize);
                });
            }
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_rename_pre(const std::string& _instance_name,
                                     const instance_configuration_map& _instance_configs,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            const auto& instance_config = _instance_configs.at(_instance_name);
            auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_config.attributes();

            {
                auto src_path = get_monitored_parent_collection(conn, attrs, input->srcDataObjInp.objPath);
                auto dst_path = get_monitored_parent_collection(conn, attrs, input->destDataObjInp.objPath);

                // Return if any of the following is true:
                // - The paths are boost::none.
                // - The paths are not boost::none and are equal.
                // - The destination path is a child of the source path.
                if (src_path == dst_path || (src_path && dst_path && *src_path < *dst_path)) {
                    return CODE(RULE_ENGINE_CONTINUE);
                }
            }

            for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                const auto status = fs::server::status(conn, input->srcDataObjInp.objPath);

                if (fs::server::is_data_object(status)) {
                    throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
                    throw_if_maximum_size_in_bytes_violation(attrs, _info, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                }
                else if (fs::server::is_collection(status)) {
                    const auto result = compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                    throw_if_maximum_number_of_data_objects_violation(attrs, _info, std::get<0>(result));
                    throw_if_maximum_size_in_bytes_violation(attrs, _info, std::get<1>(result));
                }
                else {
                    throw logical_quotas_error{"Logical Quotas Policy: Invalid object type", SYS_INTERNAL_ERR};
                }
            });
        }
        catch (const logical_quotas_error& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_rename_post(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();

            {
                auto src_path = get_monitored_parent_collection(conn, attrs, input->srcDataObjInp.objPath);
                auto dst_path = get_monitored_parent_collection(conn, attrs, input->destDataObjInp.objPath);

                // Return if any of the following is true:
                // - The paths are boost::none.
                // - The paths are not boost::none and are equal.
                // - The destination path is a child of the source path.
                if (src_path == dst_path || (src_path && dst_path && *src_path < *dst_path)) {
                    return CODE(RULE_ENGINE_CONTINUE);
                }
            }

            size_type objects = 0;
            size_type bytes = 0;

            const auto status = fs::server::status(conn, input->destDataObjInp.objPath);
            
            if (fs::server::is_data_object(status)) {
                objects = 1;
                bytes = fs::server::data_object_size(conn, input->destDataObjInp.objPath);
            }
            else if (fs::server::is_collection(status)) {
                std::tie(objects, bytes) = compute_data_object_count_and_size(conn, input->destDataObjInp.objPath);
            }
            else {
                throw logical_quotas_error{"Logical Quotas Policy: Invalid object type", SYS_INTERNAL_ERR};
            }

            for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, objects, bytes);
            });

            for_each_monitored_collection(conn, attrs, input->srcDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, objects, bytes);
            });
        }
        catch (const logical_quotas_error& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    size_type pep_api_data_obj_unlink::size_in_bytes_ = 0;

    auto pep_api_data_obj_unlink::pre(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();
            auto collection = get_monitored_parent_collection(conn, attrs, input->objPath);
            
            if (collection) {
                size_in_bytes_ = fs::server::data_object_size(conn, input->objPath);
            }
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_unlink::post(const std::string& _instance_name,
                                       const instance_configuration_map& _instance_configs,
                                       std::list<boost::any>& _rule_arguments,
                                       irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();

            for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, -1, -size_in_bytes_);
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_write::pre(const std::string& _instance_name,
                                     const instance_configuration_map& _instance_configs,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            const auto& instance_config = _instance_configs.at(_instance_name);
            auto* input = get_pointer<openedDataObjInp_t>(_rule_arguments);
            auto* bbuf = get_pointer<bytesBuf_t>(_rule_arguments, 3);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_config.attributes();
            const auto* path = irods::get_l1desc(input->l1descInx).dataObjInfo->objPath; 

            for_each_monitored_collection(conn, attrs, path, [&conn, &attrs, bbuf](const auto&, const auto& _info) {
                throw_if_maximum_size_in_bytes_violation(attrs, _info, bbuf->len);
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_write::post(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<openedDataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();
            const auto& l1desc = irods::get_l1desc(input->l1descInx);
            const auto* path = l1desc.dataObjInfo->objPath;

            for_each_monitored_collection(conn, attrs, path, [&conn, &attrs, &l1desc](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, 0, l1desc.bytesWritten);
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_mod_avu_metadata_pre(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<modAVUMetadataInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();

            const auto is_rodsadmin = (conn.clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH);
            const auto is_modification = [input] {
                const auto ops = {"set", "add", "rm"};
                return std::any_of(std::begin(ops), std::end(ops), [input](const std::string& _op) {
                    return _op == input->arg0;
                });
            }();

            if (!is_rodsadmin && is_modification) {
                const auto keys = {
                    attrs.maximum_number_of_data_objects(),
                    attrs.maximum_size_in_bytes(),
                    attrs.total_number_of_data_objects(),
                    attrs.total_size_in_bytes()
                };

                if (std::any_of(std::begin(keys), std::end(keys), [input](const auto& _key) { return _key == input->arg3; })) {
                    return ERROR(SYS_INVALID_INPUT_PARAM, "Logical Quotas Policy: User not allowed to modify administrative metadata");
                }
            }
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    size_type pep_api_rm_coll::data_objects_ = 0;
    size_type pep_api_rm_coll::size_in_bytes_ = 0;

    auto pep_api_rm_coll::pre(const std::string& _instance_name,
                              const instance_configuration_map& _instance_configs,
                              std::list<boost::any>& _rule_arguments,
                              irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<collInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();
            auto collection = get_monitored_parent_collection(conn, attrs, input->collName);
            
            if (collection) {
                std::tie(data_objects_, size_in_bytes_) = compute_data_object_count_and_size(conn, input->collName);
            }
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_rm_coll::post(const std::string& _instance_name,
                               const instance_configuration_map& _instance_configs,
                               std::list<boost::any>& _rule_arguments,
                               irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = get_pointer<collInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = _instance_configs.at(_instance_name).attributes();

            for_each_monitored_collection(conn, attrs, input->collName, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, -data_objects_, -size_in_bytes_);
            });
        }
        catch (const std::exception& e)
        {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

} // namespace handler
} // namespace irods

