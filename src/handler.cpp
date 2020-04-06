#include "handler.hpp"

#include "logical_quotas_error.hpp"
#include "switch_user_error.hpp"

#include <irods/objDesc.hpp>
#include <sys/types.h>
#include <unistd.h>

#include <irods/irods_query.hpp>
#include <irods/irods_logger.hpp>
#include <irods/filesystem.hpp>
#include <irods/dstream.hpp>
#include <irods/transport/default_transport.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_get_l1desc.hpp>
#include <irods/modAVUMetadata.h>
#include <irods/rodsErrorTable.h>

#include <fmt/format.h>

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

    using log                    = irods::experimental::log;
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

            for (; p_iter != p_last && c_iter != c_last && *p_iter == *c_iter; ++p_iter, ++c_iter);

            return (p_iter == p_last);
        }

    private:
        const fs::path& p_;
    }; // class parent_path

    // 
    // Globals
    //
    
    file_position_map_type fpos_map;

    //
    // Function Prototypes
    //

    auto get_rei(irods::callback& _effect_handler) -> ruleExecInfo_t&;

    auto get_collection_id(rsComm_t& _conn, fs::path _p) -> std::optional<std::string>;

    auto get_collection_user_id(rsComm_t& _conn, const std::string& _collection_id) -> std::optional<std::string>;

    auto get_collection_username(rsComm_t& _conn, fs::path _p) -> std::optional<std::string>;

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
                                         fs::path _p) -> std::optional<fs::path>;

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
    auto switch_user(ruleExecInfo_t& _rei, std::string_view _username, Function _func) -> void;

    template <typename Function>
    auto for_each_monitored_collection(rsComm_t& _conn,
                                       const irods::attributes& _attrs,
                                       fs::path _collection,
                                       Function _func) -> void;

    template <typename Value, typename Map>
    auto get_attribute_value(const Map& _map, std::string_view _key) -> Value;

    auto get_instance_config(const irods::instance_configuration_map& _map,
                             std::string_view _key) -> const irods::instance_configuration&;

    auto make_unique_id(fs::path _p) -> std::string;

    auto size_on_disk(rsComm_t& _conn, fs::path _p) -> size_type;

    auto throw_if_string_cannot_be_cast_to_an_integer(const std::string& s, const std::string& error_msg) -> void;

    //
    // Function Implementations
    //

    auto get_rei(irods::callback& _effect_handler) -> ruleExecInfo_t&
    {
        ruleExecInfo_t* rei{};

        if (const auto result = _effect_handler("unsafe_ms_ctx", &rei); !result.ok()) {
            const auto error_code = static_cast<irods::logical_quotas_error::error_code_type>(result.code());
            throw irods::logical_quotas_error{"Logical Quotas Policy: Failed to get rule execution information", error_code};
        }

        return *rei;
    }

    auto get_collection_id(rsComm_t& _conn, fs::path _p) -> std::optional<std::string>
    {
        const auto gql = fmt::format("select COLL_ID where COLL_NAME = '{}'", _p.c_str());

        for (auto&& row : irods::query{&_conn, gql}) {
            return row[0];
        }

        return std::nullopt;
    }

    auto get_collection_user_id(rsComm_t& _conn, const std::string& _collection_id) -> std::optional<std::string>
    {
        const auto gql = fmt::format("select COLL_ACCESS_USER_ID where COLL_ACCESS_COLL_ID = '{}' and COLL_ACCESS_NAME = 'own'", _collection_id);

        for (auto&& row : irods::query{&_conn, gql}) {
            return row[0];
        }

        return std::nullopt;
    }

    auto get_collection_username(rsComm_t& _conn, fs::path _p) -> std::optional<std::string>
    {
        auto coll_id = get_collection_id(_conn, _p);

        if (!coll_id) {
            return std::nullopt;
        }

        auto user_id = get_collection_user_id(_conn, *coll_id);

        if (!user_id) {
            return std::nullopt;
        }

        const auto gql = fmt::format("select USER_NAME where USER_ID = '{}'", *user_id);

        for (auto&& row : irods::query{&_conn, gql}) {
            return row[0];
        }

        return std::nullopt;
    }

    auto get_monitored_collection_info(rsComm_t& _conn, const irods::attributes& _attrs, const fs::path& _p) -> quotas_info_type
    {
        quotas_info_type info;

        const auto gql = fmt::format("select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = '{}'", _p.c_str());

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
                throw irods::logical_quotas_error{"Logical Quotas Policy Violation: Adding object exceeds maximum number of objects limit",
                                                  SYS_RESC_QUOTA_EXCEEDED};
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
                throw irods::logical_quotas_error{"Logical Quotas Policy Violation: Adding object exceeds maximum data size in bytes limit",
                                                  SYS_RESC_QUOTA_EXCEEDED};
            }
        }
    }

    auto is_monitored_collection(rsComm_t& _conn, const irods::attributes& _attrs, const fs::path& _p) -> bool
    {
        const auto gql = fmt::format("select META_COLL_ATTR_NAME where COLL_NAME = '{}' and META_COLL_ATTR_NAME = '{}' || = '{}'",
                                     _p.c_str(),
                                     _attrs.total_number_of_data_objects(),
                                     _attrs.total_size_in_bytes());

        for (auto&& row : irods::query{&_conn, gql}) {
            return true;
        }

        return false;
    }

    auto get_monitored_parent_collection(rsComm_t& _conn, const irods::attributes& _attrs, fs::path _p) -> std::optional<fs::path>
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

        const auto gql = fmt::format("select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = '{0}' || like '{0}/%'", _p.c_str());

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
                             std::function<std::vector<const std::string*> (const irods::attributes& _attrs)> _func) -> irods::error
    {
        try {
            auto args_iter = std::begin(_rule_arguments);
            const auto& path = *boost::any_cast<std::string*>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            auto username = get_collection_username(conn, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
                const auto info = get_monitored_collection_info(conn, attrs, path);

                for (auto&& attribute_name : _func(attrs)) {
                    if (const auto iter = info.find(*attribute_name); iter != std::end(info)) {
                        const auto value = get_attribute_value<size_type>(info, *attribute_name);
                        fs::server::remove_metadata(conn, path, {*attribute_name,  std::to_string(value)});
                    }
                }
            });
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }

    auto log_exception_message(const char* _msg, irods::callback& _effect_handler) -> void
    {
        log::rule_engine::error(_msg);
        addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, RE_RUNTIME_ERROR, _msg);
    }

    template <typename T>
    auto get_pointer(std::list<boost::any>& _rule_arguments, int _index) -> T*
    {
        return boost::any_cast<T*>(*std::next(std::begin(_rule_arguments), _index));
    }

    template <typename Function>
    auto switch_user(ruleExecInfo_t& _rei, std::string_view _username, Function _func) -> void
    {
        auto& user = _rei.rsComm->clientUser;

        if (user.authInfo.authFlag < LOCAL_PRIV_USER_AUTH) {
            throw irods::switch_user_error{"Logical Quotas Policy: Insufficient privileges", CAT_INSUFFICIENT_PRIVILEGE_LEVEL};
        }

        const std::string old_username = user.userName;

        rstrcpy(user.userName, _username.data(), NAME_LEN);

        irods::at_scope_exit at_scope_exit{[&user, &old_username] {
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
        for (auto collection = get_monitored_parent_collection(_conn, _attrs, _collection.parent_path());
             collection;
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

    auto get_instance_config(const irods::instance_configuration_map& _map,
                             std::string_view _key) -> const irods::instance_configuration&
    {
        try {
            return _map.at(_key.data());
        }
        catch (const std::out_of_range&) {
            throw std::runtime_error{fmt::format("Logical Quotas Policy: Failed to find configuration for "
                                                 "rule engine plugin instance [{}]", _key)};
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

    auto size_on_disk(rsComm_t& _conn, fs::path _p) -> size_type
    {
        namespace io = irods::experimental::io;

        io::server::default_transport tp{_conn};
        io::idstream in{tp, _p, std::ios_base::ate};

        if (!in) {
            throw std::runtime_error{"Logical Quotas Policy: Could not open data object"};
        }

        return in.tellg();
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
} // anonymous namespace

namespace irods::handler
{
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
            return std::vector{&_attrs.total_number_of_data_objects(), &_attrs.total_size_in_bytes()};
        });
    }

    auto logical_quotas_count_total_number_of_data_objects(const std::string& _instance_name,
                                                           const instance_configuration_map& _instance_configs,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error
    {
        try {
            auto args_iter = std::begin(_rule_arguments);
            const auto& path = *boost::any_cast<std::string*>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto username = get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto gql = fmt::format("select count(DATA_NAME) where COLL_NAME = '{0}' || like '{0}/%'", path);
                std::string objects;

                for (auto&& row : irods::query{rei.rsComm, gql}) {
                    objects = row[0];
                }

                const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.total_number_of_data_objects(),  objects.empty() ? "0" : objects});
            });
        }
        catch (const std::exception& e) {
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
        try {
            auto args_iter = std::begin(_rule_arguments);
            const auto& path = *boost::any_cast<std::string*>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto username = get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto gql = fmt::format("select sum(DATA_SIZE) where COLL_NAME = '{0}' || like '{0}/%'", path);
                std::string bytes;

                for (auto&& row : irods::query{rei.rsComm, gql}) {
                    bytes = row[0];
                }

                const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.total_size_in_bytes(), bytes.empty() ? "0" : bytes});
            });
        }
        catch (const std::exception& e) {
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
            if (const auto error = f(_instance_name, _instance_configs, _rule_arguments, _effect_handler); !error.ok()) {
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
        try {
            auto args_iter = std::begin(_rule_arguments);
            const auto& path = *boost::any_cast<std::string*>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto username = get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto& max_objects = *boost::any_cast<std::string*>(*++args_iter);
                const auto msg = fmt::format("Logical Quotas Policy: Invalid value for maximum number of data objects [{}]", max_objects);
                throw_if_string_cannot_be_cast_to_an_integer(max_objects, msg);
                const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.maximum_number_of_data_objects(), max_objects});
            });
        }
        catch (const std::exception& e) {
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
        try {
            auto args_iter = std::begin(_rule_arguments);
            const auto& path = *boost::any_cast<std::string*>(*args_iter);

            auto& rei = get_rei(_effect_handler);
            auto username = get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            switch_user(rei, *username, [&] {
                const auto& max_bytes = *boost::any_cast<std::string*>(*++args_iter);
                const auto msg = fmt::format("Logical Quotas Policy: Invalid value for maximum size in bytes [{}]", max_bytes);
                throw_if_string_cannot_be_cast_to_an_integer(max_bytes, msg);
                const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.maximum_size_in_bytes(), max_bytes});
            });
        }
        catch (const std::exception& e) {
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
            return std::vector{&_attrs.maximum_number_of_data_objects()};
        });
    }

    auto logical_quotas_unset_maximum_size_in_bytes(const std::string& _instance_name,
                                                    const instance_configuration_map& _instance_configs,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
            return std::vector{&_attrs.maximum_size_in_bytes()};
        });
    }

    auto logical_quotas_unset_total_number_of_data_objects(const std::string& _instance_name,
                                                           const instance_configuration_map& _instance_configs,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
            return std::vector{&_attrs.total_number_of_data_objects()};
        });
    }

    auto logical_quotas_unset_total_size_in_bytes(const std::string& _instance_name,
                                                  const instance_configuration_map& _instance_configs,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _instance_configs, _rule_arguments, _effect_handler, [](const auto& _attrs) {
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
                                    irods::callback& _effect_handler) -> irods::error
    {
        reset(); // Not needed necessarily, but here for completeness.

        try {
            auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath); fs::server::is_data_object(status)) {
                data_objects_ = 1;
                size_in_bytes_ = size_on_disk(conn, input->srcDataObjInp.objPath);
            }
            else if (fs::server::is_collection(status)) {
                std::tie(data_objects_, size_in_bytes_) = compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
            }
            else {
                throw logical_quotas_error{"Logical Quotas Policy: Invalid object type", SYS_INTERNAL_ERR};
            }

            for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs](auto& _collection, const auto& _info) {
                throw_if_maximum_number_of_data_objects_violation(attrs, _info, data_objects_);
                throw_if_maximum_size_in_bytes_violation(attrs, _info, size_in_bytes_);
            });
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

    auto pep_api_data_obj_copy::post(const std::string& _instance_name,
                                     const instance_configuration_map& _instance_configs,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        try {
            auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, data_objects_, size_in_bytes_);
            });
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_create_pre(const std::string& _instance_name,
                                     const instance_configuration_map& _instance_configs,
                                     std::list<boost::any>& _rule_arguments,
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
            log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_create_post(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, 1, 0);
            });
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
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
                const size_type existing_size = size_on_disk(conn, input->objPath);
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
        try {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

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
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
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
                                      irods::callback& _effect_handler) -> irods::error
    {
        reset();

        try {
            auto* input = get_pointer<dataObjCopyInp_t>(_rule_arguments);

            // The parent of both paths are the same, then this operation is simply a rename of the
            // source data object or collection. In this case, there is nothing to do.
            if (fs::path{input->srcDataObjInp.objPath}.parent_path() == fs::path{input->destDataObjInp.objPath}.parent_path()) {
                return CODE(RULE_ENGINE_CONTINUE);
            }

            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath); fs::server::is_data_object(status)) {
                data_objects_ = 1;
                size_in_bytes_ = size_on_disk(conn, input->srcDataObjInp.objPath);
            }
            else if (fs::server::is_collection(status)) {
                std::tie(data_objects_, size_in_bytes_) = compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
            }
            else {
                throw logical_quotas_error{"Logical Quotas Policy: Invalid object type", SYS_INTERNAL_ERR};
            }

            const auto in_violation = [&](const auto&, const auto& _info)
            {
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
                    for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
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
            log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_rename::post(const std::string& _instance_name,
                                       const instance_configuration_map& _instance_configs,
                                       std::list<boost::any>& _rule_arguments,
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
                    for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                        update_data_object_count_and_size(conn, attrs, _collection, _info, data_objects_, size_in_bytes_);
                    });

                    for_each_monitored_collection(conn, attrs, input->srcDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                        update_data_object_count_and_size(conn, attrs, _collection, _info, -data_objects_, -size_in_bytes_);
                    });
                }
            }
            else if (src_path) {
                for_each_monitored_collection(conn, attrs, input->srcDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                    update_data_object_count_and_size(conn, attrs, _collection, _info, -data_objects_, -size_in_bytes_);
                });
            }
            else if (dst_path) {
                for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                    update_data_object_count_and_size(conn, attrs, _collection, _info, data_objects_, size_in_bytes_);
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

    auto pep_api_data_obj_unlink::reset() noexcept -> void
    {
        size_in_bytes_ = 0;
    }

    auto pep_api_data_obj_unlink::pre(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        reset();

        try {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            if (auto collection = get_monitored_parent_collection(conn, attrs, input->objPath); collection) {
                size_in_bytes_ = size_on_disk(conn, input->objPath);
            }
        }
        catch (const std::exception& e) {
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
        try {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, -1, -size_in_bytes_);
            });
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_open::reset() noexcept -> void
    {
        data_objects_ = 0;
        size_in_bytes_ = 0;
    }

    auto pep_api_data_obj_open::pre(const std::string& _instance_name,
                                    const instance_configuration_map& _instance_configs,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler) -> irods::error
    {
        reset();

        try {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            if (!fs::server::exists(*rei.rsComm, input->objPath)) {
                data_objects_ = 1;
                size_in_bytes_ = 0;

                for_each_monitored_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
                    throw_if_maximum_number_of_data_objects_violation(attrs, _info, data_objects_);
                });
            }
            // If the data object exists and the truncate flag is set,
            // then capture the size of the data object. This will be used to update
            // the metadata and reflect that the data object has been truncated.
            else if (O_TRUNC == (input->openFlags & O_TRUNC)) {
                data_objects_ = 0;
                size_in_bytes_ = size_on_disk(conn, input->objPath);
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
        try {
            auto* input = get_pointer<dataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            if (data_objects_ > 0 || size_in_bytes_ > 0) {
                for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs](const auto& _collection, const auto& _info) {
                    update_data_object_count_and_size(conn, attrs, _collection, _info, data_objects_, -size_in_bytes_);
                });
            }

            // Assumptions:
            // - All stream operations are isolated from one another due to each stream using a separate connection.
            // - No two streams will ever use the same connection to write to the same data object.
            // - The logical path is enough to uniquely identify a data object.
            // - Multi-process/server is out of scope of this implementation.

            file_position_type fpos = 0; // Handles O_TRUNC case.

            // If the client requested append and NOT truncate, then set the size
            // equal to the size of the data object.
            if (O_APPEND == (input->openFlags & (O_APPEND | O_TRUNC))) {
                fpos = size_on_disk(conn, input->objPath);
            }

            fpos_map.insert_or_assign(make_unique_id(input->objPath), fpos);
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_lseek::reset() noexcept -> void
    {
        fpos_ = 0;
    }

    auto pep_api_data_obj_lseek::pre(const std::string& _instance_name,
                                     const instance_configuration_map& _instance_configs,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        reset();

        try {
            auto* input = get_pointer<openedDataObjInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
            const auto& l1desc = irods::get_l1desc(input->l1descInx); 

            // TODO Does opening a data object with the O_TRUNC flag cause an update to the catalog?
            // This is important because for lseek, we need the real size of the data object. In this case,
            // zero should be returned.
            //
            // TODO Updating the catalog to reflect O_TRUNC is mandatory and should happen in 4.2.8.
            // 
            // For now, we can use dstream::seekg/tellg to retrieve the real size of the data object
            // as it is being written to.
            const auto size = size_on_disk(conn, l1desc.dataObjInfo->objPath);

            if (O_APPEND == (l1desc.dataObjInp->openFlags & O_APPEND)) {
                fpos_ = size;
            }
            else {
                switch (input->whence) {
                    case SEEK_SET: fpos_  = input->offset; break;
                    case SEEK_CUR: fpos_ += input->offset; break;
                    case SEEK_END: fpos_  = (size + input->offset); break; // FIXME This could overflow!
                    //case SEEK_HOLE: break;
                    //case SEEK_DATA: break;
                    default: break;
                }
            }

            if (fpos_ < 0) {
                throw std::runtime_error{"Logical Quotas Policy: File seek position cannot be less than zero"};
            }

            const std::int64_t size_diff = fpos_ - size;

            // TODO Should probably do the following only if adding NEW bytes would exceed the limit.
            // Clients are allowed to write to previously allocated space.
            for_each_monitored_collection(conn, attrs, l1desc.dataObjInfo->objPath, [&attrs, size_diff](auto&, auto& _info) {
                throw_if_maximum_size_in_bytes_violation(attrs, _info, size_diff);
            });
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

    auto pep_api_data_obj_lseek::post(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try {
            auto* input = get_pointer<openedDataObjInp_t>(_rule_arguments);
            const auto& l1desc = irods::get_l1desc(input->l1descInx); 
            fpos_map.at(make_unique_id(l1desc.dataObjInfo->objPath)) = fpos_;
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_write::reset() noexcept -> void
    {
        size_diff_ = 0; 
    }

    auto pep_api_data_obj_write::pre(const std::string& _instance_name,
                                     const instance_configuration_map& _instance_configs,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        reset();

        try {
            auto* input = get_pointer<openedDataObjInp_t>(_rule_arguments);
            auto* bbuf = get_pointer<bytesBuf_t>(_rule_arguments, 3);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
            const auto& l1desc = irods::get_l1desc(input->l1descInx);
            const auto* path = l1desc.dataObjInfo->objPath; 

            size_diff_ = fpos_map.at(make_unique_id(path)) + bbuf->len - size_on_disk(conn, path);

            // Only check for violations if new bytes are written.
            if (size_diff_ > 0) {
                for_each_monitored_collection(conn, attrs, path, [&attrs](auto&, const auto& _info) {
                    throw_if_maximum_size_in_bytes_violation(attrs, _info, size_diff_);
                });
            }
        }
        catch (const std::exception& e) {
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
        try {
            auto* input = get_pointer<openedDataObjInp_t>(_rule_arguments);
            auto* bbuf = get_pointer<bytesBuf_t>(_rule_arguments, 3);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();
            const auto& l1desc = irods::get_l1desc(input->l1descInx);
            const auto* path = l1desc.dataObjInfo->objPath;

            fpos_map.at(make_unique_id(path)) += bbuf->len;

            // Only update the totals if new bytes are written.
            if (size_diff_ > 0) {
                for_each_monitored_collection(conn, attrs, path, [&conn, &attrs](const auto& _collection, const auto& _info) {
                    update_data_object_count_and_size(conn, attrs, _collection, _info, 0, size_diff_);
                });
            }
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
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
                                     irods::callback& _effect_handler) -> irods::error
    {
        reset();

        try {
            auto* input = get_pointer<openedDataObjInp_t>(_rule_arguments);
            const auto& l1desc = irods::get_l1desc(input->l1descInx);
            path_ = l1desc.dataObjInfo->objPath;
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_close::post(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try {
            fpos_map.erase(make_unique_id(path_));
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
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
        catch (const std::exception& e) {
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
        try {
            auto* input = get_pointer<collInp_t>(_rule_arguments);
            auto& rei = get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = get_instance_config(_instance_configs, _instance_name).attributes();

            for_each_monitored_collection(conn, attrs, input->collName, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                update_data_object_count_and_size(conn, attrs, _collection, _info, -data_objects_, -size_in_bytes_);
            });
        }
        catch (const std::exception& e) {
            log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }
} // namespace irods::handler

