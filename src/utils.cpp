#include "utils.hpp"

#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_structs.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_logger.hpp>
#include <irods/filesystem.hpp>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace irods
{
    class callback;
} // namespace irods

namespace irods::util
{
    ruleExecInfo_t& get_rei(irods::callback& _effect_handler)
    {
        ruleExecInfo_t* rei{};

        if (const auto result = _effect_handler("unsafe_ms_ctx", &rei); !result.ok()) {
            THROW(result.code(), "failed to get rule execution info");
        }

        return *rei;
    }

    void log_exception_message(const char* _msg, irods::callback& _effect_handler)
    {
        log::rule_engine::error(_msg);
        addRErrorMsg(&get_rei(_effect_handler).rsComm->rError, RE_RUNTIME_ERROR, _msg);
    }

    std::optional<std::string> get_collection_id(rsComm_t& _conn, fs::path _p)
    {
        const auto gql = fmt::format("select COLL_ID where COLL_NAME = '{}'", _p.c_str());

        for (auto&& row : irods::query{&_conn, gql}) {
            return row[0];
        }

        return std::nullopt;
    }

    std::optional<std::string> get_collection_user_id(rsComm_t& _conn, const std::string& _collection_id)
    {
        const auto gql = fmt::format("select COLL_ACCESS_USER_ID where COLL_ACCESS_COLL_ID = '{}' and COLL_ACCESS_NAME = 'own'", _collection_id);

        for (auto&& row : irods::query{&_conn, gql}) {
            return row[0];
        }

        return std::nullopt;
    }

    std::optional<std::string> get_collection_username(rsComm_t& _conn, fs::path _p)
    {
        // TODO Could possibly use fs::status(...) and search the permissions for an owner.
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

    tracking_info_type get_tracked_collection_info(rsComm_t& _conn, const attributes& _attrs, const fs::path& _p)
    {
        tracking_info_type info;

        const auto gql = fmt::format("select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = '{}'", _p.c_str());

        for (auto&& row : irods::query{&_conn, gql}) {
            // clang-format off
            if      (_attrs.maximum_number_of_data_objects() == row[0]) { info[_attrs.maximum_number_of_data_objects()] = std::stoull(row[1]); }
            else if (_attrs.maximum_size_in_bytes() == row[0])          { info[_attrs.maximum_size_in_bytes()] = std::stoull(row[1]); }
            else if (_attrs.total_number_of_data_objects() == row[0]) { info[_attrs.total_number_of_data_objects()] = std::stoull(row[1]); }
            else if (_attrs.total_size_in_bytes() == row[0])          { info[_attrs.total_size_in_bytes()] = std::stoull(row[1]); }
            // clang-format on
        }

        return info;
    }

    void throw_if_maximum_number_of_data_objects_violation(const attributes& _attrs, const tracking_info_type& _tracking_info, std::int64_t _delta)
    {
        if (_tracking_info.find(_attrs.maximum_number_of_data_objects()) != std::end(_tracking_info)) {
            if (_tracking_info.at(_attrs.total_number_of_data_objects()) + _delta > _tracking_info.at(_attrs.maximum_number_of_data_objects())) {
                throw logical_quotas_error{"Policy Violation: Adding object exceeds maximum number of objects limit"};
            }
        }
    }

    void throw_if_maximum_size_in_bytes_violation(const attributes& _attrs, const tracking_info_type& _tracking_info, std::int64_t _delta)
    {
        if (_tracking_info.find(_attrs.maximum_size_in_bytes()) != std::end(_tracking_info)) {
            if (_tracking_info.at(_attrs.total_size_in_bytes()) + _delta > _tracking_info.at(_attrs.maximum_size_in_bytes())) {
                throw logical_quotas_error{"Policy Violation: Adding object exceeds maximum data size in bytes limit"};
            }
        }
    }

    bool is_tracked_collection(rsComm_t& _conn, const attributes& _attrs, const fs::path& _p)
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

    std::optional<fs::path> get_tracked_parent_collection(rsComm_t& _conn, const attributes& _attrs, fs::path _p)
    {
        for (; !_p.empty(); _p = _p.parent_path()) {
            if (is_tracked_collection(_conn, _attrs, _p)) {
                return _p;
            }
            else if ("/" == _p) {
                break;
            }
        }

        return std::nullopt;
    }

    std::tuple<std::int64_t, std::int64_t> compute_data_object_count_and_size(rsComm_t& _conn, fs::path _p)
    {
        std::int64_t objects = 0;
        std::int64_t bytes = 0;

        const auto gql = fmt::format("select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = '{0}' || like '{0}/%'", _p.c_str());

        for (auto&& row : irods::query{&_conn, gql}) {
            objects = std::stoull(row[0]);
            bytes = std::stoull(row[1]);
        }

        return {objects, bytes};
    }

    void update_data_object_count_and_size(rsComm_t& _conn,
                                           const attributes& _attrs,
                                           const fs::path& _collection,
                                           const tracking_info_type& _info,
                                           std::int64_t _data_objects_delta,
                                           std::int64_t _size_in_bytes_delta)
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

    irods::error unset_metadata_impl(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler,
                                     const fs::metadata& _metadata)
    {
        try
        {
            auto args_iter = std::begin(_rule_arguments);
            const auto path = boost::any_cast<std::string>(*args_iter);

            auto& rei = util::get_rei(_effect_handler);
            auto username = util::get_collection_username(*rei.rsComm, path);

            if (!username) {
                throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
            }

            util::switch_user(rei, *username, [&] {
                const auto max_bytes = std::to_string(boost::any_cast<std::int64_t>(*++args_iter));
                const auto& attrs = instance_configs.at(_instance_name).attributes();
                fs::server::remove_metadata(*rei.rsComm, path, _metadata);
            });
        }
        catch (const std::exception& e)
        {
            util::log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }
} // namespace irods::util

#endif // IRODS_UTILS_HPP
