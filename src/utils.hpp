#ifndef IRODS_UTILS_HPP
#define IRODS_UTILS_HPP

#include "attributes.hpp"
#include "switch_user_error.hpp"

#include <irods/irods_re_structs.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_logger.hpp>
#include <irods/filesystem.hpp>
#include <irods/irods_error.hpp>
#include <irods/rodsErrorTable.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#include <boost/any.hpp>

#include <iterator>

namespace irods
{
    class callback;
} // namespace irods

namespace irods::util
{
    using quotas_info_type = std::unordered_map<std::string, std::int64_t>;

    auto get_rei(irods::callback& _effect_handler) -> ruleExecInfo_t&;

    template <typename Function>
    auto switch_user(ruleExecInfo_t& _rei, std::string_view _username, Function _func) -> void
    {
        auto& user = _rei.rsComm->clientUser;

        if (user.authInfo.authFlag < LOCAL_PRIV_USER_AUTH) {
            throw switch_user_error{"Logical Quotas Policy: Insufficient privileges", SYS_NO_API_PRIV};
        }

        const std::string old_username = user.userName;

        rstrcpy(user.userName, _username.data(), NAME_LEN);

        irods::at_scope_exit at_scope_exit{[&user, &old_username] {
            rstrcpy(user.userName, old_username.c_str(), MAX_NAME_LEN);
        }};

        _func();
    }

    auto log_exception_message(const char* _msg, irods::callback& _effect_handler) -> void;

    auto get_collection_id(rsComm_t& _conn, irods::experimental::filesystem::path _p) -> std::optional<std::string>;

    auto get_collection_user_id(rsComm_t& _conn, const std::string& _collection_id) -> std::optional<std::string>;

    auto get_collection_username(rsComm_t& _conn, irods::experimental::filesystem::path _p) -> std::optional<std::string>;

    template <typename T>
    auto get_input_object_ptr(std::list<boost::any>& _rule_arguments, int _index = 0) -> T*
    {
        return boost::any_cast<T*>(*std::next(std::begin(_rule_arguments), _index + 2));
    }

    auto get_tracked_collection_info(rsComm_t& _conn, const attributes& _attrs, const irods::experimental::filesystem::path& _p) -> quotas_info_type;

    auto throw_if_maximum_number_of_data_objects_violation(const attributes& _attrs, const quotas_info_type& _tracking_info, std::int64_t _delta) -> void;

    auto throw_if_maximum_size_in_bytes_violation(const attributes& _attrs, const quotas_info_type& _tracking_info, std::int64_t _delta) -> void;

    auto is_tracked_collection(rsComm_t& _conn, const attributes& _attrs, const irods::experimental::filesystem::path& _p) -> bool;

    auto get_tracked_parent_collection(rsComm_t& _conn,
                                       const attributes& _attrs,
                                       irods::experimental::filesystem::path _p) -> std::optional<irods::experimental::filesystem::path>;

    auto compute_data_object_count_and_size(rsComm_t& _conn, irods::experimental::filesystem::path _p) -> std::tuple<std::int64_t, std::int64_t>;

    auto update_data_object_count_and_size(rsComm_t& _conn,
                                           const attributes& _attrs,
                                           const irods::experimental::filesystem::path& _collection,
                                           const quotas_info_type& _info,
                                           std::int64_t _data_objects_delta,
                                           std::int64_t _size_in_bytes_delta) -> void;

    template <typename Function>
    auto for_each_tracked_collection(rsComm_t& _conn,
                                     const attributes& _attrs,
                                     irods::experimental::filesystem::path _collection,
                                     Function _func) -> void
    {
        for (auto tracked_collection = util::get_tracked_parent_collection(_conn, _attrs, _collection);
             tracked_collection;
             tracked_collection = util::get_tracked_parent_collection(_conn, _attrs, tracked_collection->parent_path()))
        {
            auto tracked_info = util::get_tracked_collection_info(_conn, _attrs, *tracked_collection);
            _func(*tracked_collection, tracked_info);
        }
    }

     auto unset_metadata_impl(const std::string& _instance_name,
                              std::list<boost::any>& _rule_arguments,
                              irods::callback& _effect_handler,
                              const irods::experimental::filesystem::metadata& _metadata) -> irods::error;
} // namespace irods::util

#endif // IRODS_UTILS_HPP
