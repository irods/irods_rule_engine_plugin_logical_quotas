#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_get_full_path_for_config_file.hpp>
#include <irods/irods_get_l1desc.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_query.hpp>
#include <irods/irods_logger.hpp>
#include <irods/filesystem.hpp>
#include <irods/irods_state_table.h>
#include <irods/modAVUMetadata.h>
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
#include <fmt/format.h>

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
    using tracking_info_type = std::unordered_map<std::string, std::int64_t>;
    // clang-format on

    struct logical_quotas_violation_error final
        : public std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    class switch_user_error final
        : public std::runtime_error
    {
    public:
        switch_user_error(const char* _msg, int _error_code)
            : std::runtime_error{_msg}
            , error_code_{_error_code}
        {
        }

        int error_code() { return error_code_; }

    private:
        int error_code_;
    };

    class attributes final
    {
    public:
        explicit attributes(const std::string& _namespace,
                            const std::string& _maximum_number_of_data_objects,
                            const std::string& _maximum_size_in_bytes,
                            const std::string& _current_number_of_data_objects,
                            const std::string& _current_size_in_bytes)
            : maximum_number_of_data_objects_{fmt::format("{}::{}", _namespace, _maximum_number_of_data_objects)}
            , maximum_size_in_bytes_{fmt::format("{}::{}", _namespace, _maximum_size_in_bytes)}
            , current_number_of_data_objects_{fmt::format("{}::{}", _namespace, _current_number_of_data_objects)}
            , current_size_in_bytes_{fmt::format("{}::{}", _namespace, _current_size_in_bytes)}
        {
        }

        // clang-format off
        const std::string& maximum_number_of_data_objects() const { return maximum_number_of_data_objects_; }
        const std::string& maximum_size_in_bytes() const          { return maximum_size_in_bytes_; }
        const std::string& current_number_of_data_objects() const { return current_number_of_data_objects_; }
        const std::string& current_size_in_bytes() const          { return current_size_in_bytes_; }
        // clang-format on

    private:
        std::string maximum_number_of_data_objects_;
        std::string maximum_size_in_bytes_;
        std::string current_number_of_data_objects_;
        std::string current_size_in_bytes_;
    }; // class attributes

    class instance_config final
    {
    public:
        instance_config(attributes _attrs, bool _enforce)
            : attrs_{std::move(_attrs)}
            , enforce_{_enforce}
        {
        }

        const attributes& attributes() const
        {
            return attrs_;
        }

        bool enforce_quotas() const
        {
            return enforce_;
        }

    private:
        class attributes attrs_;
        bool enforce_;
    }; // class instance_config

    std::unordered_map<std::string, instance_config> instance_configs;

    // This is a "sorted" list of the supported PEPs.
    // This will allow us to do binary search on the list for lookups.
    constexpr std::array<std::string_view, 21> peps{
        "logical_quotas_set_maximum_number_of_data_objects",
        "logical_quotas_set_maximum_size_in_bytes",
        "logical_quotas_stop_tracking_collection",
        "logical_quotas_track_collection",
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

    namespace util
    {
        ruleExecInfo_t& get_rei(irods::callback& _effect_handler)
        {
            ruleExecInfo_t* rei{};

            if (const auto result = _effect_handler("unsafe_ms_ctx", &rei); !result.ok()) {
                THROW(result.code(), "failed to get rule execution info");
            }

            return *rei;
        }

        template <typename Function>
        void switch_user(ruleExecInfo_t& _rei, std::string_view _username, Function _func)
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

        template <typename T>
        T* get_input_object_ptr(std::list<boost::any>& _rule_arguments, int _index = 0)
        {
            return boost::any_cast<T*>(*std::next(std::begin(_rule_arguments), _index + 2));
        }

        tracking_info_type get_tracked_collection_info(rsComm_t& _conn, const attributes& _attrs, const fs::path& _p)
        {
            tracking_info_type info;

            const auto gql = fmt::format("select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = '{}'", _p.c_str());

            for (auto&& row : irods::query{&_conn, gql}) {
                // clang-format off
                if      (_attrs.maximum_number_of_data_objects() == row[0]) { info[_attrs.maximum_number_of_data_objects()] = std::stoull(row[1]); }
                else if (_attrs.maximum_size_in_bytes() == row[0])          { info[_attrs.maximum_size_in_bytes()] = std::stoull(row[1]); }
                else if (_attrs.current_number_of_data_objects() == row[0]) { info[_attrs.current_number_of_data_objects()] = std::stoull(row[1]); }
                else if (_attrs.current_size_in_bytes() == row[0])          { info[_attrs.current_size_in_bytes()] = std::stoull(row[1]); }
                // clang-format on
            }

            return info;
        }

        void throw_if_maximum_count_violation(const attributes& _attrs, const tracking_info_type& _tracking_info, std::int64_t _delta)
        {
            if (_tracking_info.at(_attrs.current_number_of_data_objects()) + _delta > _tracking_info.at(_attrs.maximum_number_of_data_objects())) {
                throw logical_quotas_violation_error{"Policy Violation: Adding object exceeds maximum number of objects limit"};
            }
        }

        void throw_if_maximum_size_in_bytes_violation(const attributes& _attrs, const tracking_info_type& _tracking_info, std::int64_t _delta)
        {
            if (_tracking_info.at(_attrs.current_size_in_bytes()) + _delta > _tracking_info.at(_attrs.maximum_size_in_bytes())) {
                throw logical_quotas_violation_error{"Policy Violation: Adding object exceeds maximum data size in bytes limit"};
            }
        }

        bool is_tracked_collection(rsComm_t& _conn, const attributes& _attrs, const fs::path& _p)
        {
            const auto gql = fmt::format("select META_COLL_ATTR_NAME where COLL_NAME = '{}' and META_COLL_ATTR_NAME = '{}'",
                                         _p.c_str(),
                                         _attrs.maximum_number_of_data_objects());

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
            const auto new_object_count = std::to_string(_info.at(_attrs.current_number_of_data_objects()) + _data_objects_delta);
            fs::server::set_metadata(_conn, _collection, {_attrs.current_number_of_data_objects(), new_object_count});

            const auto new_size_in_bytes = std::to_string(_info.at(_attrs.current_size_in_bytes()) + _size_in_bytes_delta);
            fs::server::set_metadata(_conn, _collection, {_attrs.current_size_in_bytes(), new_size_in_bytes});
        }

        template <typename Function>
        void for_each_tracked_collection(rsComm_t& _conn, const attributes& _attrs, fs::path _collection, Function _func)
        {
            for (auto tracked_collection = util::get_tracked_parent_collection(_conn, _attrs, _collection);
                 tracked_collection;
                 tracked_collection = util::get_tracked_parent_collection(_conn, _attrs, tracked_collection->parent_path()))
            {
                auto tracked_info = util::get_tracked_collection_info(_conn, _attrs, *tracked_collection);
                _func(*tracked_collection, tracked_info);
            }
        }
    } // namespace util

    //
    // PEP Handlers
    //

    namespace handler
    {
        irods::error logical_quotas_track_collection(const std::string& _instance_name,
                                                     std::list<boost::any>& _rule_arguments,
                                                     irods::callback& _effect_handler)
        {
            try
            {
                auto args_iter = std::begin(_rule_arguments);
                const auto path = boost::any_cast<std::string>(*args_iter);

                auto& rei = util::get_rei(_effect_handler);
                auto username = util::get_collection_username(*rei.rsComm, path);

                if (!username) {
                    // TODO What should happen here?
                }

                util::switch_user(rei, *username, [&] {
                    std::string objects;
                    std::string bytes;

                    const auto gql = fmt::format("select count(DATA_NAME), sum(DATA_SIZE) where COLL_NAME = '{0}' || like '{0}/%'", path);

                    for (auto&& row : irods::query{rei.rsComm, gql}) {
                        objects = row[0];
                        bytes = row[1];
                    }

                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    fs::server::set_metadata(*rei.rsComm, path, {attrs.current_number_of_data_objects(),  objects.empty() ? "0" : objects});
                    fs::server::set_metadata(*rei.rsComm, path, {attrs.current_size_in_bytes(), bytes.empty() ? "0" : bytes});
                });
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return SUCCESS();
        }
        
        irods::error logical_quotas_stop_tracking_collection(const std::string& _instance_name,
                                                             std::list<boost::any>& _rule_arguments,
                                                             irods::callback& _effect_handler)
        {
            try
            {
                auto args_iter = std::begin(_rule_arguments);
                const auto path = boost::any_cast<std::string>(*args_iter);

                auto& rei = util::get_rei(_effect_handler);
                auto& conn = *rei.rsComm;
                auto username = util::get_collection_username(conn, path);

                if (!username) {
                    throw std::runtime_error{fmt::format("Logical Quotas Policy: No owner found for path [{}]", path)};
                }

                util::switch_user(rei, *username, [&] {
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    if (!util::is_tracked_collection(conn, attrs, path)) {
                        throw std::runtime_error{fmt::format("Logical Quotas Policy: [{}] is not a tracked collection", path)};
                    }

                    const auto info = util::get_tracked_collection_info(conn, attrs, path);

                    try {
                        // clang-format off
                        fs::server::remove_metadata(conn, path, {attrs.maximum_number_of_data_objects(),  std::to_string(info.at(attrs.maximum_number_of_data_objects()))});
                        fs::server::remove_metadata(conn, path, {attrs.maximum_size_in_bytes(), std::to_string(info.at(attrs.maximum_size_in_bytes()))});
                        fs::server::remove_metadata(conn, path, {attrs.current_number_of_data_objects(),  std::to_string(info.at(attrs.current_number_of_data_objects()))});
                        fs::server::remove_metadata(conn, path, {attrs.current_size_in_bytes(), std::to_string(info.at(attrs.current_size_in_bytes()))});
                        // clang-format on
                    }
                    catch (const std::out_of_range& e) {
                        log::rule_engine::error(e.what());
                        throw std::runtime_error{"Logical Quotas Policy: Missing key"};
                    }
                });
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return SUCCESS();
        }
        
        irods::error logical_quotas_set_maximum_number_of_data_objects(const std::string& _instance_name,
                                                                       std::list<boost::any>& _rule_arguments,
                                                                       irods::callback& _effect_handler)
        {
            try
            {
                auto args_iter = std::begin(_rule_arguments);
                const auto path = boost::any_cast<std::string>(*args_iter);

                auto& rei = util::get_rei(_effect_handler);
                auto username = util::get_collection_username(*rei.rsComm, path);

                if (!username) {
                    // TODO What should happen here?
                }

                util::switch_user(rei, *username, [&] {
                    const auto max_objects = std::to_string(boost::any_cast<std::int64_t>(*++args_iter));
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    fs::server::set_metadata(*rei.rsComm, path, {attrs.maximum_number_of_data_objects(), max_objects});
                });
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return SUCCESS();
        }
        
        irods::error logical_quotas_set_maximum_size_in_bytes(const std::string& _instance_name,
                                                              std::list<boost::any>& _rule_arguments,
                                                              irods::callback& _effect_handler)
        {
            try
            {
                auto args_iter = std::begin(_rule_arguments);
                const auto path = boost::any_cast<std::string>(*args_iter);

                auto& rei = util::get_rei(_effect_handler);
                auto username = util::get_collection_username(*rei.rsComm, path);

                if (!username) {
                    // TODO What should happen here?
                }

                util::switch_user(rei, *username, [&] {
                    const auto max_bytes = std::to_string(boost::any_cast<std::int64_t>(*++args_iter));
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    fs::server::set_metadata(*rei.rsComm, path, {attrs.maximum_size_in_bytes(), max_bytes});
                });
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return SUCCESS();
        }
        
        irods::error pep_api_data_obj_copy_pre(const std::string& _instance_name,
                                               std::list<boost::any>& _rule_arguments,
                                               irods::callback& _effect_handler)
        {
            try
            {
                const auto& instance_config = instance_configs.at(_instance_name);

                if (!instance_config.enforce_quotas()) {
                    return CODE(RULE_ENGINE_CONTINUE);
                }

                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
                auto& rei = util::get_rei(_effect_handler);
                auto& conn = *rei.rsComm;
                const auto& attrs = instance_config.attributes();

                util::for_each_tracked_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](auto&, const auto& _info) {
                    if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath); fs::server::is_data_object(status)) {
                        util::throw_if_maximum_count_violation(attrs, _info, 1);
                        util::throw_if_maximum_size_in_bytes_violation(attrs, _info, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                    }
                    else if (fs::server::is_collection(status)) {
                        const auto [objects, bytes] = util::compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                        util::throw_if_maximum_count_violation(attrs, _info, objects);
                        util::throw_if_maximum_size_in_bytes_violation(attrs, _info, bytes);
                    }
                    else {
                        throw logical_quotas_violation_error{"Logical Quotas Policy: Invalid object type"};
                    }
                });
            }
            catch (const logical_quotas_violation_error& e) {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_copy_post(const std::string& _instance_name,
                                                std::list<boost::any>& _rule_arguments,
                                                irods::callback& _effect_handler)
        {
            try
            {
                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
                auto& rei = util::get_rei(_effect_handler);
                auto& conn = *rei.rsComm;
                const auto& attrs = instance_configs.at(_instance_name).attributes();

                util::for_each_tracked_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                    if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath); fs::server::is_data_object(status)) {
                        util::update_data_object_count_and_size(conn, attrs, _collection, _info, 1, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                    }
                    else if (fs::server::is_collection(status)) {
                        const auto [objects, bytes] = util::compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                        util::update_data_object_count_and_size(conn, attrs, _collection, _info, objects, bytes);
                    }
                    else {
                        throw logical_quotas_violation_error{"Logical Quotas Policy: Invalid object type"};
                    }
                });
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        class pep_api_data_obj_open final
        {
        public:
            static irods::error pre(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler)
            {
                try {
                    auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& instance_config = instance_configs.at(_instance_name);
                    const auto& attrs = instance_config.attributes();

                    if (!fs::server::exists(*rei.rsComm, input->objPath)) {
                        increment_object_count_ = true;

                        if (instance_config.enforce_quotas()) {
                            util::for_each_tracked_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
                                util::throw_if_maximum_count_violation(attrs, _info, 1);
                            });
                        }
                    }
                }
                catch (const logical_quotas_violation_error& e) {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
                }
                catch (const std::exception& e) {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

            static irods::error post(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    if (increment_object_count_) {
                        util::for_each_tracked_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                            util::update_data_object_count_and_size(conn, attrs, _collection, _info, 1, 0);
                        });
                    }
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

        private:
            inline static bool increment_object_count_ = false;
        }; // class pep_api_data_obj_open

        class pep_api_data_obj_put final
        {
        public:
            static irods::error pre(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler)
            {
                try {
                    auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& instance_config = instance_configs.at(_instance_name);
                    const auto& attrs = instance_config.attributes();

                    if (fs::server::exists(*rei.rsComm, input->objPath)) {
                        forced_overwrite_ = true;
                        size_diff_ = fs::server::data_object_size(conn, input->objPath) - input->dataSize;

                        if (instance_config.enforce_quotas()) {
                            util::for_each_tracked_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, auto& _info) {
                                util::throw_if_maximum_size_in_bytes_violation(attrs, _info, size_diff_);
                            });
                        }
                    }
                    else if (instance_config.enforce_quotas()) {
                        util::for_each_tracked_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
                            util::throw_if_maximum_count_violation(attrs, _info, 1);
                            util::throw_if_maximum_size_in_bytes_violation(attrs, _info, input->dataSize);
                        });
                    }
                }
                catch (const logical_quotas_violation_error& e) {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
                }
                catch (const std::exception& e) {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

            static irods::error post(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    if (forced_overwrite_) {
                        util::for_each_tracked_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                            util::update_data_object_count_and_size(conn, attrs, _collection, _info, 0, size_diff_);
                        });
                    }
                    else {
                        util::for_each_tracked_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                            util::update_data_object_count_and_size(conn, attrs, _collection, _info, 1, input->dataSize);
                        });
                    }
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

        private:
            inline static std::int64_t size_diff_ = 0;
            inline static bool forced_overwrite_ = false;
        }; // class pep_api_data_obj_put

        irods::error pep_api_data_obj_rename_pre(const std::string& _instance_name,
                                                 std::list<boost::any>& _rule_arguments,
                                                 irods::callback& _effect_handler)
        {
            try
            {
                const auto& instance_config = instance_configs.at(_instance_name);

                if (!instance_config.enforce_quotas()) {
                    return CODE(RULE_ENGINE_CONTINUE);
                }

                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
                auto& rei = util::get_rei(_effect_handler);
                auto& conn = *rei.rsComm;
                const auto& attrs = instance_config.attributes();

                {
                    auto src_path = util::get_tracked_parent_collection(conn, attrs, input->srcDataObjInp.objPath);
                    auto dst_path = util::get_tracked_parent_collection(conn, attrs, input->destDataObjInp.objPath);

                    // Return if either of the following is true:
                    // - The paths are std::nullopt.
                    // - The paths are not std::nullopt and are equal.
                    // - The destination path is a child of the source path.
                    if (src_path == dst_path || (src_path && dst_path && *src_path < *dst_path)) {
                        return CODE(RULE_ENGINE_CONTINUE);
                    }
                }

                util::for_each_tracked_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                    if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath); fs::server::is_data_object(status)) {
                        util::throw_if_maximum_count_violation(attrs, _info, 1);
                        util::throw_if_maximum_size_in_bytes_violation(attrs, _info, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                    }
                    else if (fs::server::is_collection(status)) {
                        const auto [objects, bytes] = util::compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                        util::throw_if_maximum_count_violation(attrs, _info, objects);
                        util::throw_if_maximum_size_in_bytes_violation(attrs, _info, bytes);
                    }
                    else {
                        throw logical_quotas_violation_error{"Logical Quotas Policy: Invalid object type"};
                    }
                });
            }
            catch (const logical_quotas_violation_error& e) {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_data_obj_rename_post(const std::string& _instance_name,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler)
        {
            try
            {
                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
                auto& rei = util::get_rei(_effect_handler);
                auto& conn = *rei.rsComm;
                const auto& attrs = instance_configs.at(_instance_name).attributes();

                {
                    auto src_path = util::get_tracked_parent_collection(conn, attrs, input->srcDataObjInp.objPath);
                    auto dst_path = util::get_tracked_parent_collection(conn, attrs, input->destDataObjInp.objPath);

                    // Return if either of the following is true:
                    // - The paths are std::nullopt.
                    // - The paths are not std::nullopt and are equal.
                    // - The destination path is a child of the source path.
                    if (src_path == dst_path || (src_path && dst_path && *src_path < *dst_path)) {
                        return CODE(RULE_ENGINE_CONTINUE);
                    }
                }

                std::int64_t objects = 0;
                std::int64_t bytes = 0;

                if (const auto status = fs::server::status(conn, input->destDataObjInp.objPath); fs::server::is_data_object(status)) {
                    objects = 1;
                    bytes = fs::server::data_object_size(conn, input->destDataObjInp.objPath);
                }
                else if (fs::server::is_collection(status)) {
                    std::tie(objects, bytes) = util::compute_data_object_count_and_size(conn, input->destDataObjInp.objPath);
                }
                else {
                    throw logical_quotas_violation_error{"Logical Quotas Policy: Invalid object type"};
                }

                util::for_each_tracked_collection(conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                    util::update_data_object_count_and_size(conn, attrs, _collection, _info, objects, bytes);
                });

                util::for_each_tracked_collection(conn, attrs, input->srcDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                    util::update_data_object_count_and_size(conn, attrs, _collection, _info, objects, bytes);
                });
            }
            catch (const logical_quotas_violation_error& e) {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        class pep_api_data_obj_unlink final
        {
        public:
            static irods::error pre(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    if (auto tracked_collection = util::get_tracked_parent_collection(conn, attrs, input->objPath); tracked_collection) {
                        size_in_bytes_ = fs::server::data_object_size(conn, input->objPath);
                    }
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

            static irods::error post(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    util::for_each_tracked_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                        util::update_data_object_count_and_size(conn, attrs, _collection, _info, -1, -size_in_bytes_);
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
            inline static std::int64_t size_in_bytes_ = 0;
        }; // class pep_api_data_obj_unlink

        class pep_api_data_obj_write final
        {
        public:
            static irods::error pre(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler)
            {
                try
                {
                    const auto& instance_config = instance_configs.at(_instance_name);

                    if (!instance_config.enforce_quotas()) {
                        return CODE(RULE_ENGINE_CONTINUE);
                    }

                    auto* input = util::get_input_object_ptr<openedDataObjInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& attrs = instance_config.attributes();
                    const auto* path = irods::get_l1desc(input->l1descInx).dataObjInfo->objPath;

                    util::for_each_tracked_collection(conn, attrs, path, [&conn, &attrs, input](const auto&, const auto& _info) {
                        util::throw_if_maximum_size_in_bytes_violation(attrs, _info, input->bytesWritten);
                    });
                }
                catch (const std::exception& e)
                {
                    util::log_exception_message(e.what(), _effect_handler);
                    return ERROR(RE_RUNTIME_ERROR, e.what());
                }

                return CODE(RULE_ENGINE_CONTINUE);
            }

            static irods::error post(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<openedDataObjInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& attrs = instance_configs.at(_instance_name).attributes();
                    const auto* path = irods::get_l1desc(input->l1descInx).dataObjInfo->objPath;

                    util::for_each_tracked_collection(conn, attrs, path, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                        util::update_data_object_count_and_size(conn, attrs, _collection, _info, 0, input->bytesWritten);
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
        }; // class pep_api_data_obj_write

        irods::error pep_api_mod_avu_metadata_pre(const std::string& _instance_name,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler)
        {
            try
            {
                auto* input = util::get_input_object_ptr<modAVUMetadataInp_t>(_rule_arguments);
                auto& rei = util::get_rei(_effect_handler);
                auto& conn = *rei.rsComm;
                const auto& attrs = instance_configs.at(_instance_name).attributes();

                const auto is_rodsadmin = (conn.clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH);
                const auto is_modification = [input] {
                    const auto ops = {"set", "add", "rm"};
                    return std::any_of(std::begin(ops), std::end(ops), [input](std::string_view _op) {
                        return _op == input->arg0;
                    });
                }();

                if (!is_rodsadmin && is_modification) {
                    const auto keys = {
                        attrs.maximum_number_of_data_objects(),
                        attrs.maximum_size_in_bytes(),
                        attrs.current_number_of_data_objects(),
                        attrs.current_size_in_bytes()
                    };

                    if (std::any_of(std::begin(keys), std::end(keys), [input](const auto& _key) { return _key == input->arg3; })) {
                        return ERROR(SYS_INVALID_INPUT_PARAM, "Logical Quotas Policy: User not allowed to modify administrative metadata");
                    }
                }
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        class pep_api_rm_coll final
        {
        public:
            static irods::error pre(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<collInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    if (auto tracked_collection = util::get_tracked_parent_collection(conn, attrs, input->collName); tracked_collection) {
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

            static irods::error post(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler)
            {
                try
                {
                    auto* input = util::get_input_object_ptr<collInp_t>(_rule_arguments);
                    auto& rei = util::get_rei(_effect_handler);
                    auto& conn = *rei.rsComm;
                    const auto& attrs = instance_configs.at(_instance_name).attributes();

                    util::for_each_tracked_collection(conn, attrs, input->collName, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                        util::update_data_object_count_and_size(conn, attrs, _collection, _info, -data_objects_, -size_in_bytes_);
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
            inline static std::int64_t data_objects_ = 0;
            inline static std::int64_t size_in_bytes_ = 0;
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
            for (const auto& re : config.at(irods::CFG_PLUGIN_CONFIGURATION_KW).at(irods::PLUGIN_TYPE_RULE_ENGINE)) {
                if (_instance_name == re.at(irods::CFG_INSTANCE_NAME_KW).get<std::string>()) {
                    const auto& plugin_config = re.at(irods::CFG_PLUGIN_SPECIFIC_CONFIGURATION_KW);
                    const auto& attr_names = plugin_config.at("metadata_attribute_names");

                    attributes attrs{plugin_config.at("namespace").get<std::string>(),
                                     attr_names.at("maximum_number_of_data_objects").get<std::string>(),
                                     attr_names.at("maximum_size_in_bytes").get<std::string>(),
                                     attr_names.at("current_number_of_data_objects").get<std::string>(),
                                     attr_names.at("current_size_in_bytes").get<std::string>()};

                    instance_config instance_config{std::move(attrs), plugin_config.at("enforce").get<bool>()};

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
        constexpr auto next_int = [] { static int i = 0; return i++; };

        using handler_t = std::function<irods::error(const std::string&, std::list<boost::any>&, irods::callback&)>;

        static const std::map<std::string_view, handler_t> handlers{
#if 0
            {peps[0], handler::logical_quotas_set_maximum_number_of_data_objects},
            {peps[1], handler::logical_quotas_set_maximum_size_in_bytes},
            {peps[2], handler::logical_quotas_track_collection},
            {peps[3], handler::logical_quotas_stop_tracking_collection},
            {peps[4], handler::pep_api_data_obj_copy_post},
            {peps[5], handler::pep_api_data_obj_copy_pre},
            {peps[6], handler::pep_api_data_obj_open_and_stat_post},
            {peps[7], handler::pep_api_data_obj_open_and_stat_pre},
            {peps[8], handler::pep_api_data_obj_open_post},
            {peps[9], handler::pep_api_data_obj_open_pre},
            {peps[10], handler::pep_api_data_obj_put_post},
            {peps[11], handler::pep_api_data_obj_put_pre},
            {peps[12], handler::pep_api_data_obj_rename_post},
            {peps[13], handler::pep_api_data_obj_rename_pre},
            {peps[14], handler::pep_api_data_obj_unlink_post},
            {peps[15], handler::pep_api_data_obj_unlink_pre},
            {peps[16], handler::pep_api_data_obj_write_post},
            {peps[17], handler::pep_api_data_obj_write_pre},
            {peps[18], handler::pep_api_mod_avu_metadata_pre},
            {peps[19], handler::pep_api_rm_coll::post},
            {peps[20], handler::pep_api_rm_coll::pre}
#else
            {peps[next_int()], handler::logical_quotas_set_maximum_number_of_data_objects},
            {peps[next_int()], handler::logical_quotas_set_maximum_size_in_bytes},
            {peps[next_int()], handler::logical_quotas_stop_tracking_collection},
            {peps[next_int()], handler::logical_quotas_track_collection},
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
#endif
        };

        if (auto iter = handlers.find(_rule_name); std::end(handlers) != iter) {
            return (iter->second)(_instance_name, _rule_arguments, _effect_handler);
        }

        log::rule_engine::error({{"log_message", "[irods_rule_engine_plugin-logical_quotas] rule not supported in rule engine plugin"},
                                 {"rule", _rule_name}});

        return CODE(RULE_ENGINE_CONTINUE);
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
            // - logical_quotas_track_collection
            // - logical_quotas_stop_tracking_collection
            // - logical_quotas_set_maximum_number_of_data_objects
            // - logical_quotas_set_maximum_size_in_bytes

            if (const auto op = json_args.at("operation").get<std::string>(); op == "logical_quotas_track_collection") {
                std::list<boost::any> args{
                    json_args.at("collection").get<std::string>()
                };

                return handler::logical_quotas_track_collection(_instance_name, args, _effect_handler);
            }
            else if (op == "logical_quotas_stop_tracking_collection") {
                std::list<boost::any> args{
                    json_args.at("collection").get<std::string>(),
                };

                return handler::logical_quotas_stop_tracking_collection(_instance_name, args, _effect_handler);
            }
            else if (op == "logical_quotas_set_maximum_number_of_data_objects") {
                std::list<boost::any> args{
                    json_args.at("collection").get<std::string>(),
                    json_args.at("maximum_number_of_data_objects").get<std::int64_t>()
                };

                return handler::logical_quotas_set_maximum_number_of_data_objects(_instance_name, args, _effect_handler);
            }
            else if (op == "logical_quotas_set_maximum_size_in_bytes") {
                std::list<boost::any> args{
                    json_args.at("collection").get<std::string>(),
                    json_args.at("maximum_size_in_bytes").get<std::int64_t>()
                };

                return handler::logical_quotas_set_maximum_size_in_bytes(_instance_name, args, _effect_handler);
            }
            else {
                return ERROR(INVALID_OPERATION, fmt::format("Invalid operation [{}]", op));
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

