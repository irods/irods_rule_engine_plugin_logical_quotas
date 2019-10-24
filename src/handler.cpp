#include "handler.hpp"

#include "instance_configuration.hpp"
#include "utils.hpp"

#include <irods/irods_query.hpp>
#include <irods/irods_logger.hpp>
#include <irods/filesystem.hpp>

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace fs   = irods::experimental::filesystem;
namespace util = irods::util;
// clang-format on

namespace
{
    using log = irods::experimental::log;

    template <typename Container, typename UnaryPredicate>
    auto for_each_function(const Container& _container, UnaryPredicate _pred) -> irods::error
    {
        for (auto&& func : _container) {
            if (const auto error = _pred(func); !error.ok()) {
                return error;
            }
        }

        return SUCCESS();
    }

    auto unset_metadata_impl(const std::string& _instance_name,
                             std::list<boost::any>& _rule_arguments,
                             irods::callback& _effect_handler,
                             std::unordered_map<std::string, irods::instance_configuration>& _instance_configs,
                             std::function<std::vector<const std::string*> (const irods::attributes& _attrs)> _func) -> irods::error
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
                const auto& attrs = _instance_configs.at(_instance_name).attributes();

                if (!util::is_monitored_collection(conn, attrs, path)) {
                    throw std::runtime_error{fmt::format("Logical Quotas Policy: [{}] is not a monitored collection", path)};
                }

                const auto info = util::get_monitored_collection_info(conn, attrs, path);

                try {
                    for (auto&& attribute_name : _func(attrs)) {
                        fs::server::remove_metadata(conn, path, {*attribute_name,  std::to_string(info.at(*attribute_name))});
                    }
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
} // anonymous namespace

namespace irods::handler
{
    auto logical_quotas_start_monitoring_collection(const std::string& _instance_name,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error
    {
        return logical_quotas_recalculate_totals(_instance_name, _rule_arguments, _effect_handler);
    }
    
    auto logical_quotas_stop_monitoring_collection(const std::string& _instance_name,
                                                   std::list<boost::any>& _rule_arguments,
                                                   irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _rule_arguments, _effect_handler, _instance_configs, [](const auto& _attrs) {
            return std::vector<const std::string*>{&_attrs.total_number_of_data_objects(),
                                                   &_attrs.total_size_in_bytes()};
        });
    }

    auto logical_quotas_count_total_number_of_data_objects(const std::string& _instance_name,
                                                                   std::list<boost::any>& _rule_arguments,
                                                                   irods::callback& _effect_handler) -> irods::error
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
                const auto gql = fmt::format("select count(DATA_NAME) where COLL_NAME = '{0}' || like '{0}/%'", path);
                std::string objects;

                for (auto&& row : irods::query{rei.rsComm, gql}) {
                    objects = row[0];
                }

                const auto& attrs = instance_configs.at(_instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.total_number_of_data_objects(),  objects.empty() ? "0" : objects});
            });
        }
        catch (const std::exception& e)
        {
            util::log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }

    auto logical_quotas_count_total_size_in_bytes(const std::string& _instance_name,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error
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
                const auto gql = fmt::format("select sum(DATA_SIZE) where COLL_NAME = '{0}' || like '{0}/%'", path);
                std::string bytes;

                for (auto&& row : irods::query{rei.rsComm, gql}) {
                    bytes = row[1];
                }

                const auto& attrs = instance_configs.at(_instance_name).attributes();
                fs::server::set_metadata(*rei.rsComm, path, {attrs.total_size_in_bytes(), bytes.empty() ? "0" : bytes});
            });
        }
        catch (const std::exception& e)
        {
            util::log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return SUCCESS();
    }

    auto logical_quotas_recalculate_totals(const std::string& _instance_name,
                                           std::list<boost::any>& _rule_arguments,
                                           irods::callback& _effect_handler) -> irods::error
    {
        auto functions = {logical_quotas_count_total_number_of_data_objects,
                          logical_quotas_count_total_size_in_bytes};

        return for_each_function(functions, [&](auto&& _func) {
            return _func(_instance_name, _rule_arguments, _effect_handler);
        });
    }

    auto logical_quotas_set_maximum_number_of_data_objects(const std::string& _instance_name,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error
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

    auto logical_quotas_set_maximum_size_in_bytes(const std::string& _instance_name,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error
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

    auto logical_quotas_unset_maximum_number_of_data_objects(const std::string& _instance_name,
                                                             std::list<boost::any>& _rule_arguments,
                                                             irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _rule_arguments, _effect_handler, _instance_configs, [](const auto& _attrs) {
            return std::vector{&_attrs.maximum_number_of_data_objects()};
        });
    }

    auto logical_quotas_unset_maximum_size_in_bytes(const std::string& _instance_name,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _rule_arguments, _effect_handler, _instance_configs, [](const auto& _attrs) {
            return std::vector{&_attrs.maximum_size_in_bytes()};
        });
    }

    auto logical_quotas_unset_total_number_of_data_objects(const std::string& _instance_name,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _rule_arguments, _effect_handler, _instance_configs, [](const auto& _attrs) {
            return std::vector{&_attrs.total_number_of_data_objects()};
        });
    }

    auto logical_quotas_unset_total_size_in_bytes(const std::string& _instance_name,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error
    {
        return unset_metadata_impl(_instance_name, _rule_arguments, _effect_handler, _instance_configs, [](const auto& _attrs) {
            return std::vector{&_attrs.total_size_in_bytes()};
        });
    }

    auto pep_api_data_obj_copy_pre(const std::string& _instance_name,
                                   std::list<boost::any>& _rule_arguments,
                                   irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            const auto& instance_config = instance_configs.at(_instance_name);
            auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_config.attributes();

            util::for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](auto& _collection, const auto& _info) {
                if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath); fs::server::is_data_object(status)) {
                    util::throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
                    util::throw_if_maximum_size_in_bytes_violation(attrs, _info, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                }
                else if (fs::server::is_collection(status)) {
                    const auto [objects, bytes] = util::compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                    util::throw_if_maximum_number_of_data_objects_violation(attrs, _info, objects);
                    util::throw_if_maximum_size_in_bytes_violation(attrs, _info, bytes);
                }
                else {
                    throw logical_quotas_error{"Logical Quotas Policy: Invalid object type"};
                }
            });
        }
        catch (const logical_quotas_error& e) {
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

    auto pep_api_data_obj_copy_post(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();

            util::for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath); fs::server::is_data_object(status)) {
                    util::update_data_object_count_and_size(conn, attrs, _collection, _info, 1, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                }
                else if (fs::server::is_collection(status)) {
                    const auto [objects, bytes] = util::compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                    util::update_data_object_count_and_size(conn, attrs, _collection, _info, objects, bytes);
                }
                else {
                    throw logical_quotas_error{"Logical Quotas Policy: Invalid object type"};
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

    auto pep_api_data_obj_open::pre(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler) -> irods::error
    {
        try {
            auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& instance_config = instance_configs.at(_instance_name);
            const auto& attrs = instance_config.attributes();

            if (!fs::server::exists(*rei.rsComm, input->objPath)) {
                increment_object_count_ = true;

                util::for_each_monitored_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
                    util::throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
                });
            }
        }
        catch (const logical_quotas_error& e) {
            util::log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e) {
            util::log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_open::post(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();

            if (increment_object_count_) {
                util::for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
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

    auto pep_api_data_obj_put::pre(const std::string& _instance_name,
                                   std::list<boost::any>& _rule_arguments,
                                   irods::callback& _effect_handler) -> irods::error
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

                util::for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, auto& _info) {
                    util::throw_if_maximum_size_in_bytes_violation(attrs, _info, size_diff_);
                });
            }
            else {
                util::for_each_monitored_collection(conn, attrs, input->objPath, [&attrs, input](auto&, auto& _info) {
                    util::throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
                    util::throw_if_maximum_size_in_bytes_violation(attrs, _info, input->dataSize);
                });
            }
        }
        catch (const logical_quotas_error& e) {
            util::log_exception_message(e.what(), _effect_handler);
            return ERROR(SYS_INVALID_INPUT_PARAM, e.what());
        }
        catch (const std::exception& e) {
            util::log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_data_obj_put::post(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();

            if (forced_overwrite_) {
                util::for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                    util::update_data_object_count_and_size(conn, attrs, _collection, _info, 0, size_diff_);
                });
            }
            else {
                util::for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
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

    auto pep_api_data_obj_rename_pre(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            const auto& instance_config = instance_configs.at(_instance_name);
            auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_config.attributes();

            {
                auto src_path = util::get_monitored_parent_collection(conn, attrs, input->srcDataObjInp.objPath);
                auto dst_path = util::get_monitored_parent_collection(conn, attrs, input->destDataObjInp.objPath);

                // Return if any of the following is true:
                // - The paths are std::nullopt.
                // - The paths are not std::nullopt and are equal.
                // - The destination path is a child of the source path.
                if (src_path == dst_path || (src_path && dst_path && *src_path < *dst_path)) {
                    return CODE(RULE_ENGINE_CONTINUE);
                }
            }

            util::for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
                if (const auto status = fs::server::status(conn, input->srcDataObjInp.objPath); fs::server::is_data_object(status)) {
                    util::throw_if_maximum_number_of_data_objects_violation(attrs, _info, 1);
                    util::throw_if_maximum_size_in_bytes_violation(attrs, _info, fs::server::data_object_size(conn, input->srcDataObjInp.objPath));
                }
                else if (fs::server::is_collection(status)) {
                    const auto [objects, bytes] = util::compute_data_object_count_and_size(conn, input->srcDataObjInp.objPath);
                    util::throw_if_maximum_number_of_data_objects_violation(attrs, _info, objects);
                    util::throw_if_maximum_size_in_bytes_violation(attrs, _info, bytes);
                }
                else {
                    throw logical_quotas_error{"Logical Quotas Policy: Invalid object type"};
                }
            });
        }
        catch (const logical_quotas_error& e) {
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

    auto pep_api_data_obj_rename_post(const std::string& _instance_name,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();

            {
                auto src_path = util::get_monitored_parent_collection(conn, attrs, input->srcDataObjInp.objPath);
                auto dst_path = util::get_monitored_parent_collection(conn, attrs, input->destDataObjInp.objPath);

                // Return if any of the following is true:
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
                throw logical_quotas_error{"Logical Quotas Policy: Invalid object type"};
            }

            util::for_each_monitored_collection(conn, attrs, input->destDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                util::update_data_object_count_and_size(conn, attrs, _collection, _info, objects, bytes);
            });

            util::for_each_monitored_collection(conn, attrs, input->srcDataObjInp.objPath, [&](const auto& _collection, const auto& _info) {
                util::update_data_object_count_and_size(conn, attrs, _collection, _info, objects, bytes);
            });
        }
        catch (const logical_quotas_error& e) {
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

    auto pep_api_data_obj_unlink::pre(const std::string& _instance_name,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();

            if (auto monitored_collection = util::get_monitored_parent_collection(conn, attrs, input->objPath); monitored_collection) {
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

    auto pep_api_data_obj_unlink::post(const std::string& _instance_name,
                                       std::list<boost::any>& _rule_arguments,
                                       irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();

            util::for_each_monitored_collection(conn, attrs, input->objPath, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
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

    auto pep_api_data_obj_write::pre(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            const auto& instance_config = instance_configs.at(_instance_name);
            auto* input = util::get_input_object_ptr<openedDataObjInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_config.attributes();
            const auto* path = irods::get_l1desc(input->l1descInx).dataObjInfo->objPath;

            util::for_each_monitored_collection(conn, attrs, path, [&conn, &attrs, input](const auto&, const auto& _info) {
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

    auto pep_api_data_obj_write::post(const std::string& _instance_name,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<openedDataObjInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();
            const auto* path = irods::get_l1desc(input->l1descInx).dataObjInfo->objPath;

            util::for_each_monitored_collection(conn, attrs, path, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
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

    auto pep_api_mod_avu_metadata_pre(const std::string& _instance_name,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error
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
            util::log_exception_message(e.what(), _effect_handler);
            return ERROR(RE_RUNTIME_ERROR, e.what());
        }

        return CODE(RULE_ENGINE_CONTINUE);
    }

    auto pep_api_rm_coll::pre(const std::string& _instance_name,
                              std::list<boost::any>& _rule_arguments,
                              irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<collInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();

            if (auto monitored_collection = util::get_monitored_parent_collection(conn, attrs, input->collName); monitored_collection) {
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

    auto pep_api_rm_coll::post(const std::string& _instance_name,
                               std::list<boost::any>& _rule_arguments,
                               irods::callback& _effect_handler) -> irods::error
    {
        try
        {
            auto* input = util::get_input_object_ptr<collInp_t>(_rule_arguments);
            auto& rei = util::get_rei(_effect_handler);
            auto& conn = *rei.rsComm;
            const auto& attrs = instance_configs.at(_instance_name).attributes();

            util::for_each_monitored_collection(conn, attrs, input->collName, [&conn, &attrs, input](const auto& _collection, const auto& _info) {
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
} // namespace irods::handler

