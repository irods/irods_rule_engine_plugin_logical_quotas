#ifndef IRODS_LOGICAL_QUOTAS_HANDLER
#define IRODS_LOGICAL_QUOTAS_HANDLER

#include "instance_configuration.hpp"

#include <irods/irods_re_plugin.hpp>
#include <irods/irods_error.hpp>

#include <boost/any.hpp>

#include <string>
#include <list>

namespace irods::handler
{
    // clang-format off
    using size_type          = std::int64_t;
    using file_position_type = std::int64_t;
    // clang-format on

    auto logical_quotas_start_monitoring_collection(const std::string& _instance_name,
                                                    const instance_configuration_map& _instance_configs,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error;
    
    auto logical_quotas_stop_monitoring_collection(const std::string& _instance_name,
                                                   const instance_configuration_map& _instance_configs,
                                                   std::list<boost::any>& _rule_arguments,
                                                   irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_count_total_number_of_data_objects(const std::string& _instance_name,
                                                           const instance_configuration_map& _instance_configs,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_count_total_size_in_bytes(const std::string& _instance_name,
                                                  const instance_configuration_map& _instance_configs,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_recalculate_totals(const std::string& _instance_name,
                                           const instance_configuration_map& _instance_configs,
                                           std::list<boost::any>& _rule_arguments,
                                           irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_set_maximum_number_of_data_objects(const std::string& _instance_name,
                                                           const instance_configuration_map& _instance_configs,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_set_maximum_size_in_bytes(const std::string& _instance_name,
                                                  const instance_configuration_map& _instance_configs,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_unset_maximum_number_of_data_objects(const std::string& _instance_name,
                                                             const instance_configuration_map& _instance_configs,
                                                             std::list<boost::any>& _rule_arguments,
                                                             irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_unset_maximum_size_in_bytes(const std::string& _instance_name,
                                                    const instance_configuration_map& _instance_configs,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_unset_total_number_of_data_objects(const std::string& _instance_name,
                                                           const instance_configuration_map& _instance_configs,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_unset_total_size_in_bytes(const std::string& _instance_name,
                                                  const instance_configuration_map& _instance_configs,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error;

    class pep_api_data_obj_copy final
    {
    public:
        pep_api_data_obj_copy() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static size_type data_objects_ = 0;
        inline static size_type size_in_bytes_ = 0;
    }; // class pep_api_data_obj_copy

    auto pep_api_data_obj_create_pre(const std::string& _instance_name,
                                     const instance_configuration_map& _instance_configs,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error;

    auto pep_api_data_obj_create_post(const std::string& _instance_name,
                                      const instance_configuration_map& _instance_configs,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error;

    class pep_api_data_obj_put final
    {
    public:
        pep_api_data_obj_put() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static size_type size_diff_ = 0;
        inline static bool forced_overwrite_ = false;
    }; // class pep_api_data_obj_put

    class pep_api_data_obj_rename final
    {
    public:
        pep_api_data_obj_rename() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static size_type data_objects_ = 0;
        inline static size_type size_in_bytes_ = 0;
    }; // class pep_api_data_obj_rename

    class pep_api_data_obj_unlink final
    {
    public:
        pep_api_data_obj_unlink() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static size_type size_in_bytes_ = 0;
    }; // class pep_api_data_obj_unlink

    class pep_api_data_obj_open final
    {
    public:
        pep_api_data_obj_open() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static size_type data_objects_ = 0;
        inline static size_type size_in_bytes_ = 0;
    }; // class pep_api_data_obj_open

    class pep_api_data_obj_lseek final
    {
    public:
        pep_api_data_obj_lseek() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static file_position_type fpos_ = 0;
    }; // class pep_api_data_obj_lseek

    class pep_api_data_obj_write final
    {
    public:
        pep_api_data_obj_write() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static file_position_type fpos_ = 0; 
    }; // class pep_api_data_obj_write

    class pep_api_data_obj_close final
    {
    public:
        pep_api_data_obj_close() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;
    private:
        inline static std::string path_;
    }; // class pep_api_data_obj_close

    class pep_api_rm_coll final
    {
    public:
        pep_api_rm_coll() = delete;

        static auto reset() noexcept -> void;

        static auto pre(const std::string& _instance_name,
                        const instance_configuration_map& _instance_configs,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         const instance_configuration_map& _instance_configs,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static size_type data_objects_ = 0;
        inline static size_type size_in_bytes_ = 0;
    }; // class pep_api_rm_coll
} // namespace irods::handler

#endif // IRODS_LOGICAL_QUOTAS_HANDLER

