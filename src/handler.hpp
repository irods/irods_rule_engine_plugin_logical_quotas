#ifndef IRODS_LOGICAL_QUOTAS_HANDLER
#define IRODS_LOGICAL_QUOTAS_HANDLER

#include <irods/irods_re_plugin.hpp>
#include <irods/irods_error.hpp>

#include <boost/any.hpp>

#include <string>
#include <list>

namespace irods::handler
{
    auto logical_quotas_start_monitoring_collection(const std::string& _instance_name,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error;
    
    auto logical_quotas_stop_monitoring_collection(const std::string& _instance_name,
                                                   std::list<boost::any>& _rule_arguments,
                                                   irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_count_total_number_of_data_objects(const std::string& _instance_name,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_count_total_size_in_bytes(const std::string& _instance_name,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_recalculate_totals(const std::string& _instance_name,
                                           std::list<boost::any>& _rule_arguments,
                                           irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_set_maximum_number_of_data_objects(const std::string& _instance_name,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_set_maximum_size_in_bytes(const std::string& _instance_name,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_unset_maximum_number_of_data_objects(const std::string& _instance_name,
                                                             std::list<boost::any>& _rule_arguments,
                                                             irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_unset_maximum_size_in_bytes(const std::string& _instance_name,
                                                    std::list<boost::any>& _rule_arguments,
                                                    irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_unset_total_number_of_data_objects(const std::string& _instance_name,
                                                           std::list<boost::any>& _rule_arguments,
                                                           irods::callback& _effect_handler) -> irods::error;

    auto logical_quotas_unset_total_size_in_bytes(const std::string& _instance_name,
                                                  std::list<boost::any>& _rule_arguments,
                                                  irods::callback& _effect_handler) -> irods::error;

    auto pep_api_data_obj_copy_pre(const std::string& _instance_name,
                                   std::list<boost::any>& _rule_arguments,
                                   irods::callback& _effect_handler) -> irods::error;

    auto pep_api_data_obj_copy_post(const std::string& _instance_name,
                                    std::list<boost::any>& _rule_arguments,
                                    irods::callback& _effect_handler) -> irods::error;

    class pep_api_data_obj_open final
    {
    public:
        static auto pre(const std::string& _instance_name,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static bool increment_object_count_ = false;
    }; // class pep_api_data_obj_open

    class pep_api_data_obj_put final
    {
    public:
        static auto pre(const std::string& _instance_name,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static std::int64_t size_diff_ = 0;
        inline static bool forced_overwrite_ = false;
    }; // class pep_api_data_obj_put

    auto pep_api_data_obj_rename_pre(const std::string& _instance_name,
                                     std::list<boost::any>& _rule_arguments,
                                     irods::callback& _effect_handler) -> irods::error;

    auto pep_api_data_obj_rename_post(const std::string& _instance_name,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error;

    class pep_api_data_obj_unlink final
    {
    public:
        static auto pre(const std::string& _instance_name,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static std::int64_t size_in_bytes_ = 0;
    }; // class pep_api_data_obj_unlink

    class pep_api_data_obj_write final
    {
    public:
        static auto pre(const std::string& _instance_name,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
    }; // class pep_api_data_obj_write

    auto pep_api_mod_avu_metadata_pre(const std::string& _instance_name,
                                      std::list<boost::any>& _rule_arguments,
                                      irods::callback& _effect_handler) -> irods::error;

    class pep_api_rm_coll final
    {
    public:
        static auto pre(const std::string& _instance_name,
                        std::list<boost::any>& _rule_arguments,
                        irods::callback& _effect_handler) -> irods::error;

        static auto post(const std::string& _instance_name,
                         std::list<boost::any>& _rule_arguments,
                         irods::callback& _effect_handler) -> irods::error;

    private:
        inline static std::int64_t data_objects_ = 0;
        inline static std::int64_t size_in_bytes_ = 0;
    }; // class pep_api_rm_coll
} // namespace irods::handler

#endif // IRODS_LOGICAL_QUOTAS_HANDLER

