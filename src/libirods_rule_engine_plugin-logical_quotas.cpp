#include "irods_plugin_context.hpp"
#include "irods_re_plugin.hpp"
#include "irods_re_serialization.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "irods_get_l1desc.hpp"
#include "irods_at_scope_exit.hpp"
#include "objInfo.h"
#include "dataObjInpOut.h"
#include "rcMisc.h"
#include "rcMisc.h"
#include "rodsError.h"

#include <string>
#include <array>
#include <algorithm>
#include <iterator>
#include <functional>

#include <boost/filesystem.hpp>

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

namespace
{
    // This is a "sorted" list of the supported PEPs.
    // This will allow us to do binary search on the list for lookups.
    constexpr std::array<const char*, 10> peps{{
        "pep_api_data_obj_copy_post",
        "pep_api_data_obj_copy_pre",
        "pep_api_data_obj_put_post",
        "pep_api_data_obj_put_pre",
        "pep_api_data_obj_rename_post",
        "pep_api_data_obj_rename_pre",
        "pep_api_data_obj_unlink_post",
        "pep_api_data_obj_unlink_pre",
        "pep_api_rm_coll_post"
        "pep_api_rm_coll_pre",
    }};

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
            irods::error result{_effect_handler("unsafe_ms_ctx", &rei)};

            if (!result.ok()) {
                THROW(result.code(), "failed to get rule execution info");
            }

            return *rei;
        }

        template <typename Function>
        auto sudo(ruleExecInfo_t& _rei, Function _func) -> decltype(_func())
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

        std::string parent_path(const char* _path)
        {
            namespace fs = boost::filesystem;
            return fs::path{_path}.parent_path().generic_string();
        }

        template <typename T>
        T* get_input_object_ptr(std::list<boost::any>& _rule_arguments)
        {
            return boost::any_cast<T*>(*std::next(std::begin(_rule_arguments), 2));
        }

        std::string to_string(const collInp_t& _input)
        {
            return util::concat("collInp_t {collName: ", _input.collName, '}');
        }

        std::string to_string(const openedDataObjInp_t& _input)
        {
            const auto fd = std::to_string(_input.l1descInx);
            const auto len = std::to_string(_input.len);
            const auto op_type = std::to_string(_input.oprType);
            const auto bytes = std::to_string(_input.bytesWritten);

            return util::concat("openedDataObjInp_t {l1descInx: ", fd, 
                                ", len: ", len, 
                                ", oprType: ", op_type, 
                                ", bytesWritten: ", bytes, '}');
        }

        std::string to_string(const dataObjInp_t& _input)
        {
            return util::concat("dataObjInp_t {objPath: ", _input.objPath, '}');
        }

        std::string to_string(const dataObjCopyInp_t& _input)
        {
            const auto* src = _input.srcDataObjInp.objPath;
            const auto* dst = _input.destDataObjInp.objPath;

            return util::concat("dataObjCopyInp_t {srcDataObjInp.objPath: ", src, ", destDataObjInp.objPath: ", dst, '}');
        }

        std::string to_string(const l1desc& _input)
        {
            const auto* path = _input.dataObjInp->objPath;
            const auto bytes = std::to_string(_input.bytesWritten);

            return util::concat("l1desc {dataObjInp->objPath: ", path, ", bytesWritten: ", bytes, '}');
        }
    } // namespace util

    //
    // PEP Handlers
    //

    namespace handler
    {
        irods::error pep_api_data_obj_copy_pre(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());

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
                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());

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
            try
            {
                auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());

            }
            catch (const std::exception& e)
            {
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

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());

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
                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());
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
                auto* input = util::get_input_object_ptr<dataObjCopyInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());
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
                auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());
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
                auto* input = util::get_input_object_ptr<dataObjInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_rm_coll_pre(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                auto* input = util::get_input_object_ptr<collInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }

        irods::error pep_api_rm_coll_post(std::list<boost::any>& _rule_arguments, irods::callback& _effect_handler)
        {
            try
            {
                auto* input = util::get_input_object_ptr<collInp_t>(_rule_arguments);

                rodsLog(LOG_DEBUG, "%s - input args => %s", __func__, util::to_string(*input).c_str());
            }
            catch (const std::exception& e)
            {
                util::log_exception_message(e.what(), _effect_handler);
                return ERROR(RE_RUNTIME_ERROR, e.what());
            }

            return CODE(RULE_ENGINE_CONTINUE);
        }
    } // namespace handler

    //
    // Rule Engine Plugin
    //

    template <typename ...Args>
    using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

    irods::error rule_exists(irods::default_re_ctx&, const std::string& _rule_name, bool& _exists)
    {
        auto b = std::cbegin(peps);
        auto e = std::cend(peps);

        _exists = std::binary_search(b, e, _rule_name.c_str(), [](const auto* _lhs, const auto* _rhs) {
            return strcmp(_lhs, _rhs) < 0;
        });

        return SUCCESS();
    }

    irods::error list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules)
    {
        _rules.insert(std::end(_rules), std::begin(peps), std::end(peps));
        return SUCCESS();
    }

    irods::error exec_rule(irods::default_re_ctx&,
                           const std::string& _rule_name,
                           std::list<boost::any>& _rule_arguments,
                           irods::callback _effect_handler)
    {
        using handler_t = std::function<irods::error(std::list<boost::any>&, irods::callback&)>;

        static const std::map<std::string, handler_t> handlers{
            {peps[0], handler::pep_api_data_obj_copy_post},
            {peps[1], handler::pep_api_data_obj_copy_pre},
            {peps[2], handler::pep_api_data_obj_put_post},
            {peps[3], handler::pep_api_data_obj_put_pre},
            {peps[4], handler::pep_api_data_obj_rename_post},
            {peps[5], handler::pep_api_data_obj_rename_pre},
            {peps[6], handler::pep_api_data_obj_unlink_post},
            {peps[7], handler::pep_api_data_obj_unlink_pre},
            {peps[8], handler::pep_api_rm_coll_post},
            {peps[9], handler::pep_api_rm_coll_pre}
        };

        auto iter = handlers.find(_rule_name);

        if (std::end(handlers) != iter) {
            return (iter->second)(_rule_arguments, _effect_handler);
        }

        const auto* msg = "[irods_rule_engine_plugin-logical_quotas][rule => %s] "
                          "rule not supported in rule engine plugin";

        rodsLog(LOG_ERROR, msg, _rule_name.c_str());

        // DO NOT BLOCK RULE ENGINE PLUGINS THAT FOLLOW THIS ONE!
        return CODE(RULE_ENGINE_CONTINUE);
    }
} // namespace (anonymous)

//
// Plugin Factory
//

extern "C"
pluggable_rule_engine* plugin_factory(const std::string& _instance_name,
                                      const std::string& _context)
{
    // clang-format off
    const auto no_op         = [](auto...) { return SUCCESS(); };
    const auto not_supported = [](auto...) { return CODE(SYS_NOT_SUPPORTED); };
    // clang-format on

    auto* re = new pluggable_rule_engine{_instance_name, _context};

    re->add_operation("start", operation<const std::string&>{no_op});
    re->add_operation("stop", operation<const std::string&>{no_op});
    re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists});
    re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
    re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule});
    re->add_operation("exec_rule_text", operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{not_supported});
    re->add_operation("exec_rule_expression", operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{not_supported});

    return re;
}

