cmake_minimum_required(VERSION 3.12...3.18 FATAL_ERROR)
if (POLICY CMP0109)
  # find_program requires permission to execute but not to read
  cmake_policy(SET CMP0109 NEW)
endif()
if (POLICY CMP0121)
  # Detect invalid indices in list()
  cmake_policy(SET CMP0121 NEW)
endif()
if (POLICY CMP0125)
  # Consistent behavior for cache variables managed by find_*()
  cmake_policy(SET CMP0125 NEW)
endif()
if (POLICY CMP0130)
  # Diagnose condition evaluation errors in while()
  cmake_policy(SET CMP0130 NEW)
endif()
if (POLICY CMP0132)
  # Consistent handling of compiler environment variables
  cmake_policy(SET CMP0132 NEW)
endif()
if (POLICY CMP0140)
  # Check validity of return() params
  cmake_policy(SET CMP0140 NEW)
endif()

set(IRODS_MINIMUM_VERSION "4.90.0")
set(IRODS_MAXIMUM_VERSION "6.0.0")
find_package(IRODS "${IRODS_MINIMUM_VERSION}...<${IRODS_MAXIMUM_VERSION}" REQUIRED)

set(IRODS_PLUGIN_VERSION "5.0.1")

set(IRODS_PACKAGE_REVISION "0")

include(IrodsCXXCompiler)
set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
include(IrodsRunpathDefaults)

project(irods_rule_engine_plugin-logical_quotas
  VERSION "${IRODS_PLUGIN_VERSION}"
  LANGUAGES CXX)

include(${IRODS_TARGETS_PATH})

if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build {Debug, Release}." FORCE)
    message(STATUS "Setting unspecified CMAKE_BUILD_TYPE to '${CMAKE_BUILD_TYPE}'")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

include(GNUInstallDirs)

find_package(nlohmann_json "3.6.1" REQUIRED)
find_package(fmt "8.1.1" REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fpermissive>)
endif()

set(PLUGIN irods_rule_engine_plugin-logical_quotas)

add_library(${PLUGIN} MODULE ${CMAKE_SOURCE_DIR}/src/main.cpp
                             ${CMAKE_SOURCE_DIR}/src/handler.cpp)

target_compile_options(${PLUGIN} PRIVATE -Wno-write-strings)

target_compile_definitions(${PLUGIN} PRIVATE ${IRODS_COMPILE_DEFINITIONS}
                                             ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
                                             IRODS_QUERY_ENABLE_SERVER_SIDE_API
                                             IRODS_ENABLE_SYSLOG
                                             IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
                                             IRODS_REPLICA_ENABLE_SERVER_SIDE_API
                                             SPDLOG_FMT_EXTERNAL
                                             SPDLOG_NO_TLS)

target_include_directories(${PLUGIN} PRIVATE ${IRODS_INCLUDE_DIRS}
                                             ${IRODS_EXTERNALS_FULLPATH_BOOST}/include)

target_link_libraries(${PLUGIN} PRIVATE irods_server
                                        irods_common
                                        nlohmann_json::nlohmann_json
                                        fmt::fmt
                                        ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so
                                        ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so
                                        ${CMAKE_DL_LIBS})

install(TARGETS ${PLUGIN} LIBRARY DESTINATION ${IRODS_PLUGINS_DIRECTORY}/rule_engines)

install(FILES ${CMAKE_SOURCE_DIR}/packaging/test_rule_engine_plugin_logical_quotas.py
        DESTINATION ${IRODS_HOME_DIRECTORY}/scripts/irods/test
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

set(PLUGIN_PACKAGE_NAME irods-rule-engine-plugin-logical-quotas)

include(IrodsCPackCommon)

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods/test")

set(CPACK_PACKAGE_VERSION ${IRODS_PLUGIN_VERSION})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/packaging/postinst;")
set(CPACK_DEBIAN_PACKAGE_BREAKS ${PLUGIN_PACKAGE_NAME})
set(CPACK_DEBIAN_PACKAGE_REPLACES ${PLUGIN_PACKAGE_NAME})
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
set(CPACK_RPM_PACKAGE_OBSOLETES ${PLUGIN_PACKAGE_NAME})
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/postinst")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

set(CPACK_DEBIAN_PACKAGE_NAME ${PLUGIN_PACKAGE_NAME})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server (= ${IRODS_VERSION}), irods-runtime (= ${IRODS_VERSION}), libc6")

set(CPACK_RPM_PACKAGE_NAME ${PLUGIN_PACKAGE_NAME})
set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-server = ${IRODS_VERSION}, irods-runtime = ${IRODS_VERSION}")

if (NOT CPACK_GENERATOR)
    set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
    message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)
