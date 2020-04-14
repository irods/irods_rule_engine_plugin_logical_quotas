# iRODS Rule Engine Plugin - Logical Quotas

Allows administrators to track and enforce limits on the number of bytes and data objects in a collection.

The following example demonstrates monitoring a collection, setting a quota on the maximum number of data
objects, and then violating that quota.
```bash
$ ils
/tempZone/home/rods:
  foo
  bar
$ irule -r irods_rule_engine_plugin-irods_rule_language-instance 'logical_quotas_start_monitoring_collection("/tempZone/home/rods")' null ruleExecOut
$ imeta ls -C .                                                                                                                                                                
AVUs defined for collection /tempZone/home/rods:
attribute: irods::logical_quotas::total_number_of_data_objects
value: 2
units: 
----
attribute: irods::logical_quotas::total_size_in_bytes
value: 1014
units: 
$ irule -r irods_rule_engine_plugin-irods_rule_language-instance 'logical_quotas_set_maximum_number_of_data_objects("/tempZone/home/rods", "2")' null ruleExecOut              
$ imeta ls -C .
AVUs defined for collection /tempZone/home/rods:
attribute: irods::logical_quotas::maximum_number_of_data_objects
value: 2
units: 
----
attribute: irods::logical_quotas::total_number_of_data_objects
value: 2
units: 
----
attribute: irods::logical_quotas::total_size_in_bytes
value: 1014
units: 
$ iput baz
remote addresses: 152.54.8.75 ERROR: putUtil: put error for /tempZone/home/rods/baz, status = -130000 status = -130000 SYS_INVALID_INPUT_PARAM
Level 0: Logical Quotas Policy Violation: Adding object exceeds maximum number of objects limit
$ ils
/tempZone/home/rods:
  foo
  bar
```

## Requirements
- iRODS v4.2.8+
- irods-dev package
- irods-runtime package
- irods-externals-boost package
- irods-externals-json package

## Compiling
```bash
$ git clone https://github.com/irods/irods_rule_engine_plugin_logical_quotas
$ cd irods_rule_engine_plugin_logical_quotas
$ git checkout 4-2-stable
$ mkdir _build && cd _build
$ cmake -GNinja ..
$ ninja package
```
After compiling, you should now have a `deb` or `rpm` package with a name similar to the following:
```bash
irods-rule-engine-plugin-logical-quotas-<plugin_version>-<os>-<arch>.<deb|rpm>
```

## Installing
Ubuntu:
```bash
$ sudo dpkg -i irods-rule-engine-plugin-logical-quotas-*.deb
```
CentOS:
```bash
$ su -c yum localinstall irods-rule-engine-plugin-logical-quotas-*.rpm
```
If the installation was successful, you should now have a new shared library. The full path to the library
should be similar to the following:
```
<irods_lib_home>/plugins/rule_engines/libirods_rule_engine_plugin-logical_quotas.so
```

## Configuration
To enable, prepend the following plugin config to the list of rule engines in `/etc/irods/server_config.json`. 
The plugin config must be placed ahead of all plugins that do not support continuation.

Even though this plugin will process PEPs first due to it's positioning, subsequent Rule Engine Plugins (REP) will 
still be allowed to process the same PEPs without any issues.
```javascript
"rule_engines": [
    {
        "instance_name": "irods_rule_engine_plugin-logical_quotas-instance",
        "plugin_name": "irods_rule_engine_plugin-logical_quotas",
        "plugin_specific_configuration": {
            "namespace": "irods::logical_quotas",
            "metadata_attribute_names": {
                "maximum_number_of_data_objects": "maximum_number_of_data_objects",
                "maximum_size_in_bytes": "maximum_size_in_bytes",
                "total_number_of_data_objects": "total_number_of_data_objects",
                "total_size_in_bytes": "total_size_in_bytes"
            }
        }
    },
    
    // ... Previously installed rule engine plugin configs ...
]
```

## How To Use
The following operations are supported:
- logical_quotas_count_total_number_of_data_objects
- logical_quotas_count_total_size_in_bytes
- logical_quotas_recalculate_totals
- logical_quotas_set_maximum_number_of_data_objects
- logical_quotas_set_maximum_size_in_bytes
- logical_quotas_start_monitoring_collection
- logical_quotas_stop_monitoring_collection
- logical_quotas_unset_maximum_number_of_data_objects
- logical_quotas_unset_maximum_size_in_bytes
- logical_quotas_unset_total_number_of_data_objects
- logical_quotas_unset_total_size_in_bytes

### Invoking operations via the Plugin
To invoke an operation through the plugin, JSON must be passed using the following structure:
```javascript
{
    // One of the operations listed above.
    "operation": "<value>",

    // The absolute logical path of an existing collection.
    "collection": "<value>",

    // This value is only used by "logical_quotas_set_maximum_number_of_data_objects" and
    // "logical_quotas_set_maximum_size_in_bytes". This is expected to be an integer
    // passed in as a string.
    "value": "<value>"
}
```

Use `irule` to execute an operation. For example, we can start monitoring a collection by running the following:
```bash
$ irule -r irods_rule_engine_plugin-logical_quotas-instance '{"operation": "logical_quotas_start_monitoring_collection", "collection": "/tempZone/home/rods"}' null ruleExecOut
```

We can set a maximum limit on the number of data objects by running the following:
```bash
$ irule -r irods_rule_engine_plugin-logical_quotas-instance '{"operation": "logical_quotas_set_maximum_number_of_data_objects", "collection": "/tempZone/home/rods", "value": "100"}' null ruleExecOut
```
If no errors occurred, then `/tempZone/home/rods` will only be allowed to contain 100 data objects. However, Logical
Quotas does not guarantee that the numbers produced perfectly reflect the total number of data objects under a collection.
Logical Quotas only provides a relative value assuming there are many clients accessing the system simultaneously.

To help with this situation, `logical_quotas_recalculate_totals` is provided. This operation can be scheduled
to run periodically to keep the numbers as accurate as possible.

### Invoking operations via the Native Rule Language
Here, we demonstrate how to start monitoring a collection just like in the section above.
```bash
$ irule -r irods_rule_engine_plugin-irods_rule_language-instance 'logical_quotas_start_monitoring_collection(*col)' '*col=/tempZone/home/rods' ruleExecOut
```

