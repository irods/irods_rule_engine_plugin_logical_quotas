# iRODS Rule Engine Plugin - Logical Quotas

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
$ git submodule update --init
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
The plugin config should be placed near the beginning of the `"rule_engines"` section.

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
Convenience scripts are available under the `<repo>/scripts` directory.

To use it, you will first need to edit the `<rule_file.r>` files. Within these files, you'll need to set the
collection along with any other properties that are important to your deployment. You should only need to modify
the `collection` property (and `value` property if listed) within the rule files.

Once you've updated the rule files, navigate to the **scripts** directory and run `./lq_cmd.sh <rule_file.r>` to
execute the operation.

For example, to start monitoring a collection, you'd do the following:
```bash
$ vim start_monitoring.r             # Set the collection.
$ ./lq_cmd.sh start_monitoring.r     # Execute the rule file.
$ imeta ls -C <path/to/collection>   # Verify that the metadata is set.
```

The following operations are available:
- start_monitoring
- stop_monitoring
- set_maximum_number_of_data_objects
- set_maximum_size_in_bytes
- recalculate_totals
- count_total_number_of_data_objects
- count_total_size_in_bytes
- unset_maximum_number_of_data_objects
- unset_maximum_size_in_bytes
- unset_total_number_of_data_objects
- unset_total_size_in_bytes

