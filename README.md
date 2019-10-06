# iRODS Rule Engine Plugin - Logical Quotas

## Requirements
- iRODS v4.2.6+
- irods-externals-boost package
- irods-dev package
- irods-runtime package

## Compiling
```bash
$ git clone https://github.com/irods/irods_rule_engine_plugin_logical_quotas
$ mkdir _build
$ cd _build
$ cmake -GNinja ../irods_rule_engine_plugin_logical_quotas
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
            "namespace": "logical_quotas"
        }
    },
    
    // ... Previously installed rule engine plugin configs ...
]
```
