# iRODS Rule Engine Plugin - Update Collection MTime

This plugin was developed as a dependency for [NFSRODS](https://github.com/irods/irods_client_nfsrods).

This plugin brings iRODS closer to POSIX semantics by enabling iRODS to automatically update the mtimes for
collections when changes are detected within them.

## Requirements
- iRODS v4.2.6+
- irods-externals-boost package
- irods-dev package
- irods-runtime package

## Compiling
```bash
$ git clone https://github.com/irods/irods_rule_engine_plugin_update_collection_mtime
$ mkdir _build
$ cd _build
$ cmake -GNinja ../irods_rule_engine_plugin_update_collection_mtime
$ ninja package
```
After compiling, you should now have a `deb` or `rpm` package with a name similar to the following:
```bash
irods-rule-engine-plugin-update-collection-mtime-<plugin_version>-<os>-<arch>.<deb|rpm>
```

## Installing
Ubuntu:
```bash
$ sudo dpkg -i irods-rule-engine-plugin-update-collection-mtime-*.deb
```
CentOS:
```bash
$ su -c yum localinstall irods-rule-engine-plugin-update-collection-mtime-*.rpm
```
If the installation was successful, you should now have a new shared library. The full path to the library
should be similar to the following:
```
<irods_lib_home>/plugins/rule_engines/libirods_rule_engine_plugin-update_collection_mtime.so
```

## Configuration
To enable, prepend the following plugin config to the list of rule engines in `/etc/irods/server_config.json`. 
The plugin config must be placed at the beginning of the `"rule_engines"` section. Placing the plugin after other 
plugins could result in mtimes not being updated.

Even though this plugin will process PEPs first due to it's positioning, subsequent Rule Engine Plugins (REP) will 
still be allowed to process the same PEPs without any issues.
```javascript
"rule_engines": [
    {
        "instance_name": "irods_rule_engine_plugin-update_collection_mtime-instance",
        "plugin_name": "irods_rule_engine_plugin-update_collection_mtime",
        "plugin_specific_configuration": {}
    },
    
    // ... Previously installed rule engine plugin configs ...
]
```
