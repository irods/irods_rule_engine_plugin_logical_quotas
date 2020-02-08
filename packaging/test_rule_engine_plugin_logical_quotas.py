from __future__ import print_function

import os
import sys
import shutil
import json
import subprocess
import tempfile

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from . import session
from .. import test
from .. import lib
from .. import paths
from ..configuration import IrodsConfig

class Test_Rule_Engine_Plugin_Logical_Quotas(session.make_sessions_mixin([('otherrods', 'rods')], []), unittest.TestCase):

    def setUp(self):
        super(Test_Rule_Engine_Plugin_Logical_Quotas, self).setUp()
        self.admin = self.admin_sessions[0]

    def tearDown(self):
        super(Test_Rule_Engine_Plugin_Logical_Quotas, self).tearDown()

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_logical_quotas_commands(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_incorrect_config(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_create_data_object(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_put_data_object(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # For each test, the following behavior must be checked:
            # - The totals are updated appropriately (object count and bytes)
            # - The quotas are enforced appropriately (object count and bytes)
            # - Consider nesting

            sandbox = self.admin.session_collection
            self.logical_quotas_start_monitoring_collection(sandbox)
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, 2)
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, 15)

            # Put a data object. This should not exceed any quotas.
            file_size = 4
            self.put_new_data_object('f1.txt', file_size)
            expected_number_of_objects = 1
            expected_size_in_bytes = file_size
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Exceeds max number of bytes quota.
            file_size = 100
            self.put_new_data_object_exceeds_quota('not_gonna_work.buddy', file_size)
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Put another data object. This should not exceed any quotas.
            file_size = 6
            self.put_new_data_object('f2.txt', file_size)
            expected_number_of_objects += 1
            expected_size_in_bytes += file_size
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Exceeds max number of data objects quota.
            file_size = 5
            self.put_new_data_object_exceeds_quota('not_gonna_work.buddy', file_size)
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Remove the data objects.
            self.admin.assert_icommand(['irm', '-f', 'f1.txt'])
            self.admin.assert_icommand(['irm', '-f', 'f2.txt'])
            expected_number_of_objects = 0
            expected_size_in_bytes = 0
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            self.logical_quotas_stop_monitoring_collection(sandbox)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_put_collection(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            sandbox = self.admin.session_collection
            self.logical_quotas_start_monitoring_collection(sandbox)
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, 1)

            dir_path = os.path.join(self.admin.local_session_dir, 'coll.d')
            dir_name = os.path.basename(dir_path)
            file_size = 20
            self.make_directory(dir_path, ['f1.txt', 'f2.txt', 'f3.txt'], file_size)

            # Test: Exceed the max number of data objects.
            self.admin.assert_icommand_fail(['iput', '-r', dir_path])
            expected_number_of_objects = 1
            expected_size_in_bytes = 20
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Test: Exceed the max number of bytes and show that the current totals are correct.
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, 100)
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, 1)
            self.admin.assert_icommand_fail(['iput', '-rf', dir_path])
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Test: No quota violations on put of a non-empty collection.
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, 100)
            self.admin.assert_icommand(['iput', '-rf', dir_path], 'STDOUT', ['pre-scan'])
            expected_number_of_objects = 3
            expected_size_in_bytes = 60
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Remove the collection.
            self.admin.assert_icommand(['irm', '-rf', dir_name])
            expected_number_of_objects = 0
            expected_size_in_bytes = 0
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            for f in ['f1.txt', 'f2.txt', 'f3.txt']:
                os.remove(os.path.join(dir_path, f))
            os.removedirs(dir_path)

            self.logical_quotas_stop_monitoring_collection(sandbox)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_copy_data_object(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            col1 = self.admin.session_collection
            self.logical_quotas_start_monitoring_collection(col1)
            self.logical_quotas_set_maximum_number_of_data_objects(col1, 4)
            self.logical_quotas_set_maximum_size_in_bytes(col1, 100)

            # "col2" is a child collection of "col1".
            col2 = os.path.join(col1, 'col.d')
            self.admin.assert_icommand(['imkdir', col2])
            self.logical_quotas_start_monitoring_collection(col2)
            self.logical_quotas_set_maximum_number_of_data_objects(col2, 1)
            self.logical_quotas_set_maximum_size_in_bytes(col2, 100)

            # Put a data object into "col1".
            data_object = 'foo.txt'
            file_size = 1
            self.put_new_data_object(data_object, file_size)
            expected_number_of_objects = 1
            expected_size_in_bytes = file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

            # Copy data object into child collection.
            self.admin.assert_icommand(['icp', data_object, col2])
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)

            # Trigger quota violation.
            self.admin.assert_icommand_fail(['icp', data_object, os.path.join(col2, 'foo.txt.copy')])
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)

            # Verify that "col1"'s quota totals have also changed as a result of "col2"'s totals.
            expected_number_of_objects += 1
            expected_size_in_bytes += file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

            # Copy data object into current collection.
            self.admin.assert_icommand(['icp', data_object, 'foo.txt.copy'])
            expected_number_of_objects += 1
            expected_size_in_bytes += file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_copy_collection(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # TODO Copy collection into monitored collection
            # TODO Copy collection to sibling collection
            # TODO Copy collection to child collection
            # TODO Copy collection back to parent collection.

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_rename_data_object(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # TODO rename/move data object under same collection.
            # TODO rename/move data object under child collection.
            # TODO rename/move collection back to parent collection.
            # TODO rename/move data object under sibling collection.

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_rename_collection(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # TODO rename/move collection under same collection.
            # TODO rename/move collection under child collection.
            # TODO rename/move collection back to parent collection.
            # TODO rename/move collection under sibling collection.

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_stream_data_object(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            sandbox = self.admin.session_collection
            self.logical_quotas_start_monitoring_collection(sandbox)
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, 10)
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, len('hello, world!'))

            data_object = 'foo.txt'

            # Create a new data object and write to it.
            contents = 'hello, world!'
            self.admin.assert_icommand(['istream', 'write', data_object], input=contents)
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])
            expected_number_of_objects = 1
            expected_size_in_bytes = len(contents)
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Write in memory used by existing data object.
            # The current totals should not change.
            self.admin.assert_icommand(['ils', '-l', data_object], 'STDOUT', [data_object])
            self.admin.assert_icommand(['istream', 'write', '-o', '7', '--no-trunc', data_object], input='iRODS!')
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', ['hello, iRODS!'])
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Trigger quota violation.
            self.admin.assert_icommand_fail(['istream', 'write', '-a', data_object], input='This will trigger a quota violation.')
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', ['hello, iRODS!'])
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Truncate and write to existing data object.
            contents = 'truncated'
            self.admin.assert_icommand(['istream', 'write', data_object], input=contents)
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])
            expected_size_in_bytes = len(contents)
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Append to existing data object.
            contents = ' it!'
            self.admin.assert_icommand(['istream', 'write', '-a', data_object], input=contents)
            self.admin.assert_icommand(['istream', 'read', data_object], 'STDOUT', ['truncated it!'])
            expected_size_in_bytes = len('truncated it!')
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            self.logical_quotas_stop_monitoring_collection(sandbox)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_nested_monitored_collections(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_sibling_monitored_collections(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_unset_maximum_quotas_when_not_tracking__issue_5(self):
        config = IrodsConfig()
        col = self.admin.session_collection

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            self.logical_quotas_start_monitoring_collection(col)
            self.admin.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', [self.total_number_of_data_objects_attribute(),
                                                                              self.total_size_in_bytes_attribute()])

            self.logical_quotas_set_maximum_number_of_data_objects(col, 100)
            self.logical_quotas_set_maximum_size_in_bytes(col, 10000)
            self.admin.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', [self.total_number_of_data_objects_attribute(),
                                                                              self.total_size_in_bytes_attribute(),
                                                                              self.maximum_number_of_data_objects_attribute(),
                                                                              self.maximum_size_in_bytes_attribute()])

            self.logical_quotas_stop_monitoring_collection(col)
            self.admin.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', [self.maximum_number_of_data_objects_attribute(),
                                                                              self.maximum_size_in_bytes_attribute()])

            self.logical_quotas_unset_maximum_number_of_data_objects(col)
            self.logical_quotas_unset_maximum_size_in_bytes(col)
            self.admin.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', ['None'])

    #
    # Utility Functions
    #

    def put_new_data_object(self, logical_path, size=0):
        filename = os.path.join(self.admin.local_session_dir, os.path.basename(logical_path))
        lib.make_file(filename, size, 'arbitrary')
        self.admin.assert_icommand(['iput', filename, logical_path])
        os.remove(filename)

    def put_new_data_object_exceeds_quota(self, logical_path, size=0):
        filename = os.path.basename(logical_path)
        lib.make_file(filename, size, 'arbitrary')
        self.admin.assert_icommand_fail(['iput', filename, logical_path])
        os.remove(filename)

    def make_directory(self, dir_name, files, file_size):
        os.makedirs(dir_name)
        for f in files:
            lib.make_file(os.path.join(dir_name, f), file_size, 'arbitrary')

    def assert_quotas(self, coll, expected_number_of_objects, expected_size_in_bytes):
        values = self.get_logical_quotas_attribute_values(coll)
        self.assertEquals(values[self.total_number_of_data_objects_attribute()], expected_number_of_objects)
        self.assertEquals(values[self.total_size_in_bytes_attribute()],          expected_size_in_bytes)

    def enable_rule_engine_plugin(self, config, namespace=None):
        config.server_config['log_level']['rule_engine'] = 'trace'
        config.server_config['plugin_configuration']['rule_engines'].insert(0, {
            'instance_name': 'irods_rule_engine_plugin-logical_quotas-instance',
            'plugin_name': 'irods_rule_engine_plugin-logical_quotas',
            'plugin_specific_configuration': {
                'namespace': self.logical_quotas_namespace() if namespace == None else namespace,
                'metadata_attribute_names': {
                    'maximum_number_of_data_objects': self.maximum_number_of_data_objects_attribute_name(),
                    'maximum_size_in_bytes': self.maximum_size_in_bytes_attribute_name(),
                    'total_number_of_data_objects': self.total_number_of_data_objects_attribute_name(),
                    'total_size_in_bytes': self.total_size_in_bytes_attribute_name()
                }
            }
        })
        lib.update_json_file_from_dict(config.server_config_path, config.server_config)

    def maximum_number_of_data_objects_attribute_name(self):
        return 'maximum_number_of_data_objects'

    def maximum_size_in_bytes_attribute_name(self):
        return 'maximum_size_in_bytes'

    def total_number_of_data_objects_attribute_name(self):
        return 'total_number_of_data_objects'

    def total_size_in_bytes_attribute_name(self):
        return 'total_size_in_bytes'

    def logical_quotas_namespace(self):
        return 'irods::logical_quotas'

    def maximum_number_of_data_objects_attribute(self):
        return self.logical_quotas_namespace() + '::' + self.maximum_number_of_data_objects_attribute_name()

    def maximum_size_in_bytes_attribute(self):
        return self.logical_quotas_namespace() + '::' + self.maximum_size_in_bytes_attribute_name()

    def total_number_of_data_objects_attribute(self):
        return self.logical_quotas_namespace() + '::' + self.total_number_of_data_objects_attribute_name()

    def total_size_in_bytes_attribute(self):
        return self.logical_quotas_namespace() + '::' + self.total_size_in_bytes_attribute_name()

    def get_logical_quotas_attribute_values(self, collection, include_max_values=False):
        query = '"select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = \'{0}\'"'.format(collection)
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s=%s', query])

        attrs = [
            self.total_number_of_data_objects_attribute(),
            self.total_size_in_bytes_attribute()
        ]

        if include_max_values == True:
            attrs.append(self.maximum_number_of_data_objects_attribute())
            attrs.append(self.maximum_size_in_bytes_attribute())

        quota_values = {}

        # Convert the utf-8 string to an ascii string.
        # Split the string into rows and remove the last element (which will be an empty string).
        for row in str(utf8_query_result_string).split('\n')[:-1]:
            columns = row.split('=')
            if columns[0] in attrs:
                quota_values[columns[0]] = int(columns[1])

        return quota_values

    def exec_logical_quotas_operation(self, json_string):
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', json_string, 'null', 'null'])

    def logical_quotas_start_monitoring_collection(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_start_monitoring_collection',
            'collection': collection
        }))

    def logical_quotas_stop_monitoring_collection(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_stop_monitoring_collection',
            'collection': collection
        }))

    def logical_quotas_set_maximum_number_of_data_objects(self, collection, max_number_of_data_objects):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_set_maximum_number_of_data_objects',
            'collection': collection,
            'value': max_number_of_data_objects
        }))

    def logical_quotas_unset_maximum_number_of_data_objects(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_unset_maximum_number_of_data_objects',
            'collection': collection
        }))

    def logical_quotas_set_maximum_size_in_bytes(self, collection, max_size_in_bytes):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_set_maximum_size_in_bytes',
            'collection': collection,
            'value': max_size_in_bytes
        }))

    def logical_quotas_unset_maximum_size_in_bytes(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_unset_maximum_size_in_bytes',
            'collection': collection
        }))

