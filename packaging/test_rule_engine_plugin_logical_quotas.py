from __future__ import print_function

import os
import sys
import shutil
import json

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

#   @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
#   def test_posix_api(self):
#       max_number_of_objects = 3
#       max_size_in_bytes = 3000

#       def f():
#           pass

#       self.run_test(f, self.admin.session_collection, max_number_of_objects, max_size_in_bytes)


    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_copy_and_remove_data_object(self):
        max_number_of_objects = 100
        max_size_in_bytes = 10000

        def f():
            filenames = [
                {'name': 'foo', 'size': 100},
                {'name': 'bar', 'size': 1000},
                {'name': 'baz', 'size': 1100}
            ]

            expected_number_of_objects = 0
            expected_size = 0

            for filename in filenames:
                name = filename['name']
                size = filename['size']
                lib.make_file(name, size)

                # Put a data object and check that the quota values for the collection
                # increase appropriately.
                self.admin.assert_icommand(['iput', name])
                self.admin.assert_icommand(['ils', name], 'STDOUT', name)
                os.remove(name)

                # Increment the expected values.
                expected_number_of_objects += 1
                expected_size += size

                # Check quotas.
                values = self.get_logical_quotas_attribute_values(self.admin.session_collection)
                self.assertEquals(values[self.current_number_of_objects_attribute()], expected_number_of_objects)
                self.assertEquals(values[self.current_size_in_bytes_attribute()],     expected_size)

            # Copy some of the data objects.
            file_copies = [
                {'source': 'foo', 'target': 'foo.copy', 'size': filenames[0]['size']},
                {'source': 'baz', 'target': 'baz.copy', 'size': filenames[1]['size']}
            ]

            for filename in file_copies:
                source = filename['source']
                target = filename['target']
                size = filename['size']

                self.admin.assert_icommand(['icp', source, target])
                self.admin.assert_icommand(['ils', target], 'STDOUT', target)

                # Increment the expected values.
                expected_number_of_objects += 1
                expected_size += size

                # Check quotas.
                values = self.get_logical_quotas_attribute_values(self.admin.session_collection)
                self.assertEquals(values[self.current_number_of_objects_attribute()], expected_number_of_objects)
                self.assertEquals(values[self.current_size_in_bytes_attribute()],     expected_size)

            for filename in filenames:
                name = filename['name']
                size = filename['size']

                # Remove the recently added data object and check that the quota values for
                # the collection decrease appropriately.
                self.admin.assert_icommand(['irm', '-f', name])

                # Increment the expected 
                expected_number_of_objects -= 1
                expected_size -= size

                values = self.get_logical_quotas_attribute_values(self.admin.session_collection)
                self.assertEquals(values[self.current_number_of_objects_attribute()], expected_number_of_objects)
                self.assertEquals(values[self.current_size_in_bytes_attribute()],     expected_size)

        self.run_test(f, self.admin.session_collection, max_number_of_objects, max_size_in_bytes)

#   @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
#   def test_copy_and_remove_collection(self):
#       max_number_of_objects = 3
#       max_size_in_bytes = 3000

#       def f():
#           pass

#       self.run_test(f, self.admin.session_collection, max_number_of_objects, max_size_in_bytes)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_put_and_remove_data_object(self):
        max_number_of_objects = 3
        max_size_in_bytes = 3000

        def f():
            filename = 'data_object.txt'
            lib.make_file(filename, 1024)

            # Put a data object and check that the quota values for the collection
            # increase appropriately.
            self.admin.assert_icommand(['iput', filename])
            values = self.get_logical_quotas_attribute_values(self.admin.session_collection)
            self.assertEquals(values[self.maximum_number_of_objects_attribute()], max_number_of_objects)
            self.assertEquals(values[self.maximum_size_in_bytes_attribute()],     max_size_in_bytes)
            self.assertEquals(values[self.current_number_of_objects_attribute()], 1)
            self.assertEquals(values[self.current_size_in_bytes_attribute()],     1024)

            # Remove the recently added data object and check that the quota values for
            # the collection decrease appropriately.
            self.admin.assert_icommand(['irm', '-f', filename])
            values = self.get_logical_quotas_attribute_values(self.admin.session_collection)
            self.assertEquals(values[self.current_number_of_objects_attribute()], 0)
            self.assertEquals(values[self.current_size_in_bytes_attribute()],     0)

            os.remove(filename)

        self.run_test(f, self.admin.session_collection, max_number_of_objects, max_size_in_bytes)

#   @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
#   def test_put_and_remove_collection(self):
#       max_number_of_objects = 3
#       max_size_in_bytes = 3000

#       def f():
#           pass

#       self.run_test(f, self.admin.session_collection, max_number_of_objects, max_size_in_bytes)

#   @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
#   def test_rename_and_remove_data_object(self):
#       max_number_of_objects = 3
#       max_size_in_bytes = 3000

#       def f():
#           pass

#       self.run_test(f, self.admin.session_collection, max_number_of_objects, max_size_in_bytes)

#   @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
#   def test_rename_and_remove_collection(self):
#       max_number_of_objects = 3
#       max_size_in_bytes = 3000

#       def f():
#           pass

#       self.run_test(f, self.admin.session_collection, max_number_of_objects, max_size_in_bytes)

    def run_test(self, do_test, collection, max_number_of_objects, max_size_in_bytes):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)
            self.logical_quotas_init(collection, max_number_of_objects, max_size_in_bytes)
            do_test()
            self.logical_quotas_remove(collection)

    def enable_rule_engine_plugin(self, config, namespace=None):
        config.server_config['plugin_configuration']['rule_engines'].insert(0, {
            'instance_name': 'irods_rule_engine_plugin-logical_quotas-instance',
            'plugin_name': 'irods_rule_engine_plugin-logical_quotas',
            'plugin_specific_configuration': {
                'namespace': self.logical_quotas_namespace() if namespace == None else namespace
            }
        })

        lib.update_json_file_from_dict(config.server_config_path, config.server_config)

    def logical_quotas_namespace(self):
        return 'irods::logical_quotas'

    def maximum_number_of_objects_attribute(self):
        return self.logical_quotas_namespace() + '::maximum_object_count'

    def maximum_size_in_bytes_attribute(self):
        return self.logical_quotas_namespace() + '::maximum_data_size_in_bytes'

    def current_number_of_objects_attribute(self):
        return self.logical_quotas_namespace() + '::current_object_count'

    def current_size_in_bytes_attribute(self):
        return self.logical_quotas_namespace() + '::current_data_size_in_bytes'

    def get_logical_quotas_attribute_values(self, collection):
        query = '"select META_COLL_ATTR_NAME, META_COLL_ATTR_VALUE where COLL_NAME = \'{0}\'"'.format(collection)
        utf8_query_result_string, ec, rc = self.admin.run_icommand(['iquest', '%s=%s', query])

        attrs = [
            self.maximum_number_of_objects_attribute(),
            self.maximum_size_in_bytes_attribute(),
            self.current_number_of_objects_attribute(),
            self.current_size_in_bytes_attribute()
        ]

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

    def logical_quotas_init(self, collection, max_number_of_objects, max_size_in_bytes):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_init',
            'collection': collection,
            'maximum_number_of_objects': max_number_of_objects,
            'maximum_size_in_bytes': max_size_in_bytes
        }))

    def logical_quotas_remove(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_remove',
            'collection': collection
        }))

