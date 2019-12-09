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

    # TODO Test incorrect REP config
    # TODO Test setting only max avus without corresponding totals avus
    # TODO Test object counters (put, copy, remove)
    # TODO Test size counters (put, copy, remove)
    # TODO Test streaming counters (open/create, write)
    # TODO Test administrative metadata guard

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_basic_functionality(self):
        def do_test(root_coll, child_coll, data_object):
            root_expected_number_of_objects = 1
            root_expected_size_in_bytes = 20

            child_expected_number_of_objects = 0
            child_expected_size_in_bytes = 0

            #
            # TEST 1: Put new data object.
            #
            filename = 'bar'
            size = 20
            lib.make_file(filename, size)
            other_data_object = os.path.join(root_coll, filename)
            self.admin.assert_icommand(['iput', filename, other_data_object])
            os.remove(filename)

            # Check quotas. The quotas for the "child_coll" should not have been modified.
            root_expected_number_of_objects += 1
            root_expected_size_in_bytes += size
            self.assert_quotas(root_coll, root_expected_number_of_objects, root_expected_size_in_bytes)
            self.assert_quotas(child_coll, child_expected_number_of_objects, child_expected_size_in_bytes)

            #
            # TEST 2: Move the data objects under another collection.
            #
            self.admin.assert_icommand(['imv', data_object, os.path.join(child_coll, os.path.basename(data_object))])
            self.admin.assert_icommand(['imv', other_data_object, os.path.join(child_coll, os.path.basename(other_data_object))])
            data_object = os.path.join(child_coll, os.path.basename(data_object))
            other_data_object = os.path.join(child_coll, os.path.basename(other_data_object))

            # Check quotas. The quotas for the "root_coll" should not have been modified.
            child_expected_number_of_objects = root_expected_number_of_objects
            child_expected_size_in_bytes = root_expected_size_in_bytes
            self.assert_quotas(root_coll, root_expected_number_of_objects, root_expected_size_in_bytes)
            self.assert_quotas(child_coll, child_expected_number_of_objects, child_expected_size_in_bytes)

            #
            # TEST 3: Exceeding Quotas
            #
            filename = 'foobar'
            size = 0
            lib.make_file(filename, size)
            self.admin.assert_icommand_fail(['iput', filename, os.path.join(child_coll, filename)])
            os.remove(filename)

            filename = 'foobar'
            size = 200
            lib.make_file(filename, size)
            self.admin.assert_icommand_fail(['iput', filename, os.path.join(root_coll, filename)])
            os.remove(filename)

            #
            # TEST 4: Recursively copy "child_coll" into "root_coll".
            #
            other_child_coll = os.path.join(root_coll, 'col.b')
            self.admin.assert_icommand(['icp', '-r', child_coll, other_child_coll])

            # Check quotas. The quotas for the "child_coll" should not have been modified.
            root_expected_number_of_objects += 2
            root_expected_size_in_bytes += 40
            self.assert_quotas(root_coll, root_expected_number_of_objects, root_expected_size_in_bytes)
            self.assert_quotas(child_coll, child_expected_number_of_objects, child_expected_size_in_bytes)

            #
            # TEST 5: Remove a data object from "other_child_coll".
            #
            self.admin.assert_icommand(['irm', '-f', os.path.join(other_child_coll, os.path.basename(other_data_object))])

            # Check quotas. The quotas for the "child_coll" should not have been modified.
            root_expected_number_of_objects -= 1
            root_expected_size_in_bytes -= 20
            self.assert_quotas(root_coll, root_expected_number_of_objects, root_expected_size_in_bytes)
            self.assert_quotas(child_coll, child_expected_number_of_objects, child_expected_size_in_bytes)
 
            #
            # TEST 6: Recursively remove "other_child_coll".
            #
            self.admin.assert_icommand(['irm', '-rf', other_child_coll])

            # Check quotas. The quotas for the "child_coll" should not have been modified.
            root_expected_number_of_objects -= 1
            root_expected_size_in_bytes -= 20
            self.assert_quotas(root_coll, root_expected_number_of_objects, root_expected_size_in_bytes)
            self.assert_quotas(child_coll, child_expected_number_of_objects, child_expected_size_in_bytes)

        self.run_test(do_test)

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

    def assert_quotas(self, coll, expected_number_of_objects, expected_size_in_bytes):
        values = self.get_logical_quotas_attribute_values(coll)
        self.assertEquals(values[self.total_number_of_data_objects_attribute()], expected_number_of_objects)
        self.assertEquals(values[self.total_size_in_bytes_attribute()],          expected_size_in_bytes)

    # TODO Return the max number of objects and max size in bytes.
    # Creates and monitors the following tree under the session collection:
    #   {session_collection}/logical_quotas_root/
    #   {session_collection}/logical_quotas_root/col.a/
    #   {session_collection}/logical_quotas_root/foo
    def init_logical_quotas_tree(self):
        root_coll = os.path.join(self.admin.session_collection, 'logical_quotas_root')
        self.admin.assert_icommand(['imkdir', root_coll])

        child_coll = os.path.join(root_coll, 'col.a')
        self.admin.assert_icommand(['imkdir', child_coll])

        filename = 'foo'
        lib.make_file(filename, 20)
        data_object = os.path.join(root_coll, filename)
        self.admin.assert_icommand(['iput', filename, data_object])
        os.remove(filename)

        # Start monitoring root collection and set maximums.
        self.logical_quotas_start_monitoring_collection(root_coll)

        max_number_of_data_objects = 5
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_set_maximum_number_of_data_objects',
            'collection': root_coll,
            'value': max_number_of_data_objects
        }))

        max_size_in_bytes = 100
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_set_maximum_size_in_bytes',
            'collection': root_coll,
            'value': max_size_in_bytes
        }))

        include_maximums = True
        values = self.get_logical_quotas_attribute_values(root_coll, include_maximums)
        self.assertEquals(values[self.maximum_number_of_data_objects_attribute()], max_number_of_data_objects)
        self.assertEquals(values[self.maximum_size_in_bytes_attribute()],          max_size_in_bytes)
        self.assertEquals(values[self.total_number_of_data_objects_attribute()],   1)
        self.assertEquals(values[self.total_size_in_bytes_attribute()],            20)

        # Start monitoring child collection and set maximums.
        self.logical_quotas_start_monitoring_collection(child_coll)

        max_number_of_data_objects = 2
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_set_maximum_number_of_data_objects',
            'collection': child_coll,
            'value': max_number_of_data_objects
        }))

        max_size_in_bytes = 40
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_set_maximum_size_in_bytes',
            'collection': child_coll,
            'value': max_size_in_bytes
        }))

        values = self.get_logical_quotas_attribute_values(child_coll, include_maximums)
        self.assertEquals(values[self.maximum_number_of_data_objects_attribute()], max_number_of_data_objects)
        self.assertEquals(values[self.maximum_size_in_bytes_attribute()],          max_size_in_bytes)
        self.assertEquals(values[self.total_number_of_data_objects_attribute()],   0)
        self.assertEquals(values[self.total_size_in_bytes_attribute()],            0)

        return (root_coll, child_coll, data_object)

    #def run_test(self, do_test, collection, max_number_of_objects, max_size_in_bytes):
    def run_test(self, test):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)
            root, child, data_object  = self.init_logical_quotas_tree()
            test(root, child, data_object)
            self.logical_quotas_stop_monitoring_collection(child)
            self.logical_quotas_stop_monitoring_collection(root)
            self.admin.assert_icommand(['irm', '-rf', root])

    def enable_rule_engine_plugin(self, config, namespace=None):
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

