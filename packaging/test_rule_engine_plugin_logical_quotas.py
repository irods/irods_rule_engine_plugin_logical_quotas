from __future__ import print_function

import os
import sys
import shutil
import json
import subprocess
import textwrap

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from . import session
from .. import test
from .. import lib
from .. import paths
from ..configuration import IrodsConfig

admins = [('otherrods', 'rods'), ('anotherrods', 'rods')]
users  = [('alice', 'apass')]

class Test_Rule_Engine_Plugin_Logical_Quotas(session.make_sessions_mixin(admins, users), unittest.TestCase):

    def setUp(self):
        super(Test_Rule_Engine_Plugin_Logical_Quotas, self).setUp()
        self.admin1 = self.admin_sessions[0]
        self.admin2 = self.admin_sessions[1]
        self.user = self.user_sessions[0]

        count_data_objects = str('select count(distinct data_id) from R_DATA_MAIN d ' +
                                 'inner join R_COLL_MAIN c on d.coll_id = c.coll_id ' +
                                 'where coll_name like ?')

        self.admin1.assert_icommand(['iadmin', 'asq', count_data_objects,
                                    'logical_quotas_count_data_objects_recursive'])

        sum_data_object_sizes = str('select sum(t.data_size) from (' +
                                    'select data_id, data_size from R_DATA_MAIN d ' +
                                    'inner join R_COLL_MAIN c on d.coll_id = c.coll_id ' +
                                        'where coll_name like ? and data_is_dirty in (\'1\', \'4\') ' +
                                    'group by data_id, data_size) as t')

        self.admin1.assert_icommand(['iadmin', 'asq', sum_data_object_sizes,
                                    'logical_quotas_sum_data_object_sizes_recursive'])

    def tearDown(self):
        self.admin1.assert_icommand(['iadmin', 'rsq',
                                    'logical_quotas_sum_data_object_sizes_recursive'])

        self.admin1.assert_icommand(['iadmin', 'rsq',
                                    'logical_quotas_count_data_objects_recursive'])

        super(Test_Rule_Engine_Plugin_Logical_Quotas, self).tearDown()

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_control_rules(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # Given that most logical quotas specific commands are tested throughout
            # the test suite, only a subset will be tested here.

            sandbox = self.admin1.session_collection
            self.logical_quotas_start_monitoring_collection(sandbox)
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, '2')
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, '15')

            # Set the totals to incorrect values.
            self.admin1.assert_icommand(['imeta', 'set', '-C', sandbox, self.total_number_of_data_objects_attribute(), '100'])
            self.admin1.assert_icommand(['imeta', 'set', '-C', sandbox, self.total_size_in_bytes_attribute(), '200'])
            expected_number_of_objects = 100
            expected_size_in_bytes = 200
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Correct the totals.
            self.logical_quotas_count_total_number_of_data_objects(sandbox)
            self.logical_quotas_count_total_size_in_bytes(sandbox)
            expected_number_of_objects = 0
            expected_size_in_bytes = 0
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Set the totals to incorrect values.
            self.admin1.assert_icommand(['imeta', 'set', '-C', sandbox, self.total_number_of_data_objects_attribute(), '100'])
            self.admin1.assert_icommand(['imeta', 'set', '-C', sandbox, self.total_size_in_bytes_attribute(), '200'])
            expected_number_of_objects = 100
            expected_size_in_bytes = 200
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Correct the totals.
            self.logical_quotas_recalculate_totals(sandbox)
            expected_number_of_objects = 0
            expected_size_in_bytes = 0
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_incorrect_config(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            config.server_config['log_level']['rule_engine'] = 'trace'
            config.server_config['plugin_configuration']['rule_engines'].insert(0, {
                'instance_name': 'irods_rule_engine_plugin-logical_quotas-instance',
                'plugin_name': 'irods_rule_engine_plugin-logical_quotas',
                'plugin_specific_configuration': {
                    'namespace': self.logical_quotas_namespace(),
                    'metadata_attribute_names': {
                        'mum_numberata_objects': self.maximum_number_of_data_objects_attribute_name(),
                        'aximum_': self.maximum_size_in_bytes_attribute_name(),
                        'umber_of_data': self.total_number_of_data_objects_attribute_name(),
                        'total_size_in': self.total_size_in_bytes_attribute_name()
                    }
                }
            })
            lib.update_json_file_from_dict(config.server_config_path, config.server_config)

            filename = os.path.join(self.admin1.local_session_dir, 'foo.txt')
            lib.make_file(filename, 1, 'arbitrary')
            error_msg = 'Failed to find configuration for rule engine plugin instance [irods_rule_engine_plugin-logical_quotas-instance]'
            self.admin1.assert_icommand_fail(['iput', filename], 'STDOUT', [error_msg])
            os.remove(filename)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_put_data_object(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            sandbox = self.admin1.session_collection
            self.logical_quotas_start_monitoring_collection(sandbox)
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, '2')
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, '15')

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
            self.admin1.assert_icommand(['irm', '-f', 'f1.txt'])
            self.admin1.assert_icommand(['irm', '-f', 'f2.txt'])
            expected_number_of_objects = 0
            expected_size_in_bytes = 0
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            self.logical_quotas_stop_monitoring_collection(sandbox)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_put_collection(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            sandbox = self.admin1.session_collection
            self.logical_quotas_start_monitoring_collection(sandbox)
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, '1')

            dir_path = os.path.join(self.admin1.local_session_dir, 'coll.d')
            dir_name = os.path.basename(dir_path)
            file_size = 20
            self.make_directory(dir_path, ['f1.txt', 'f2.txt', 'f3.txt'], file_size)

            # Test: Exceed the max number of data objects.
            self.admin1.assert_icommand_fail(['iput', '-r', dir_path])
            expected_number_of_objects = 1
            expected_size_in_bytes = 20
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Test: Exceed the max number of bytes and show that the current totals are correct.
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, '100')
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, '1')
            self.admin1.assert_icommand_fail(['iput', '-rf', dir_path])
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Test: No quota violations on put of a non-empty collection.
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, '100')
            self.admin1.assert_icommand(['iput', '-rf', dir_path], 'STDOUT', ['pre-scan'])
            expected_number_of_objects = 3
            expected_size_in_bytes = 60
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Remove the collection.
            self.admin1.assert_icommand(['irm', '-rf', dir_name])
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

            col1 = self.admin1.session_collection
            self.logical_quotas_start_monitoring_collection(col1)
            self.logical_quotas_set_maximum_number_of_data_objects(col1, '4')
            self.logical_quotas_set_maximum_size_in_bytes(col1, '100')

            # "col2" is a child collection of "col1".
            col2 = os.path.join(col1, 'col.d')
            self.admin1.assert_icommand(['imkdir', col2])
            self.logical_quotas_start_monitoring_collection(col2)
            self.logical_quotas_set_maximum_number_of_data_objects(col2, '1')
            self.logical_quotas_set_maximum_size_in_bytes(col2, '100')

            # Put a data object into "col1".
            data_object = 'foo.txt'
            file_size = 1
            self.put_new_data_object(data_object, file_size)
            expected_number_of_objects = 1
            expected_size_in_bytes = file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

            # Copy data object into child collection.
            self.admin1.assert_icommand(['icp', data_object, col2])
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)

            # Trigger quota violation.
            self.admin1.assert_icommand_fail(['icp', data_object, os.path.join(col2, 'foo.txt.copy')])
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)

            # Verify that "col1"'s quota totals have also changed as a result of "col2"'s totals.
            expected_number_of_objects += 1
            expected_size_in_bytes += file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

            # Copy data object into current collection.
            self.admin1.assert_icommand(['icp', data_object, 'foo.txt.copy'])
            expected_number_of_objects += 1
            expected_size_in_bytes += file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_copy_collection(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # Create and put directory holding one file into iRODS.
            dir_path = os.path.join(self.admin1.local_session_dir, 'col.a')
            file_size = 1
            self.make_directory(dir_path, ['foo.txt'], file_size)
            self.admin1.assert_icommand(['iput', '-r', dir_path], 'STDOUT', ['pre-scan'])

            # Monitor first collection.
            col1 = os.path.join(self.admin1.session_collection, 'col.a')
            self.logical_quotas_start_monitoring_collection(col1)
            self.logical_quotas_set_maximum_number_of_data_objects(col1, '4')
            self.logical_quotas_set_maximum_size_in_bytes(col1, '100')
            expected_number_of_objects = 1
            expected_size_in_bytes = file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

            # Monitor sibling collection.
            col2 = os.path.join(self.admin1.session_collection, 'col.b')
            self.admin1.assert_icommand(['imkdir', col2])
            self.logical_quotas_start_monitoring_collection(col2)
            self.logical_quotas_set_maximum_number_of_data_objects(col2, '4')
            self.logical_quotas_set_maximum_size_in_bytes(col2, '100')

            # Copy "col1" into "col2".
            data_object = os.path.join(col1, 'foo.txt')
            col1_copy = os.path.join(col2, 'col.a')
            self.admin1.assert_icommand(['icp', '-r', col1, col1_copy])
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)

            # Copy "col2/col1" in-place.
            col1_copy_inplace = os.path.join(col2, 'col.a.inplace')
            self.admin1.assert_icommand(['icp', '-r', col1_copy, col1_copy_inplace])
            expected_number_of_objects += 1
            expected_size_in_bytes += file_size
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_rename_data_object(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            col1 = self.admin1.session_collection
            self.logical_quotas_start_monitoring_collection(col1)
            self.logical_quotas_set_maximum_number_of_data_objects(col1, '4')
            self.logical_quotas_set_maximum_size_in_bytes(col1, '100')

            # "col2" is a child collection of "col1".
            col2 = os.path.join(col1, 'col.d')
            self.admin1.assert_icommand(['imkdir', col2])
            self.logical_quotas_start_monitoring_collection(col2)
            self.logical_quotas_set_maximum_number_of_data_objects(col2, '1')
            self.logical_quotas_set_maximum_size_in_bytes(col2, '100')

            # "col3" is a sibling collection to "col2".
            col3 = os.path.join(col1, 'col.e')
            self.admin1.assert_icommand(['imkdir', col3])
            self.logical_quotas_start_monitoring_collection(col3)
            self.logical_quotas_set_maximum_number_of_data_objects(col3, '4')
            self.logical_quotas_set_maximum_size_in_bytes(col3, '100')

            # Put a data object into "col1".
            data_object = 'foo.txt'
            file_size = 1
            self.put_new_data_object(data_object, file_size)
            expected_number_of_objects = 1
            expected_size_in_bytes = file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)
            self.assert_quotas(col2, 0, 0)

            # Rename data object in-place.
            self.admin1.assert_icommand(['imv', data_object, 'foo.txt.renamed'])
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)
            self.assert_quotas(col2, 0, 0)
            data_object = 'foo.txt.renamed'

            # Move data object into child collection.
            self.admin1.assert_icommand(['imv', data_object, col2])
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)

            # Move data object back into parent collection.
            self.admin1.assert_icommand(['imv', os.path.join(col2, data_object), col1])
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)
            self.assert_quotas(col2, 0, 0)

            # Copy data object into child collection.
            self.admin1.assert_icommand(['icp', data_object, os.path.join(col2, 'foo.txt.copy')])
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)
            expected_number_of_objects += 1
            expected_size_in_bytes += file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

            # Trigger quota violation.
            self.admin1.assert_icommand_fail(['imv', data_object, col2])
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)
            self.assert_quotas(col2, expected_number_of_objects - 1, expected_size_in_bytes - 1)

            # Move all data objects to "col3".
            self.admin1.assert_icommand(['imv', data_object, col3])
            self.admin1.assert_icommand(['imv', os.path.join(col2, 'foo.txt.copy'), col3])
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)
            self.assert_quotas(col2, 0, 0)
            self.assert_quotas(col3, expected_number_of_objects, expected_size_in_bytes)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_rename_collection(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            col1 = os.path.join(self.admin1.session_collection, 'col.a')
            self.admin1.assert_icommand(['imkdir', col1])
            self.logical_quotas_start_monitoring_collection(col1)
            self.logical_quotas_set_maximum_number_of_data_objects(col1, '1')
            self.logical_quotas_set_maximum_size_in_bytes(col1, '100')

            # "col2" is a sibling collection to "col1".
            col2 = os.path.join(self.admin1.session_collection, 'col.b')
            self.admin1.assert_icommand(['imkdir', col2])
            self.logical_quotas_start_monitoring_collection(col2)
            self.logical_quotas_set_maximum_number_of_data_objects(col2, '1')
            self.logical_quotas_set_maximum_size_in_bytes(col2, '100')

            # Put a data object into "col1".
            data_object = os.path.join(col1, 'foo.txt')
            file_size = 1
            self.put_new_data_object(data_object, file_size)
            expected_number_of_objects = 1
            expected_size_in_bytes = file_size
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

            # Rename collection in-place.
            new_name = os.path.join(self.admin1.session_collection, 'col.a.renamed')
            self.admin1.assert_icommand(['imv', col1, new_name])
            col1 = new_name
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)

            # Move collection under sibling collection.
            src_col = col1
            col1 = os.path.join(col2, os.path.basename(col1))
            self.admin1.assert_icommand(['imv', src_col, col1])
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)
            self.assert_quotas(col2, expected_number_of_objects, expected_size_in_bytes)

            # Move collection back out of sibling collection.
            src_col = col1
            col1 = os.path.join(self.admin1.session_collection, os.path.basename(col1))
            self.admin1.assert_icommand(['imv', src_col, col1])
            self.assert_quotas(col1, expected_number_of_objects, expected_size_in_bytes)
            self.assert_quotas(col2, 0, 0)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_stream_data_object(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            sandbox = self.admin1.session_collection
            self.logical_quotas_start_monitoring_collection(sandbox)
            self.logical_quotas_set_maximum_number_of_data_objects(sandbox, '1')
            self.logical_quotas_set_maximum_size_in_bytes(sandbox, '15')

            data_object = 'foo.txt'

            # Create a new data object and write to it.
            # Write enough bytes so that the next write will trigger a violation.
            # This effectively disables all stream-based write operations.
            contents = 'We can write any number of bytes because the quotas have not been violated!'
            self.admin1.assert_icommand(['istream', 'write', data_object], input=contents)
            self.admin1.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])
            expected_number_of_objects = 1
            expected_size_in_bytes = len(contents)
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            # Trigger quota violation (data object count exceeded).
            self.admin1.assert_icommand_fail(['istream', 'write', 'bar'], input=contents)

            # Trigger quota violation (byte count exceeded).
            self.admin1.assert_icommand_fail(['istream', 'write', '-a', data_object], input='This will trigger a quota violation.')

            # Show that the quotas have been enforced.
            self.assert_quotas(sandbox, expected_number_of_objects, expected_size_in_bytes)

            self.logical_quotas_stop_monitoring_collection(sandbox)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_unset_maximum_quotas_when_not_tracking__issue_5(self):
        config = IrodsConfig()
        col = self.admin1.session_collection

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            self.logical_quotas_start_monitoring_collection(col)
            self.admin1.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', [self.total_number_of_data_objects_attribute(),
                                                                               self.total_size_in_bytes_attribute()])

            self.logical_quotas_set_maximum_number_of_data_objects(col, '100')
            self.logical_quotas_set_maximum_size_in_bytes(col, '10000')
            self.admin1.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', [self.total_number_of_data_objects_attribute(),
                                                                               self.total_size_in_bytes_attribute(),
                                                                               self.maximum_number_of_data_objects_attribute(),
                                                                               self.maximum_size_in_bytes_attribute()])

            self.logical_quotas_stop_monitoring_collection(col)
            self.admin1.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', [self.maximum_number_of_data_objects_attribute(),
                                                                               self.maximum_size_in_bytes_attribute()])

            self.logical_quotas_unset_maximum_number_of_data_objects(col)
            self.logical_quotas_unset_maximum_size_in_bytes(col)
            self.admin1.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', ['None'])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_violation_during_recursive_put__issue_6(self):
        config = IrodsConfig()
        col = self.admin1.session_collection

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            self.logical_quotas_start_monitoring_collection(col)
            self.logical_quotas_set_maximum_number_of_data_objects(col, '2')
            self.logical_quotas_set_maximum_size_in_bytes(col, '100')

            # Trigger quota violation and verify that an appropriate message is returned to the client.
            dir_path = os.path.join(self.admin1.local_session_dir, 'col.a')
            self.make_directory(dir_path, ['foo', 'bar', 'baz'], file_size=1)
            error_msg = 'Logical Quotas Policy Violation: Adding object exceeds maximum number of objects limit'
            self.admin1.assert_icommand_fail(['iput', '-r', dir_path], 'STDOUT', [error_msg])
            self.admin1.assert_icommand(['irm', '-rf', os.path.basename(dir_path)])

            # Trigger quota violation and verify that an appropriate message is returned to the client.
            dir_path = os.path.join(self.admin1.local_session_dir, 'col.b')
            self.make_directory(dir_path, ['foo', 'bar'], file_size=75)
            error_msg = 'Logical Quotas Policy Violation: Adding object exceeds maximum data size in byteslimit'
            self.admin1.assert_icommand_fail(['iput', '-r', dir_path], 'STDOUT', [error_msg])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_logical_quotas_get_collection_status__issue_28(self):
        config = IrodsConfig()
        col = self.admin1.session_collection

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            self.logical_quotas_start_monitoring_collection(col)
            self.logical_quotas_set_maximum_number_of_data_objects(col, '2')

            # Add a data object to the collection.
            data_object = 'foo'
            contents = 'hello, iRODS!'
            self.admin1.assert_icommand(['istream', 'write', data_object], input=contents)
            self.admin1.assert_icommand(['istream', 'read', data_object], 'STDOUT', [contents])

            # Fetch the quota status.
            expected_output = ['"{0}":"2"'.format(self.maximum_number_of_data_objects_attribute()),
                               '"{0}":"1"'.format(self.total_number_of_data_objects_attribute()),
                               '"{0}":"{1}"'.format(self.total_size_in_bytes_attribute(), len(contents))]

            op = json.dumps({'operation': 'logical_quotas_get_collection_status', 'collection': col})
            self.admin1.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', op, 'null', 'ruleExecOut'], 'STDOUT', expected_output)

            op = 'logical_quotas_get_collection_status(*col, *out)'
            op_args = '*col={0}%*out='.format(col)
            self.admin1.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', op, op_args, '*out'], 'STDOUT', expected_output)

            # Add another max quota and show that it appears in the output now.
            self.logical_quotas_set_maximum_size_in_bytes(col, '100')
            expected_output.append('"{0}":"100"'.format(self.maximum_size_in_bytes_attribute()))

            op = json.dumps({'operation': 'logical_quotas_get_collection_status', 'collection': col})
            self.admin1.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', op, 'null', 'ruleExecOut'], 'STDOUT', expected_output)

            op = 'logical_quotas_get_collection_status(*col, *out)'
            op_args = '*col={0}%*out='.format(col)
            self.admin1.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', op, op_args, '*out'], 'STDOUT', expected_output)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_adding_duplicate_attribute_names_with_different_values_or_units_is_not_allowed__issue_36(self):
        config = IrodsConfig()
        col = self.admin1.session_collection

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            self.logical_quotas_start_monitoring_collection(col)
            self.logical_quotas_set_maximum_number_of_data_objects(col, '10')
            self.logical_quotas_set_maximum_size_in_bytes(col, '1000')
            self.admin1.assert_icommand(['imeta', 'ls', '-C', col], 'STDOUT', [' ']) # Show the metadata.

            # Assert that the quota values are what we expect them to be.
            values = self.get_logical_quotas_attribute_values(col, include_max_values=True)
            self.assertEquals(values[self.maximum_number_of_data_objects_attribute()], 10)
            self.assertEquals(values[self.maximum_size_in_bytes_attribute()],          1000)
            self.assertEquals(values[self.total_number_of_data_objects_attribute()],   0)
            self.assertEquals(values[self.total_size_in_bytes_attribute()],            0)

            expected_output = ['-169000 SYS_NOT_ALLOWED']

            self.admin1.assert_icommand(['imeta', 'add', '-C', col, self.maximum_number_of_data_objects_attribute(), '5'], 'STDERR', expected_output)
            self.admin1.assert_icommand(['imeta', 'add', '-C', col, self.maximum_number_of_data_objects_attribute(), '10', 'data_objects'], 'STDERR', expected_output)

            self.admin1.assert_icommand(['imeta', 'add', '-C', col, self.maximum_size_in_bytes_attribute(), '2000'], 'STDERR', expected_output)
            self.admin1.assert_icommand(['imeta', 'add', '-C', col, self.maximum_size_in_bytes_attribute(), '2000', 'bytes'], 'STDERR', expected_output)

            self.admin1.assert_icommand(['imeta', 'add', '-C', col, self.total_number_of_data_objects_attribute(), '5'], 'STDERR', expected_output)
            self.admin1.assert_icommand(['imeta', 'add', '-C', col, self.total_number_of_data_objects_attribute(), '10', 'data_objects'], 'STDERR', expected_output)

            self.admin1.assert_icommand(['imeta', 'add', '-C', col, self.total_size_in_bytes_attribute(), '2000'], 'STDERR', expected_output)
            self.admin1.assert_icommand(['imeta', 'add', '-C', col, self.total_size_in_bytes_attribute(), '2000', 'bytes'], 'STDERR', expected_output)

            # Show that the quota values have not changed.
            values = self.get_logical_quotas_attribute_values(col, include_max_values=True)
            self.assertEquals(values[self.maximum_number_of_data_objects_attribute()], 10)
            self.assertEquals(values[self.maximum_size_in_bytes_attribute()],          1000)
            self.assertEquals(values[self.total_number_of_data_objects_attribute()],   0)
            self.assertEquals(values[self.total_size_in_bytes_attribute()],            0)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_executing_logical_quotas_rules_do_not_fail_when_group_permissions_are_present__issue_46(self):
        config = IrodsConfig()
        col = self.admin1.session_collection
        group = 'issue_46_group'

        try:
            self.admin1.assert_icommand(['iadmin', 'mkgroup', group])
            self.admin1.assert_icommand(['iadmin', 'atg', group, self.admin2.username])
            self.admin1.assert_icommand(['ichmod', 'own', group, col])

            with lib.file_backed_up(config.server_config_path):
                self.enable_rule_engine_plugin(config)

                # Show that the presence of group permissions no longer trip the plugin.
                # The only requirement is that the user invoking the rule must be an administrator.
                # The invoking user does not need permissions on the target collection.
                json_string = json.dumps({'operation': 'logical_quotas_start_monitoring_collection', 'collection': col})
                self.admin2.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', json_string, 'null', 'null'])

                json_string = json.dumps({'operation': 'logical_quotas_stop_monitoring_collection', 'collection': col})
                self.admin2.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', json_string, 'null', 'null'])

        finally:
            self.admin1.run_icommand(['ichmod', 'null', group, col])
            self.admin1.run_icommand(['iadmin', 'rfg', group, self.admin2.username])
            self.admin1.run_icommand(['iadmin', 'rmgroup', group])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_executing_logical_quotas_rules_require_that_the_user_be_an_administrator(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # Even though the user can use imeta to set the correct metadata for the plugin
            # to track information, the user is not allowed to use the plugin's rules to do so.
            # The Metadata Guard REP exists to cover the imeta use-case.
            json_string = json.dumps({'operation': 'logical_quotas_start_monitoring_collection', 'collection': self.user.session_collection})
            self.user.assert_icommand_fail(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', json_string, 'null', 'null'],
                                           'STDOUT', ['Logical Quotas Policy: Insufficient privileges'])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_recalculating_totals_produce_the_correct_results_in_a_multi_replica_scenario__issue_48(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            try:
                # Create a resource hierarchy containing two unixfilesystem resources
                # under a replication resource.
                repl_resc = 'repl_resc_issue_48'
                lib.create_replication_resource(repl_resc, self.admin1)

                ufs0_resc = 'ufs0_resc_issue_48'
                lib.create_ufs_resource(ufs0_resc, self.admin1)

                ufs1_resc = 'ufs1_resc_issue_48'
                lib.create_ufs_resource(ufs1_resc, self.admin1)

                lib.add_child_resource(repl_resc, ufs0_resc, self.admin1)
                lib.add_child_resource(repl_resc, ufs1_resc, self.admin1)

                # Create three data objects under the replication resource. Two in the
                # session collection and one in a sub-collection.
                col = self.admin1.session_collection
                self.logical_quotas_start_monitoring_collection(col)

                # Show that the plugin did not detect any data objects.
                self.assert_quotas(col, expected_number_of_objects=0, expected_size_in_bytes=0)

                data_object_1 = os.path.join(col, 'data_object_1')
                self.admin1.assert_icommand(['istream', 'write', '-R', repl_resc, data_object_1], input='12345')

                data_object_2 = os.path.join(col, 'data_object_2')
                self.admin1.assert_icommand(['istream', 'write', '-R', repl_resc, data_object_2], input='12345')

                other_col = os.path.join(col, 'other_collection')
                self.admin1.assert_icommand(['imkdir', other_col])

                data_object_3 = os.path.join(other_col, 'data_object_3')
                self.admin1.assert_icommand(['istream', 'write', '-R', repl_resc, data_object_3], input='12345')

                # Show that the plugin correctly recalculates the total number of data objects
                # and total size in bytes used by the data objects.
                self.logical_quotas_recalculate_totals(col)
                self.assert_quotas(col, expected_number_of_objects=3, expected_size_in_bytes=15)

            finally:
                for data_object in [data_object_1, data_object_2, data_object_3]:
                    self.admin1.run_icommand(['irm', '-f', data_object])

                lib.remove_child_resource(repl_resc, ufs0_resc, self.admin1)
                lib.remove_child_resource(repl_resc, ufs1_resc, self.admin1)

                for resc_name in [repl_resc, ufs0_resc, ufs1_resc]:
                    self.admin1.run_icommand(['iadmin', 'rmresc', resc_name])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_group_owned_collections_do_not_require_the_admin_to_manually_change_acls__issue_35(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            zone_name = self.admin1.zone_name
            group_name = 'testgroup_issue_36'
            group_home_col = os.path.join('/', zone_name, 'home', group_name)

            try:
                # Create a new empty group.
                # This will result in a new home collection being created for the group
                # with only the group having OWN permissions on it.
                self.admin1.assert_icommand(['iadmin', 'mkgroup', group_name])

                # Show that only the group has permissions on the group's home collection.
                _, out, _ = self.admin1.assert_icommand(['ils', '-A', group_home_col], 'STDOUT', [' '])
                self.assertIn('/{0}/home/{1}:'.format(zone_name, group_name), out)
                self.assertIn('        ACL - g:{0}#{1}:own'.format(group_name, zone_name), out)
                self.assertNotIn('        ACL - {0}#{1}:'.format(self.admin1.username, zone_name), out)

                # Show that the admin can invoke rules on the group's home collection without
                # needing to manually adjust ACLs on it.
                json_string = json.dumps({'operation': 'logical_quotas_start_monitoring_collection', 'collection': group_home_col})
                self.admin2.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', json_string, 'null', 'null'])

                self.admin1.assert_icommand(['imeta', 'ls', '-C', group_home_col], 'STDOUT', [
                    'attribute: irods::logical_quotas::total_size_in_bytes',
                    'attribute: irods::logical_quotas::total_number_of_data_objects'
                ])

                json_string = json.dumps({'operation': 'logical_quotas_stop_monitoring_collection', 'collection': group_home_col})
                self.admin2.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', json_string, 'null', 'null'])

            finally:
                self.admin1.run_icommand(['iadmin', 'rmgroup', group_name])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_plugin_supports_touch_api_PEPs__issue_62(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            col = self.user.session_collection
            self.logical_quotas_start_monitoring_collection(col)

            # Show that the REP hasn't detected any data objects in the monitored collection.
            self.assert_quotas(col, expected_number_of_objects=0, expected_size_in_bytes=0)

            # Show that after creating a new data object via itouch, the REP correctly increments
            # the data object count by one.
            self.user.assert_icommand(['itouch', 'foo'])
            self.assert_quotas(col, expected_number_of_objects=1, expected_size_in_bytes=0)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_plugin_does_not_return_an_error_when_exec_rule_is_invoked_by_non_administrators__issue_63(self):
        # This test verifies that regular users are allowed to invoke logical quotas rules indirectly.
        # That is, a non-admin user will not be blocked by the REP unless they try to invoke a logical
        # quotas rule via irule.

        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            col = self.user.session_collection
            self.logical_quotas_start_monitoring_collection(col)

            # Show that the REP hasn't detected any data objects in the monitored collection.
            self.assert_quotas(col, expected_number_of_objects=0, expected_size_in_bytes=0)

            # Show that non-admins can create data objects without issues.
            contents = 'it worked!'
            self.user.assert_icommand(['istream', 'write', 'foo'], input=contents)
            self.assert_quotas(col, expected_number_of_objects=1, expected_size_in_bytes=len(contents))

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_plugin_does_not_crash_on_unsupported_rule_text_executed_via_irule_F__issue_6831(self):
        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # Create a rule file that contains rule code that isn't supported by the plugin.
            # This originally caused the plugin to throw an exception which lead to the agent
            # crashing.
            rule_file = os.path.join(self.user.local_session_dir, 'issue_6831.r')
            with open(rule_file, 'w') as f:
                f.write(textwrap.dedent('''
                def syntax_not_supported_by_logical_quotas(rule_args, callback, rei):
                    callback.writeLine('serverLog', 'some data')

                INPUT null
                OUTPUT null
                '''))

            # Show that the plugin gracefully handles unsupported rule code.
            # The use of "-F" is important because it tests the code path that originally
            # caused an exception to be thrown.
            self.user.assert_icommand(['irule', '-F', rule_file])

            # Show that the plugin is still working.
            col = self.user.session_collection
            self.logical_quotas_start_monitoring_collection(col)

            # Show that the REP hasn't detected any data objects in the monitored collection.
            self.assert_quotas(col, expected_number_of_objects=0, expected_size_in_bytes=0)

            # Show that after creating a new data object via itouch, the REP correctly increments
            # the data object count by one.
            self.user.assert_icommand(['itouch', 'foo'])
            self.assert_quotas(col, expected_number_of_objects=1, expected_size_in_bytes=0)

    #
    # Utility Functions
    #

    def put_new_data_object(self, logical_path, size=0):
        filename = os.path.join(self.admin1.local_session_dir, os.path.basename(logical_path))
        lib.make_file(filename, size, 'arbitrary')
        self.admin1.assert_icommand(['iput', filename, logical_path])
        os.remove(filename)

    def put_new_data_object_exceeds_quota(self, logical_path, size=0):
        filename = os.path.basename(logical_path)
        lib.make_file(filename, size, 'arbitrary')
        self.admin1.assert_icommand_fail(['iput', filename, logical_path])
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
        utf8_query_result_string, ec, rc = self.admin1.run_icommand(['iquest', '%s=%s', query])

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
        self.admin1.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-logical_quotas-instance', json_string, 'null', 'null'])

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

    def logical_quotas_count_total_number_of_data_objects(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_count_total_number_of_data_objects',
            'collection': collection
        }))

    def logical_quotas_unset_total_number_of_data_objects(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_unset_total_number_of_data_objects',
            'collection': collection
        }))

    def logical_quotas_count_total_size_in_bytes(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_count_total_size_in_bytes',
            'collection': collection
        }))

    def logical_quotas_unset_total_size_in_bytes(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_unset_total_size_in_bytes',
            'collection': collection
        }))

    def logical_quotas_recalculate_totals(self, collection):
        self.exec_logical_quotas_operation(json.dumps({
            'operation': 'logical_quotas_recalculate_totals',
            'collection': collection
        }))

