from __future__ import print_function

import os
import sys
import shutil

from time import sleep

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from . import session
from .. import test
from .. import lib
from .. import paths
from ..configuration import IrodsConfig

class Test_Rule_Engine_Plugin_Update_Collection_MTime(session.make_sessions_mixin([('otherrods', 'rods')], []), unittest.TestCase):

    def setUp(self):
        super(Test_Rule_Engine_Plugin_Update_Collection_MTime, self).setUp()
        self.admin = self.admin_sessions[0]

    def tearDown(self):
        super(Test_Rule_Engine_Plugin_Update_Collection_MTime, self).tearDown()

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_update_collection_mtime(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_mtime_rep(config)
            self.run_collection_pep_tests()
            self.run_data_object_pep_tests()
            self.run_irule_tests(config.server_config['plugin_configuration']['rule_engines'])

    def enable_mtime_rep(self, config):
        # Add the MTime REP to the beginning of the rule engines list.
        config.server_config['plugin_configuration']['rule_engines'].insert(0, {
            'instance_name': 'irods_rule_engine_plugin-update_collection_mtime-instance',
            'plugin_name': 'irods_rule_engine_plugin-update_collection_mtime',
            'plugin_specific_configuration': {}
        })

        # Save the changes.
        lib.update_json_file_from_dict(config.server_config_path, config.server_config)

    def run_collection_pep_tests(self):
        collection = 'rep_mtime_col.d'
        copied_collection = 'rep_mtime_col.copied.d'

        self.run_create_collection_test(collection)
        self.run_copy_collection_test(collection, copied_collection)
        self.run_remove_collection_test(collection)

    def run_data_object_pep_tests(self):
        filename = 'rep_mtime_file.txt'
        new_filename = 'rep_mtime_file.renamed.txt'
        copied_filename = 'rep_mtime_file.copied.txt'

        self.run_put_data_object_test(filename)
        self.run_rename_data_object_test(filename, new_filename)
        self.run_copy_data_object_test(new_filename, copied_filename)
        self.run_remove_data_object_test(new_filename)

        os.remove(filename)

    def run_irule_tests(self, rule_engines):
        native_rep = 'irods_rule_engine_plugin-irods_rule_language'

        # Run this test only if the NREP is configured.
        for re in rule_engines:
            if re['plugin_name'] == native_rep:
                msg = 'THIS SHOULD NOT PRODUCE AN ERROR!'
                cmd = 'irule -r {0}-instance \'writeLine("stdout", "{1}")\' null ruleExecOut'.format(native_rep, msg)
                self.admin.assert_icommand(cmd, 'STDOUT', msg)
                break

    def run_create_collection_test(self, collection):
        self.run_test(lambda: self.admin.run_icommand(['imkdir', collection]))

    def run_copy_collection_test(self, src_collection, dst_collection):
        self.run_test(lambda: self.admin.run_icommand(['icp', src_collection, dst_collection]))

    def run_remove_collection_test(self, collection):
        self.run_test(lambda: self.admin.run_icommand(['irmdir', collection]))

    def run_put_data_object_test(self, filename):
        lib.make_file(filename, 1)
        self.run_test(lambda: self.admin.run_icommand(['iput', filename]))

    def run_rename_data_object_test(self, filename, new_filename):
        self.run_test(lambda: self.admin.run_icommand(['imv', filename, new_filename]))

    def run_copy_data_object_test(self, src_filename, dst_filename):
        self.run_test(lambda: self.admin.run_icommand(['icp', src_filename, dst_filename]))

    def run_remove_data_object_test(self, filename):
        self.run_test(lambda: self.admin.run_icommand(['irm', '-f', filename]))

    def run_test(self, trigger_mtime_update_func):
        old_mtime = self.get_mtime(self.admin.session_collection)
        sleep(2) # Guarantees that the following operation produces a different mtime.
        trigger_mtime_update_func()
        self.assertTrue(self.get_mtime(self.admin.session_collection) != old_mtime)

    def get_mtime(self, coll_path):
        mtime, ec, rc = self.admin.run_icommand('iquest %s "select COLL_MODIFY_TIME where COLL_NAME = \'{0}\'"'.format(coll_path))
        return int(mtime)

