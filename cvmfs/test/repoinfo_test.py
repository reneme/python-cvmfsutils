#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import unittest

import cvmfs
from mock_repository import MockRepository


class TestRepoInfo(unittest.TestCase):
    def setUp(self):
        # the JSON repository info data is contained in the MockRepository
        # see 'aux/make_mock_repo.sh' for details
        self.mock_repo = MockRepository()

    def tearDown(self):
        del self.mock_repo


    def test_has_repoinfo(self):
        repo = cvmfs.open_repository(self.mock_repo.dir)
        self.assertTrue(isinstance(repo, cvmfs.Repository))
        self.assertEqual(self.mock_repo.repo_name, repo.manifest.repository_name)
        self.assertTrue(repo.manifest.has_repoinfo())


    def test_retrieve_repoinfo(self):
        repo = cvmfs.open_repository(self.mock_repo.dir)
        self.assertTrue(isinstance(repo, cvmfs.Repository))
        repoinfo = repo.retrieve_repoinfo()
        self.assertTrue(isinstance(repoinfo, cvmfs.RepoInfo))
        self.assertEqual(repo.manifest.repository_name, repoinfo.fqrn)


    def test_read_basic_repoinfo(self):
        repo = cvmfs.open_repository(self.mock_repo.dir)
        self.assertTrue(isinstance(repo, cvmfs.Repository))
        repoinfo = repo.retrieve_repoinfo()
        self.assertTrue(isinstance(repoinfo, cvmfs.RepoInfo))
        self.assertEqual("Rene Meusel",               repoinfo.administrator)
        self.assertEqual("dont.send.me.spam@cern.ch", repoinfo.email)
        self.assertEqual("CERN",                      repoinfo.organisation)
        self.assertEqual("This is a test repository", repoinfo.description)
        self.assertEqual(3, len(repoinfo.stratum1s))


    def test_read_stratum1_list(self):
        repo = cvmfs.open_repository(self.mock_repo.dir)
        self.assertTrue(isinstance(repo, cvmfs.Repository))
        repoinfo = repo.retrieve_repoinfo()
        self.assertTrue(isinstance(repoinfo, cvmfs.RepoInfo))
        self.assertEqual(3, len(repoinfo.stratum1s))
        stratum1s = [
            "http://cvmfs-stratum-one.cern.ch/cvmfs/test.cern.ch",
            "http://cernvmfs.gridpp.rl.ac.uk/cvmfs/test.cern.ch",
            "http://cvmfs.racf.bnl.gov/cvmfs/test.cern.ch"
        ]
        for s1 in stratum1s:
            self.assertTrue(s1 in repoinfo.stratum1s)


    def test_read_custom_data(self):
        repo = cvmfs.open_repository(self.mock_repo.dir)
        self.assertTrue(isinstance(repo, cvmfs.Repository))
        repoinfo = repo.retrieve_repoinfo()
        self.assertTrue(isinstance(repoinfo, cvmfs.RepoInfo))
        self.assertEqual("This is",        repoinfo.json_data["custom"]["foo"])
        self.assertEqual("arbitrary data", repoinfo.json_data["custom"]["bar"])
