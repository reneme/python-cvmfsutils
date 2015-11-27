#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import unittest

import cvmfs
from file_sandbox    import FileSandbox
from mock_repository import MockRepository


class TestRepositoryWrapper(unittest.TestCase):
    def setUp(self):
        self.sandbox = FileSandbox("py_ut_repo_")
        self.mock_repo = MockRepository()

        self.cern_public_key = '\n'.join([
            '-----BEGIN PUBLIC KEY-----',
            'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAukBusmYyFW8KJxVMmeCj',
            'N7vcU1mERMpDhPTa5PgFROSViiwbUsbtpP9CvfxB/KU1gggdbtWOTZVTQqA3b+p8',
            'g5Vve3/rdnN5ZEquxeEfIG6iEZta9Zei5mZMeuK+DPdyjtvN1wP0982ppbZzKRBu',
            'BbzR4YdrwwWXXNZH65zZuUISDJB4my4XRoVclrN5aGVz4PjmIZFlOJ+ytKsMlegW',
            'SNDwZO9z/YtBFil/Ca8FJhRPFMKdvxK+ezgq+OQWAerVNX7fArMC+4Ya5pF3ASr6',
            '3mlvIsBpejCUBygV4N2pxIcPJu/ZDaikmVvdPTNOTZlIFMf4zIP/YHegQSJmOyVp',
            'HQIDAQAB',
            '-----END PUBLIC KEY-----'
            ''
        ])
        pubkey = self.sandbox.write_to_temporary(self.cern_public_key)
        self.public_key_file = pubkey

    def tearDown(self):
        del self.mock_repo


    def test_open_repository_http(self):
        self.mock_repo.serve_via_http()
        repo = cvmfs.open_repository(self.mock_repo.url)
        self.assertTrue(isinstance(repo, cvmfs.Repository))
        self.assertEqual(self.mock_repo.repo_name, repo.manifest.repository_name)


    def test_open_repository_local(self):
        repo = cvmfs.open_repository(self.mock_repo.dir)
        self.assertTrue(isinstance(repo, cvmfs.Repository))
        self.assertEqual(self.mock_repo.repo_name, repo.manifest.repository_name)


    def test_open_repository_verification(self):
        self.mock_repo.make_valid_whitelist()
        self.mock_repo.serve_via_http()
        repo1 = cvmfs.open_repository(self.mock_repo.url,
                                      public_key=self.mock_repo.public_key)
        self.assertTrue(isinstance(repo1, cvmfs.Repository))
        self.assertTrue(repo1.verify(self.mock_repo.public_key))
        self.assertEqual(self.mock_repo.repo_name, repo1.manifest.repository_name)

        repo2 = cvmfs.open_repository(self.mock_repo.dir,
                                      public_key=self.mock_repo.public_key)
        self.assertTrue(isinstance(repo2, cvmfs.Repository))
        self.assertTrue(repo2.verify(self.mock_repo.public_key))
        self.assertEqual(self.mock_repo.repo_name, repo2.manifest.repository_name)

        repo3 = cvmfs.open_repository(self.mock_repo.url)
        self.assertTrue(isinstance(repo3, cvmfs.Repository))
        self.assertTrue(repo3.verify(self.mock_repo.public_key))
        self.assertEqual(self.mock_repo.repo_name, repo3.manifest.repository_name)

        repo4 = cvmfs.open_repository(self.mock_repo.dir)
        self.assertTrue(isinstance(repo4, cvmfs.Repository))
        self.assertTrue(repo4.verify(self.mock_repo.public_key))
        self.assertEqual(self.mock_repo.repo_name, repo4.manifest.repository_name)


    def test_wrong_public_key(self):
        self.mock_repo.make_valid_whitelist()
        self.mock_repo.serve_via_http()
        self.assertRaises(cvmfs.RepositoryVerificationFailed,
                          cvmfs.open_repository,
                          self.mock_repo.url, public_key=self.public_key_file)
        self.assertRaises(cvmfs.RepositoryVerificationFailed,
                          cvmfs.open_repository,
                          self.mock_repo.dir, public_key=self.public_key_file)


    def test_expired_whitelist(self):
        self.mock_repo.make_expired_whitelist()
        self.mock_repo.serve_via_http()
        self.assertRaises(cvmfs.RepositoryVerificationFailed,
                          cvmfs.open_repository,
                          self.mock_repo.url, public_key=self.mock_repo.public_key)
        self.assertRaises(cvmfs.RepositoryVerificationFailed,
                          cvmfs.open_repository,
                          self.mock_repo.dir, public_key=self.mock_repo.public_key)


    def test_lookup(self):
        self.mock_repo.make_valid_whitelist()
        self.mock_repo.serve_via_http()
        repo = cvmfs.open_repository(self.mock_repo.url,
                                     public_key=self.mock_repo.public_key)
        rev = repo.get_current_revision()
        dirent = rev.lookup('/.cvmfsdirtab')
        self.assertIsNotNone(dirent)
        dirent = rev.lookup('/bar/4/foo')
        self.assertIsNotNone(dirent)
        dirent = rev.lookup('/bar/4/foobar')
        self.assertIsNone(dirent)
        # with trailing slash this time
        dirent1 = rev.lookup('/bar/4/foo/')
        self.assertIsNotNone(dirent1)
        dirent2 = rev.lookup('/bar/4/../4/foo/')
        self.assertIsNotNone(dirent2)
        self.assertEquals(dirent1.name, dirent2.name)


    def test_list(self):
        self.mock_repo.make_valid_whitelist()
        self.mock_repo.serve_via_http()
        repo = cvmfs.open_repository(self.mock_repo.url,
                                     public_key=self.mock_repo.public_key)
        rev = repo.get_current_revision()
        dirents = rev.list_directory('/')
        self.assertIsNotNone(dirents)
        self.assertEqual(3, len(dirents))
        dirents = rev.list_directory('/bar/3')
        self.assertIsNotNone(dirents)
        self.assertEqual(4, len(dirents))
        self.assertEquals('.cvmfscatalog', dirents[0].name)
        self.assertEquals('1', dirents[1].name)
        self.assertEquals('2', dirents[2].name)
        self.assertEquals('3', dirents[3].name)
        dirents = rev.list_directory('/bar/4/foo')
        self.assertIsNone(dirents)
        dirents = rev.list_directory('/fakedir')
        self.assertIsNone(dirents)
        # with trailing slash this time
        dirents = rev.list_directory('/bar/3/')
        self.assertIsNotNone(dirents)
        self.assertEqual(4, len(dirents))

    def test_revision(self):
        self.mock_repo.make_valid_whitelist()
        self.mock_repo.serve_via_http()
        repo = cvmfs.open_repository(self.mock_repo.url,
                                     public_key=self.mock_repo.public_key)
        rev3 = repo.get_current_revision()
        self.assertEqual(3, rev3.revision_number)
        dirent = rev3.lookup('/bar/3')
        self.assertIsNotNone(dirent)
        self.assertTrue(dirent.is_directory())

        rev1 = repo.get_revision(1)
        self.assertEqual(1, rev1.revision_number)
        dirent = rev1.lookup('/bar/3')
        self.assertIsNone(dirent)

    def test_catalog_lookup(self):
        self.mock_repo.make_valid_whitelist()
        self.mock_repo.serve_via_http()
        repo = cvmfs.open_repository(self.mock_repo.url,
                                     public_key=self.mock_repo.public_key)
        rev = repo.get_current_revision()
        for catalog in rev.catalogs():
            if catalog.root_prefix == '/bar/4':
                self.assertIsNone(catalog
                                  .find_nested_for_path('/bar/4/foobar'))
                self.assertIsNone(catalog
                                  .find_nested_for_path('/bar/4/foo'))
                break
