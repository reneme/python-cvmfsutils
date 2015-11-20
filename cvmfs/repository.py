#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import dateutil.parser
import os
from datetime import datetime
from dateutil.tz import tzutc


import _common
from revision import Revision, RevisionIterator
from fetcher import RemoteFetcher, LocalFetcher
from manifest import Manifest
from history import History
from certificate import Certificate
from whitelist import Whitelist
from catalog import Catalog
from _exceptions import RepositoryNotFound, FileNotFoundInRepository, \
    RepositoryVerificationFailed, HistoryNotFound


class Repository(object):
    """ Wrapper around a CVMFS Repository representation """

    def __init__(self, fetcher):
        self._fetcher = fetcher
        self.opened_catalogs = {}
        self._read_manifest()
        self._try_to_get_last_replication_timestamp()
        self._try_to_get_replication_state()

    @classmethod
    def from_source(cls, source, cache_dir = None):
        if not source:
            raise Exception('source cannot be empty')
        return cls(Repository.__make_fetcher(source, cache_dir))

    @classmethod
    def with_custom_fetcher(cls, fetcher):
        return cls(fetcher)

    @staticmethod
    def __make_fetcher(source, cache_dir):
        if source.startswith("http://"):
            return RemoteFetcher(source, cache_dir)
        if os.path.exists(source):
            return LocalFetcher(source, cache_dir)
        if os.path.exists(os.path.join('/srv/cvmfs', source)):
            return LocalFetcher(os.path.join('/srv/cvmfs', source), cache_dir)
        else:
            raise RepositoryNotFound(source)

    def __iter__(self):
        return RevisionIterator(self)

    def _read_manifest(self):
        try:
            with self._fetcher.retrieve_raw_file(_common._MANIFEST_NAME) as manifest_file:
                self.manifest = Manifest(manifest_file)
            self.fqrn = self.manifest.repository_name
        except FileNotFoundInRepository, e:
            raise RepositoryNotFound(self._fetcher.source)


    @staticmethod
    def __read_timestamp(timestamp_string):
        local_ts = dateutil.parser.parse(timestamp_string,
                                         ignoretz=False,
                                         tzinfos=_common.TzInfos.get_tzinfos())
        return local_ts.astimezone(tzutc())

    def _try_to_get_last_replication_timestamp(self):
        try:
            with self._fetcher.retrieve_raw_file(_common._LAST_REPLICATION_NAME) as rf:
                timestamp = rf.readline()
                self.last_replication = self.__read_timestamp(timestamp)
            if not self.has_repository_type():
                self.type = 'stratum1'
        except FileNotFoundInRepository, e:
            self.last_replication = datetime.fromtimestamp(0, tz=tzutc())

    def _try_to_get_replication_state(self):
        self.replicating = False
        try:
            with self._fetcher.retrieve_raw_file(_common._REPLICATING_NAME) as rf:
                timestamp = rf.readline()
                self.replicating = True
                self.replicating_since = self.__read_timestamp(timestamp)
        except FileNotFoundInRepository, e:
            pass

    def verify(self, public_key_path):
        """ Use a public key to verify the repository's authenticity """
        whitelist   = self.retrieve_whitelist()
        certificate = self.retrieve_certificate()
        if not whitelist.verify_signature(public_key_path):
            raise RepositoryVerificationFailed("Public key doesn't fit", self)
        if whitelist.expired():
            raise RepositoryVerificationFailed("Whitelist expired", self)
        if not whitelist.contains(certificate):
            raise RepositoryVerificationFailed("Certificate not in whitelist", self)
        if not self.manifest.verify_signature(certificate):
            raise RepositoryVerificationFailed("Certificate doesn't fit", self)
        return True

    def has_repository_type(self):
        return hasattr(self, 'type') and self.type != 'unknown'

    def has_history(self):
        return self.manifest.has_history()

    def retrieve_history(self):
        if not self.has_history():
            raise HistoryNotFound(self)
        history_db = self.retrieve_object(self.manifest.history_database, 'H')
        return History(history_db)

    def get_current_revision(self):
        return self._get_revision_by_number(self.manifest.revision)

    def get_revision(self, revision_data):
        if isinstance(revision_data, int):
            return self._get_revision_by_number(revision_data)
        elif isinstance(revision_data, str):
            return self._get_revision_by_tag(revision_data)

    def _get_revision_by_number(self, revision):
        history = self.retrieve_history()
        revision_tag = history.get_tag_by_revision(revision)
        return Revision(self, revision_tag)

    def _get_revision_by_tag(self, tag_name):
        history = self.retrieve_history()
        revision_tag = history.get_tag_by_name(tag_name)
        return Revision(self, revision_tag)

    def retrieve_whitelist(self):
        """ retrieve and parse the .cvmfswhitelist file from the repository """
        whitelist = self._fetcher.retrieve_raw_file(_common._WHITELIST_NAME)
        return Whitelist(whitelist)

    def retrieve_certificate(self):
        """ retrieve the repository's certificate file """
        certificate = self.retrieve_object(self.manifest.certificate, 'X')
        return Certificate(certificate)

    def retrieve_catalog(self, catalog_hash):
        """ Download and open a catalog from the repository """
        if catalog_hash in self.opened_catalogs:
            return self.opened_catalogs[catalog_hash]
        return self._retrieve_and_open_catalog(catalog_hash)

    def retrieve_object(self, object_hash, hash_suffix = ''):
        """ Retrieves an object from the content addressable storage """
        path = "data/" + object_hash[:2] + "/" + object_hash[2:] + hash_suffix
        return self._fetcher.retrieve_file(path)

    def close_catalog(self, catalog):
        try:
            del self.opened_catalogs[catalog.hash]
        except KeyError, e:
            print "not found:" , catalog.hash

    def _retrieve_and_open_catalog(self, catalog_hash):
        catalog_file = self.retrieve_object(catalog_hash, 'C')
        new_catalog = Catalog(catalog_file, catalog_hash)
        self.opened_catalogs[catalog_hash] = new_catalog
        return new_catalog


def all_local():
    d = _common._REPO_CONFIG_PATH
    if not os.path.isdir(d):
        raise _common.CvmfsNotInstalled
    return [ Repository.from_source(repo) for repo in os.listdir(d) if os.path.isdir(os.path.join(d, repo)) ]


def all_local_stratum0():
    return [ repo for repo in all_local() if repo.type == 'stratum0' ]


def open_repository(repository_path, **kwargs):
    """ wrapper function accessing a repository by URL, local FQRN or path """
    cache_dir  = kwargs['cache_dir']  if 'cache_dir'  in kwargs else None
    public_key = kwargs['public_key'] if 'public_key' in kwargs else None
    repo = Repository.from_source(repository_path, cache_dir)
    if public_key:
        repo.verify(public_key)
    return repo
