#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import os
import collections
from datetime import datetime
import dateutil.parser
from dateutil.tz import tzutc

import _common
import cvmfs
from manifest import Manifest
from catalog import Catalog
from history import History
from whitelist import Whitelist
from certificate import Certificate
from fetcher import RemoteFetcher, LocalFetcher
from _exceptions import *


class RepositoryIterator(object):
    """ Iterates through all directory entries in a whole Repository """

    class _CatalogIterator:
        def __init__(self, catalog):
            self.catalog          = catalog
            self.catalog_iterator = catalog.__iter__()


    def __init__(self, repository, catalog_hash=None):
        self.repository    = repository
        self.catalog_stack = collections.deque()
        if catalog_hash is None:
            catalog = repository.retrieve_root_catalog()
        else:
            catalog = repository.retrieve_catalog(catalog_hash)
        self._push_catalog(catalog)


    def __iter__(self):
        return self


    def next(self):
        full_path, dirent = self._get_next_dirent()
        if dirent.is_nested_catalog_mountpoint():
            self._fetch_and_push_catalog(full_path)
            return self.next() # same directory entry is also in nested catalog
        return full_path, dirent


    def _get_next_dirent(self):
        try:
            return self._get_current_catalog().catalog_iterator.next()
        except StopIteration, e:
            self._pop_catalog()
            if not self._has_more():
                raise StopIteration()
            return self._get_next_dirent()


    def _fetch_and_push_catalog(self, catalog_mountpoint):
        current_catalog = self._get_current_catalog().catalog
        nested_ref      = current_catalog.find_nested_for_path(catalog_mountpoint)
        if not nested_ref:
            raise NestedCatalogNotFound(self.repository)
        new_catalog     = nested_ref.retrieve_from(self.repository)
        self._push_catalog(new_catalog)


    def _has_more(self):
        return len(self.catalog_stack) > 0


    def _push_catalog(self, catalog):
        catalog_iterator = self._CatalogIterator(catalog)
        self.catalog_stack.append(catalog_iterator)

    def _get_current_catalog(self):
        return self.catalog_stack[-1]

    def _pop_catalog(self):
        return self.catalog_stack.pop()


class CatalogTreeIterator(object):
    class _CatalogWrapper:
        def __init__(self, repository):
            self.repository        = repository
            self.catalog           = None
            self.catalog_reference = None

        def get_catalog(self):
            if self.catalog is None:
                self.catalog = self.catalog_reference.retrieve_from(self.repository)
            return self.catalog

    def __init__(self, repository, root_catalog):
        if not root_catalog:
            root_catalog = repository.retrieve_root_catalog()
        self.repository    = repository
        self.catalog_stack = collections.deque()
        wrapper            = self._CatalogWrapper(self.repository)
        wrapper.catalog    = root_catalog
        self._push_catalog_wrapper(wrapper)

    def __iter__(self):
        return self

    def next(self):
        if not self._has_more():
            raise StopIteration()
        catalog = self._pop_catalog()
        self._push_nested_catalogs(catalog)
        return catalog

    def _has_more(self):
        return len(self.catalog_stack) > 0

    def _push_nested_catalogs(self, catalog):
        for nested_reference in catalog.list_nested():
            wrapper = self._CatalogWrapper(self.repository)
            wrapper.catalog_reference = nested_reference
            self._push_catalog_wrapper(wrapper)

    def _push_catalog_wrapper(self, catalog):
        self.catalog_stack.append(catalog)

    def _pop_catalog(self):
        wrapper = self.catalog_stack.pop()
        return wrapper.get_catalog()



class Repository(object):
    """ Wrapper around a CVMFS Repository representation """

    def __init__(self, fetcher):
        self._fetcher = fetcher
        self._opened_catalogs = {}
        self._read_manifest()
        self._try_to_get_last_replication_timestamp()
        self._try_to_get_replication_state()
        self._root_catalog_hash = self.manifest.root_catalog

    @classmethod
    def from_source(cls, source, cache_dir = None):
        if not source:
            raise Exception('source cannot be empty')
        return cls(Repository.__make_fetcher(source, cache_dir))

    @classmethod
    def with_custom_fetcher(cls, fetcher):
        return cls(fetcher)


    @classmethod
    def __make_fetcher(cls, source, cache_dir):
        if source.startswith("http://"):
            return RemoteFetcher(source, cache_dir)
        if os.path.exists(source):
            return LocalFetcher(source, cache_dir)
        if os.path.exists(os.path.join('/srv/cvmfs', source)):
            return LocalFetcher(os.path.join('/srv/cvmfs', source), cache_dir)
        else:
            raise RepositoryNotFound(source)


    def __iter__(self):
        return RepositoryIterator(self)


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


    def catalogs(self, root_catalog = None):
        return CatalogTreeIterator(self, root_catalog)


    def has_repository_type(self):
        return hasattr(self, 'type') and self.type != 'unknown'


    def has_history(self):
        return self.manifest.has_history()


    def retrieve_history(self):
        if not self.has_history():
            raise HistoryNotFound(self)
        history_db = self.retrieve_object(self.manifest.history_database, 'H')
        return History(history_db)

    def switch_revision(self, revision):
        history = self.retrieve_history()
        revision_tag = history.get_tag_by_revision(revision)
        self._root_catalog_hash = revision_tag.hash

    def switch_tag(self, tag_name):
        history = self.retrieve_history()
        revision_tag = history.get_tag_by_name(tag_name)
        self._root_catalog_hash = revision_tag.hash

    def retrieve_whitelist(self):
        """ retrieve and parse the .cvmfswhitelist file from the repository """
        whitelist = self._fetcher.retrieve_raw_file(_common._WHITELIST_NAME)
        return Whitelist(whitelist)


    def retrieve_certificate(self):
        """ retrieve the repository's certificate file """
        certificate = self.retrieve_object(self.manifest.certificate, 'X')
        return Certificate(certificate)


    def retrieve_object(self, object_hash, hash_suffix = ''):
        """ Retrieves an object from the content addressable storage """
        path = "data/" + object_hash[:2] + "/" + object_hash[2:] + hash_suffix
        return self._fetcher.retrieve_file(path)


    def retrieve_root_catalog(self):
        return self.retrieve_catalog(self._root_catalog_hash)


    def retrieve_catalog_for_path(self, needle_path):
        """ Recursively walk down the Catalogs and find the best fit for a path """
        clg = self.retrieve_root_catalog()
        while True:
            new_nested_reference = clg.find_nested_for_path(needle_path)
            if new_nested_reference is None:
                break
            nested_reference = new_nested_reference
            clg = self.retrieve_catalog(nested_reference.hash)
        return clg


    def close_catalog(self, catalog):
        try:
            del self._opened_catalogs[catalog.hash]
        except KeyError, e:
            print "not found:" , catalog.hash
            pass


    def retrieve_catalog(self, catalog_hash):
        """ Download and open a catalog from the repository """
        if catalog_hash in self._opened_catalogs:
            return self._opened_catalogs[catalog_hash]
        return self._retrieve_and_open_catalog(catalog_hash)

    def _retrieve_and_open_catalog(self, catalog_hash):
        catalog_file = self.retrieve_object(catalog_hash, 'C')
        new_catalog = Catalog(catalog_file, catalog_hash)
        self._opened_catalogs[catalog_hash] = new_catalog
        return new_catalog

    def _lookup_path(self, path):
        """
        Lookups in all existing catalogs for this path's best fit
        :param path: path to search for
        :return: the DirectoryEntry that corresponds to the given path if
        it is found in the already loaded catalogs, or None otherwise
        """
        if path == '/':
            path = ''
        best_fit = self._opened_catalogs_for_path(path)
        result = best_fit.find_directory_entry(path)
        while result is None:
            best_nested = best_fit.find_best_child_for_path(path)
            if best_nested is None:
                break
            best_fit = best_nested.retrieve_from(self)
            result = best_fit.find_directory_entry(path)
        return result

    def lookup(self, path):
        """
        Lookups up in the repository for a given path
        :param path: path to search for
        follow it and return its final representation
        :return: the DirectoryEntry that corresponds to the given path
        """
        return self._lookup_path(path)

    def _opened_catalogs_for_path(self, path):
        """
        Gets the closest already opened catalog for a given path
        :param path: the path to search for
        :return: the closest opened catalog for a given path
        """
        best_catalog = self.retrieve_root_catalog()
        max_length = 0
        for catalog in self._opened_catalogs.values():
            curr_length = len(catalog.root_prefix) \
                if path.find(catalog.root_prefix) == 0 else 0
            if curr_length > max_length:
                best_catalog = catalog
                max_length = len(best_catalog.root_prefix)
        return best_catalog

    def list_directory(self, path):
        """
        List all the entries in a directory
        :param path: path of the directory
        :return: a list of DirectoryEntry representing all the entries for the
        given directory, or None if such a directory does not exist
        """
        dirent = self.lookup(path)
        if dirent and dirent.is_directory():
            best_fit = self.retrieve_catalog_for_path(path)
            return best_fit.list_directory(path)


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
