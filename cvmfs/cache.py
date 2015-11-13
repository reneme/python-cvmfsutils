#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import abc
import os
import tempfile

import cvmfs
import _common
from _exceptions import *

class CacheNotFoundException(Exception):
    def __init__(self, path):
        super(Exception, self).__init__("Couldn't initialize the cache in \' "
                                        + str(path) + "\' does not exist")

class Cache(object):
    """ Abstract base class for a caching strategy """

    """ Try to get an object from the cache
        :file_name  name of the object to be retrieved
        :return     a file object of the cached object or None if not found
    """
    @abc.abstractmethod
    def get(self, file_name):
        pass

    """ Open a transaction to accomodate a new object in the cache
        :file_name  name of the object to be stored in the cache
        :return     a writable file object to a temporary storage location
    """
    @abc.abstractmethod
    def transaction(self, file_name):
        pass

    """ Commit a filled file object obtained via transaction() into the cache
        :resource   a file object obtained by transaction() and filled with data
        :return     a file object to the committed object
    """
    @abc.abstractmethod
    def commit(self, resource):
        pass


class DummyCache(Cache):
    """ A dummy cache uses temporary storage without actual cache logic """

    def get(self, file_name):
        return None

    def transaction(self, file_name):
        return tempfile.NamedTemporaryFile("w+b")

    def commit(self, resource):
        resource.seek(0)
        return resource


class DiskCache(Cache):
    """ Maintains a fully functional and reusable disk cache """

    class TransactionFile(file):
        """ Wrapper around a writable file. The actual file will be renamed
        to a different location once it is closed
        """

        def __init__(self, name, tmp_dir):
            self.__final_destination_path = name
            temp_path = tempfile.mktemp(dir=tmp_dir, prefix='tmp.')
            super(DiskCache.TransactionFile, self).__init__(temp_path, 'w+b')

        def __del__(self):
            if not self.closed:
                self.close()

        def commit(self):
            super(DiskCache.TransactionFile, self).close()
            os.rename(self.name, self.__final_destination_path)
            return open(self.__final_destination_path, "rb")

    def __init__(self, cache_dir):
        if cache_dir and not os.path.exists(cache_dir):
            raise CacheNotFoundException(cache_dir)
        self._cache_dir = cache_dir
        self._create_cache_structure()
        self._cleanup_metadata()

    def _cleanup_metadata(self):
        metadata_file_list = [
            os.path.join(self._cache_dir, _common._MANIFEST_NAME),
            os.path.join(self._cache_dir, _common._LAST_REPLICATION_NAME),
            os.path.join(self._cache_dir, _common._REPLICATING_NAME),
            os.path.join(self._cache_dir, _common._WHITELIST_NAME)
        ]
        for metadata_file in metadata_file_list:
            try:
                os.remove(metadata_file)
            except OSError:
                pass

    def _create_dir(self, path):
        cache_full_path = os.path.join(self._cache_dir, path)
        if not os.path.exists(cache_full_path):
            os.mkdir(cache_full_path, 0755)

    def _create_cache_structure(self):
        self._create_dir('data')
        for i in range(0x00, 0xff + 1):
            new_folder = '{0:#0{1}x}'.format(i, 4)[2:]
            self._create_dir(os.path.join('data', new_folder))
        self._create_dir(os.path.join('data', 'txn'))

    def get_transaction_dir(self):
        return os.path.join(self._cache_dir, 'data', 'txn')

    def get_cache_path(self):
        return str(self._cache_dir)

    def transaction(self, file_name):
        full_path = os.path.join(self._cache_dir, file_name)
        tmp_dir = self.get_transaction_dir()
        return DiskCache.TransactionFile(full_path, tmp_dir)

    def commit(self, resource):
        return resource.commit()

    def get(self, file_name):
        full_path = os.path.join(self._cache_dir, file_name)
        if os.path.exists(full_path):
            try:
                # if the file has been removed by now the open method
                # throws an exception
                return open(full_path, 'rb')
            except IOError, e:
                raise FileNotFoundInRepository(full_path)
        return None
