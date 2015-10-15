#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import abc
import os
import requests
import zlib

import cvmfs
from _exceptions import *
from cache import DummyCache, DiskCache

class Fetcher(object):
    """ Abstract wrapper around a Fetcher """

    __metadata__ = abc.ABCMeta

    def __init__(self, source, cache_dir = None):
        self.__cache = DiskCache(cache_dir) if cache_dir else DummyCache()
        self.source = source

    def _make_file_uri(self, file_name):
        return os.path.join(self.source, file_name)

    def get_cache_path(self):
        if self.__cache:
            return self.__cache.get_cache_path()

    def retrieve_file(self, file_name):
        """
        Method to retrieve a file from the cache if exists, or from
        the repository if it doesn't. In case it has to be retrieved from
        the repository it will also be decompressed before being stored in
        the cache
        :param file_name: name of the file in the repository
        :return: a file read-only file object that represents the cached file
        """
        return self._retrieve(file_name, self._retrieve_file)

    def retrieve_raw_file(self, file_name):
        """
        Method to retrieve a file from the cache if exists, or from
        the repository if it doesn't. In case it has to be retrieved from
        the repository it won't be decompressed
        :param file_name: name of the file in the repository
        :return: a file read-only file object that represents the cached file
        """
        return self._retrieve(file_name, self._retrieve_raw_file)

    def _retrieve(self, file_name, retrieve_fn):
        cached_file_ro = self.__cache.get(file_name)
        if cached_file_ro:
            return cached_file_ro

        cached_file_rw = self.__cache.transaction(file_name)
        retrieve_fn(file_name, cached_file_rw)
        return self.__cache.commit(cached_file_rw)


    @abc.abstractmethod
    def _retrieve_file(self, file_name, cached_file):
        """ Abstract method to retrieve a file from the repository """
        pass

    @abc.abstractmethod
    def _retrieve_raw_file(self, file_name, cached_file):
        """ Abstract method to retrieve a raw file from the repository """
        pass


class LocalFetcher(Fetcher):
    """ Retrieves files only from the local cache """

    def __init__(self, local_repo, cache_dir = None):
        super(LocalFetcher, self).__init__(local_repo, cache_dir)

    def _retrieve_file(self, file_name, cached_file):
        full_path = self._make_file_uri(file_name)
        if os.path.exists(full_path):
            compressed_file = open(full_path, 'r')
            decompressed_content = zlib.decompress(compressed_file.read())
            compressed_file.close()
            cached_file.write(decompressed_content)
        else:
            raise FileNotFoundInRepository(file_name)

    def _retrieve_raw_file(self, file_name, cached_file):
        """ Retrieves the file directly from the source """
        full_path = self._make_file_uri(file_name)
        if os.path.exists(full_path):
            raw_file = open(full_path, 'rb')
            cached_file.write(raw_file.read())
            raw_file.close()
        else:
            raise FileNotFoundInRepository(file_name)


class RemoteFetcher(Fetcher):
    """ Retrieves files from the local cache if found, and from
    remote otherwise
    """

    def __init__(self, repo_url, cache_dir = None):
        super(RemoteFetcher, self).__init__(repo_url, cache_dir)
        self._user_agent      = cvmfs.__package_name__ + "/" + cvmfs.__version__
        self._default_headers = { 'User-Agent': self._user_agent }

    def _download_content_and_store(self, cached_file, file_url):
        response = requests.get(file_url, stream=True,
                                          headers=self._default_headers)
        if response.status_code != requests.codes.ok:
            raise FileNotFoundInRepository(file_url)
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                cached_file.write(chunk)

    def _download_content_and_decompress(self, cached_file, file_url):
        response = requests.get(file_url, stream=False,
                                          headers=self._default_headers)
        if response.status_code != requests.codes.ok:
            raise FileNotFoundInRepository(file_url)
        decompressed_content = zlib.decompress(response.content)
        cached_file.write(decompressed_content)

    def _retrieve_file(self, file_name, cached_file):
        file_url = self._make_file_uri(file_name)
        self._download_content_and_decompress(cached_file, file_url)

    def _retrieve_raw_file(self, file_name, cached_file):
        file_url = self._make_file_uri(file_name)
        self._download_content_and_store(cached_file, file_url)
