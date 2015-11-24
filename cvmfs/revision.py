#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by José Molina
This file is part of the CernVM File System auxiliary tools.
"""

import collections

from _exceptions import NestedCatalogNotFound


class RevisionIterator(object):
    """ Iterates through all directory entries in a whole Repository """

    class _CatalogIterator:
        def __init__(self, catalog):
            self.catalog          = catalog
            self.catalog_iterator = catalog.__iter__()

    def __init__(self, revision, catalog_hash=None):
        self.revision    = revision
        self.catalog_stack = collections.deque()
        if catalog_hash is None:
            catalog = revision.retrieve_root_catalog()
        else:
            catalog = revision.retrieve_catalog(catalog_hash)
        self._push_catalog(catalog)

    def __iter__(self):
        return self

    def next(self):
        full_path, dirent = self._get_next_dirent()
        if dirent.is_nested_catalog_mountpoint():
            self._fetch_and_push_catalog(full_path)
            return self.next()  # same directory entry is also in nested catalog
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
        nested_ref = current_catalog.find_nested_for_path(catalog_mountpoint)
        if not nested_ref:
            raise NestedCatalogNotFound(self.revision.repository)
        new_catalog     = nested_ref.retrieve_from(self.revision.repository)
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
        def __init__(self, revision):
            self.revision        = revision
            self.catalog           = None
            self.catalog_reference = None

        def get_catalog(self):
            if self.catalog is None:
                self.catalog = self.catalog_reference.retrieve_from(self.revision.repository)
            return self.catalog

    def __init__(self, revision):
        root_catalog = revision.retrieve_root_catalog()
        self.revision    = revision
        self.catalog_stack = collections.deque()
        wrapper            = self._CatalogWrapper(self.revision)
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
            wrapper = self._CatalogWrapper(self.revision)
            wrapper.catalog_reference = nested_reference
            self._push_catalog_wrapper(wrapper)

    def _push_catalog_wrapper(self, catalog):
        self.catalog_stack.append(catalog)

    def _pop_catalog(self):
        wrapper = self.catalog_stack.pop()
        return wrapper.get_catalog()


class Revision:
    """ Wrapper around a CVMFS Repository revision.
    A Revision is a concrete instantiation in time of the Repository. It
    represents the concrete status of the repository in a certain period of
    time. Revision data is contained in the so-called Tags, which are stored in
    the History database.
    """

    def __init__(self, repository, tag):
        self.repository = repository
        self._tag = tag

    def __str__(self):
        return '<Revision ' + self.revision_number \
               + ' - ' + self.root_hash + '>'

    @property
    def revision_number(self):
        return self._tag.revision

    @property
    def name(self):
        return self._tag.name

    @property
    def timestamp(self):
        return self._tag.timestamp

    @property
    def root_hash(self):
        return self._tag.hash

    def retrieve_catalog(self, catalog_hash):
        """ Retrieve and open a catalog that belongs to this revision """
        if catalog_hash in self.repository.opened_catalogs:
            return self.repository.opened_catalogs[catalog_hash]
        return self.repository.retrieve_catalog(catalog_hash)

    def retrieve_root_catalog(self):
        return self.retrieve_catalog(self.root_hash)

    def catalogs(self):
        return CatalogTreeIterator(self)

    def retrieve_catalog_for_path(self, needle_path):
        """
        Recursively walk down the Catalogs and find the best fit for a path
        """
        clg = self.retrieve_root_catalog()
        while True:
            new_nested_reference = clg.find_nested_for_path(needle_path)
            if new_nested_reference is None:
                break
            nested_reference = new_nested_reference
            clg = self.retrieve_catalog(nested_reference.hash)
        return clg

    def lookup(self, path):
        """
        Lookups in all existing catalogs for this path's best fit
        :param path: path to search for
        :return: the DirectoryEntry that corresponds to the given path if
        it is found in the already loaded catalogs, or None otherwise
        """
        if path == '/':
            path = ''
        best_fit = self.retrieve_catalog_for_path(path)
        return best_fit.find_directory_entry(path)

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
