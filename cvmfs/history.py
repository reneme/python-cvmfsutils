#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import datetime

from _common import DatabaseObject


class RevisionTag:
    @staticmethod
    def _database_fields():
        return 'name, hash, revision, timestamp, channel, description'

    """ Specific revisions in CernVM-FS 2.1.x repositories have named tags  """
    @staticmethod
    def sql_query_all():
        return 'SELECT ' + RevisionTag._database_fields() + \
               ' FROM tags ORDER BY timestamp DESC'

    @staticmethod
    def sql_query_name(name):
        return 'SELECT ' + RevisionTag._database_fields() + \
               ' FROM tags WHERE name=' + str(name) + ' LIMIT 1'

    @staticmethod
    def sql_query_revision(revision):
        return 'SELECT ' + RevisionTag._database_fields() + \
               ' FROM tags WHERE revision=' + str(revision) + ' LIMIT 1'

    @staticmethod
    def sql_query_date(timestamp):
        return 'SELECT ' + RevisionTag._database_fields() + \
               ' FROM tags WHERE timestamp >' + str(timestamp) + \
               ' ORDER BY timestamp ASC LIMIT 1'

    def __init__(self, sql_result):
        self.name        = sql_result[0]
        self.hash        = sql_result[1]
        self.revision    = int(sql_result[2])
        self.timestamp   = datetime.datetime.fromtimestamp(int(sql_result[3]))
        self.channel     = int(sql_result[4])
        self.description = sql_result[5]

    def __str__(self):
        return "<RevisionTag '" + self.name + "'>"

    def __repr__(self):
        return self.__str__()


class History(DatabaseObject):
    """ Wrapper around CernVM-FS 2.1.x repository history databases """

    @staticmethod
    def open(history_path):
        """ Initializes a History Database from a local file path """
        f = open(history_path)
        return History(f)

    def __init__(self, history_file):
        DatabaseObject.__init__(self, history_file)
        self._read_properties()

    def __str__(self):
        return "<History for '" + self.repository_name + "'>"

    def __repr__(self):
        return self.__str__()

    def __iter__(self):
        return self.list_tags().__iter__()

    def _get_tag_by_query(self, query):
        result = self.run_sql(query)
        if result:
            return RevisionTag(result[0])

    def list_tags(self):
        results = self.run_sql(RevisionTag.sql_query_all())
        return [ RevisionTag(sql_res) for sql_res in results ]

    def get_tag_by_name(self, tag_name):
        return self._get_tag_by_query(RevisionTag.sql_query_name(tag_name))

    def get_tag_by_revision(self, revision):
        return self._get_tag_by_query(RevisionTag.sql_query_revision(revision))

    def get_tag_by_date(self, timestamp):
        return self._get_tag_by_query(RevisionTag.sql_query_date(timestamp))

    def _read_properties(self):
        self.read_properties_table(lambda prop_key, prop_value:
            self._read_property(prop_key, prop_value))
        assert hasattr(self, 'schema') and self.schema == '1.0'

    def _read_property(self, prop_key, prop_value):
        if prop_key == "schema":
            self.schema          = prop_value
        if prop_key == "fqrn":
            self.repository_name = prop_value
