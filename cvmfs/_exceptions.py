#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""


class RepositoryNotFound(Exception):
    def __init__(self, repo_path):
        self.path = repo_path

    def __str__(self):
        return self.path + " not found"

class UnknownRepositoryType(Exception):
    def __init__(self, repo_fqrn, repo_type):
        self.fqrn = repo_fqrn
        self.type = repo_type

    def __str__(self):
        return self.fqrn + " (" + self.type + ")"

class ConfigurationNotFound(Exception):
    def __init__(self, repo, config_field):
        self.repo         = repo
        self.config_field = config_field

    def __str__(self):
        return repr(self.repo) + " " + self.config_field

class FileNotFoundInRepository(Exception):
    def __init__(self, file_name):
        self.file_name = file_name

    def __str__(self):
        return repr(self.file_name)

class HistoryNotFound(Exception):
    def __init__(self, repo):
        self.repo = repo

    def __str__(self):
        return repr(self.repo)

class CannotReplicate(Exception):
    def __init__(self, repo):
        self.repo = repo

    def __str__(self):
        return repr(self.repo)

class NestedCatalogNotFound(Exception):
    def __init__(self, repo):
        self.repo = repo

    def __str__(self):
        return repr(self.repo)

class RepositoryVerificationFailed(Exception):
    def __init__(self, message, repo):
        Exception.__init__(self, message)
        self.repo = repo

    def __str__(self):
        return self.args[0] + " (Repo: " + repr(self.repo) + ")"

class UnknownManifestField(Exception):
    def __init__(self, key_char):
        self.key_char = key_char

    def __str__(self):
        return self.key_char

class ManifestValidityError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class IncompleteRootFileSignature(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class InvalidRootFileSignature(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class UnknownWhitelistLine(Exception):
    def __init__(self, line):
        Exception.__init__(self, line)

class WhitelistValidityError(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class InvalidWhitelistTimestamp(Exception):
    def __init__(self, timestamp):
        Exception.__init__(self, timestamp)
