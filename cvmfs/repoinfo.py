#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import json

class RepoInfo:
    """ Wraps JSON repository information contained in a CernVM-FS repo """

    def __init__(self, fqrn, repo_info_file):
        self.fqrn = fqrn
        self.json_data = json.load(repo_info_file)
        self.__extract_if_exists("email")
        self.__extract_if_exists("administrator")
        self.__extract_if_exists("organisation")
        self.__extract_if_exists("description")
        self.__extract_if_exists("recommended-stratum1s", "stratum1s")


    def __str__(self):
        return "<RepoInfo for " + self.fqrn + ">"


    def __repr__(self):
        return self.__str__()


    def __extract_if_exists(self, field, member_name = ""):
        if not member_name:
            member_name = field
        if field in self.json_data:
            setattr(self, member_name, self.json_data[field])
