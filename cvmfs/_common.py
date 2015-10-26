#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import ctypes
import sqlite3
import subprocess
import os


_REPO_CONFIG_PATH      = "/etc/cvmfs/repositories.d"
_SERVER_CONFIG_NAME    = "server.conf"

_REST_CONNECTOR        = "control"

_MANIFEST_NAME         = ".cvmfspublished"
_WHITELIST_NAME        = ".cvmfswhitelist"
_LAST_REPLICATION_NAME = ".cvmfs_last_snapshot"
_REPLICATING_NAME      = ".cvmfs_is_snapshotting"


class CvmfsNotInstalled(Exception):
    def __init__(self):
        Exception.__init__(self, "It seems that cvmfs is not installed on this machine!")


class DatabaseObject:
    _db_handle = None

    def __init__(self, db_file):
        self._file = db_file
        self._open_database()

    def __del__(self):
        if self._db_handle:
            self._db_handle.close()
        self._file.close()

    def _open_database(self):
        """ Create and configure a database handle to the Catalog """
        self._db_handle = sqlite3.connect(self._file.name,
                                          check_same_thread=False)
        self._db_handle.text_factory = str

    def db_size(self):
        return os.path.getsize(self._file.name)

    def read_properties_table(self, reader):
        """ Retrieve all properties stored in the 'properties' table """
        props = self.run_sql("SELECT key, value FROM properties;")
        for prop in props:
            prop_key   = prop[0]
            prop_value = prop[1]
            reader(prop_key, prop_value)

    def run_sql(self, sql):
        """ Run an arbitrary SQL query on the catalog database """
        cursor = self._db_handle.cursor()
        cursor.execute(sql)
        data = cursor.fetchall()
        cursor.close()
        return data

    def open_interactive(self):
        """ Spawns a sqlite shell for interactive catalog database inspection """
        subprocess.call(['sqlite3', self._file.name])



def _binary_buffer_to_hex_string(binbuf):
    return "".join(map(lambda c: ("%0.2X" % c).lower(),map(ord,binbuf)))

def _split_md5(md5digest):
    hi = lo = 0
    for i in range(0, 8):
        lo |= (ord(md5digest[i]) << (i * 8))
    for i in range(8,16):
        hi |= (ord(md5digest[i]) << ((i - 8) * 8))
    return ctypes.c_int64(lo).value, ctypes.c_int64(hi).value  # signed int!

def _combine_md5(lo, hi):
    md5digest = [ '\x00','\x00','\x00','\x00','\x00','\x00','\x00','\x00',
                  '\x00','\x00','\x00','\x00','\x00','\x00','\x00','\x00' ]
    for i in range(0, 8):
        md5digest[i] = chr(lo & 0xFF)
        lo >>= 8
    for i in range(8,16):
        md5digest[i] = chr(hi & 0xFF)
        hi >>= 8
    return ''.join(md5digest)


class TzInfos:
    tzd = None

    @staticmethod
    def get_tzinfos():
        """ Time Zone Codes are ambiguous but dateutil.parser.parse allows to
            pass a desired mapping of these codes to offsets to UTC.

            This is taken from Stack Overflow:
            http://stackoverflow.com/questions/1703546/
            parsing-date-time-string-with-timezone-abbreviated-name-in-python/
            4766400#4766400
        """
        if not TzInfos.tzd:
            TzInfos._generate_tzd()
        return TzInfos.tzd


    @staticmethod
    def _generate_tzd():
        TzInfos.tzd = {}
        tz_str = '''-12 Y
-11 X NUT SST
-10 W CKT HAST HST TAHT TKT
-9 V AKST GAMT GIT HADT HNY
-8 U AKDT CIST HAY HNP PST PT
-7 T HAP HNR MST PDT
-6 S CST EAST GALT HAR HNC MDT
-5 R CDT COT EASST ECT EST ET HAC HNE PET
-4 Q AST BOT CLT COST EDT FKT GYT HAE HNA PYT
-3 P ADT ART BRT CLST FKST GFT HAA PMST PYST SRT UYT WGT
-2 O BRST FNT PMDT UYST WGST
-1 N AZOT CVT EGT
0 Z EGST GMT UTC WET WT
1 A CET DFT WAT WEDT WEST BST
2 B CAT CEDT CEST EET SAST WAST
3 C EAT EEDT EEST IDT MSK
4 D AMT AZT GET GST KUYT MSD MUT RET SAMT SCT
5 E AMST AQTT AZST HMT MAWT MVT PKT TFT TJT TMT UZT YEKT
6 F ALMT BIOT BTT IOT KGT NOVT OMST YEKST
7 G CXT DAVT HOVT ICT KRAT NOVST OMSST THA WIB
8 H ACT AWST BDT BNT CAST HKT IRKT KRAST MYT PHT SGT ULAT WITA WST
9 I AWDT IRKST JST KST PWT TLT WDT WIT YAKT
10 K AEST ChST PGT VLAT YAKST YAPT
11 L AEDT LHDT MAGT NCT PONT SBT VLAST VUT
12 M ANAST ANAT FJT GILT MAGST MHT NZST PETST PETT TVT WFT
13 FJST NZDT
11.5 NFT
10.5 ACDT LHST
9.5 ACST
6.5 CCT MMT
5.75 NPT
5.5 SLT
4.5 AFT IRDT
3.5 IRST
-2.5 HAT NDT
-3.5 HNT NST NT
-4.5 HLV VET
-9.5 MART MIT'''

        for tz_descr in map(str.split, tz_str.split('\n')):
            tz_offset = int(float(tz_descr[0]) * 3600)
            for tz_code in tz_descr[1:]:
                TzInfos.tzd[tz_code] = tz_offset
