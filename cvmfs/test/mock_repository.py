#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created by René Meusel
This file is part of the CernVM File System auxiliary tools.
"""

import base64
import datetime
import hashlib
import os
import StringIO
import tarfile
import threading

from M2Crypto import RSA

import SimpleHTTPServer
import SocketServer

from file_sandbox import FileSandbox

class CvmfsTestServer(SocketServer.TCPServer):
    allow_reuse_address = True
    def __init__(self, document_root, bind_address, handler):
        self.document_root = document_root
        SocketServer.TCPServer.__init__(self, bind_address, handler)

class CvmfsRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        return os.path.normpath(self.server.document_root + os.sep + path)

    def log_message(self, msg_format, *args):
        pass


class MockRepository:
    """ Generates a mock CVMFS repository for unit testing purposes """
    repo_extract_dir = "repo"

    def __init__(self):
        self.running = False
        self.sandbox = FileSandbox("py_cvmfs_mock_repo_")
        self.repo_name = MockRepository.repo_name
        self._extract_dir = os.path.join(self.sandbox.temporary_dir,
                                         MockRepository.repo_extract_dir)
        self.dir = os.path.join(self._extract_dir, "cvmfs", self.repo_name)
        self._setup_repository()

    def __del__(self):
        if self.running:
            self._shut_down_http_server()


    def serve_via_http(self, port = 8000):
        self._spawn_http_server(self._extract_dir, port)
        self.url = "http://localhost:" + str(port) + "/cvmfs/" + self.repo_name


    def make_valid_whitelist(self):
        tomorrow = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        self._resign_whitelist(tomorrow)


    def make_expired_whitelist(self):
        yesterday = datetime.datetime.utcnow() - datetime.timedelta(days=2)
        self._resign_whitelist(yesterday)


    def _resign_whitelist(self, expiry_date):
        old_whitelist = os.path.join(self.dir, ".cvmfswhitelist")
        new_whitelist = os.path.join(self.dir, ".cvmfswhitelist.new")
        wl_hash = hashlib.sha1()
        with open(new_whitelist, 'w+') as new_wl: # TODO: more elegant is Py 2.7
            with open(old_whitelist) as old_wl:
                pos = old_wl.tell()
                while True:
                    line = old_wl.readline()
                    if len(line) >= 3 and line[0:3] == 'E20': #fails in 85 years
                        line = 'E' + expiry_date.strftime("%Y%m%d%H%M%S") + '\n'
                    if line[0:2] == "--":
                        break
                    if pos == old_wl.tell():
                        raise Exception("Signature not found in whitelist")
                    wl_hash.update(line)
                    new_wl.write(line)
                    pos = old_wl.tell()
            new_wl.write("--\n")
            new_wl.write(wl_hash.hexdigest())
            new_wl.write("\n")
            key = RSA.load_key(self.master_key)
            sig = key.private_encrypt(wl_hash.hexdigest(), RSA.pkcs1_padding)
            new_wl.write(sig)
        os.rename(new_whitelist, old_whitelist)


    def _setup_repository(self):
        self.sandbox.create_directory(self._extract_dir)
        repo = StringIO.StringIO(base64.b64decode(MockRepository.repo_data))
        repo_tar = tarfile.open(None, "r:gz", repo)
        repo_tar.extractall(self._extract_dir)
        pubkey = self.sandbox.write_to_temporary(MockRepository.repo_pubkey)
        self.public_key = pubkey
        privkey = self.sandbox.write_to_temporary(MockRepository.repo_privkey)
        self.private_key = privkey
        mkey = self.sandbox.write_to_temporary(MockRepository.repo_masterkey)
        self.master_key = mkey


    def _spawn_http_server(self, document_root, port):
        handler = CvmfsRequestHandler
        address = ("localhost", port)
        self.httpd = CvmfsTestServer(document_root, address, handler)
        self.httpd_thread = threading.Thread(target=self.httpd.serve_forever)
        self.httpd_thread.setDaemon(True)
        self.httpd_thread.start()
        self.running = True

    def _shut_down_http_server(self):
        self.httpd.shutdown()
        self.url = None


################################################################################

#
# Note: This packed up repository can be recreated by the script
#       aux/make_mock_repo.sh
#

    repo_name = "test.cern.ch"

    repo_pubkey = '\n'.join([
'-----BEGIN PUBLIC KEY-----',
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueS/yBwR4UlRsgkv7hcM',
'ljvt/KyrhkI5y7n7ksLBFumjPhieaWz3L44s4Y1dUJ2H8krRqLXVjQ0X5x/F/nCH',
'erxxjuei4Vu9yG6BFqow0ZdmjqJzU4swRylBkSjf4QVOVSxUcbd7sL2QVbRH9g+C',
'hQ42pB+PD0CcEZp3VEsFV4wI9IY7EMRUC6dwM+LG0jubvhGbvlaqtufGXDESRJEu',
'RM76cnfxh/0qui8Vbs93St2VhsahJWcNGdeIaXlVsMyI77u1QhztPvF39+oDWEsW',
'2xAkfJ5d6NZJdrmRBD3agh5Zj8DuK0VttsvXwsSMw5gwBSRGLJIB8qXf254uouuq',
'lQIDAQAB',
'-----END PUBLIC KEY-----',
''
        ])

    repo_privkey = '\n'.join([
'-----BEGIN RSA PRIVATE KEY-----',
'MIIEowIBAAKCAQEA5TQNCMPftxI8Z27ReqQKgi1MNNmfW/l0Ns1Ax2KxspBYnbE3',
'FBhC1/B/uzIhW8mrYcXlFQ0400WfJHC+/pquDR/IXCrWB+1dyz9dp/7l4HcxcDNH',
'fc/g2hSvtdcw1ZCHNGONcCOxOYE3Rx10eZjviQZiGkzVkHwpnjgWNxbT7bkIV6iu',
'R8YWNUfGABwhTB5diq3UPtw5LEwYYj/CKFR9BkTK0VmZJbXV5bAvGQyINfT5296r',
'XJWD4WItJJ95R/zkBQgBjvLTNpFPRiOln8FTFpEDVWdteezDDXGWNWma3jYwvJg8',
'PBZEEcUmZBDQT9k0nfRizhsTyO7xzDmcAPfVHQIDAQABAoIBAB1JV1kFXjKQO/Oj',
'b1TSXR1hGFmwbPJdn4HZHCvd6oK8evY7TKRerTvWWRvcPfLyg9mMZccY12f3f2wy',
'k9UIgrDenMVaG9sLc26i/B6ZLVpPIJwLkVj8FOkIt6LuiijfvMbu6YWoqd6FKkEF',
'/HoFFqZVkHd31doOY2r6E6yaWB4JxqXcNJLAQRnm0mCytZUkzHodr+Tsy1GkSJC2',
'I3saPSIG5u4TL3XVsIBs5mE47FLK/YKRHJyp3tTLgTkhDvpLPEJC8ij1oWJ4PSzo',
'jeaK8xpv+LAjqu8brL9WZQI812Fmx+nPncSmKZrmjAYr4HaZ4aAgsWKOnqnyzrZv',
'QSao9EECgYEA8p1g/4iZVXkUjNVL6a+Cmj+g6+ji9wPXDOXFiwlOgXCDRFxunaMM',
'ZbZtxe26XHQdVm4e2hC4Zv2nn7Sn9gGg+7NCso5Y5qDH2HMJ/w+ya6XUIcE/YDMb',
'PqK6llLqsyLg+nrtV0ZkA5UN8Rlp116fWE0ensszH9qF43pB+7m8ANkCgYEA8dlA',
'sv9ZJW4/MtK8dbxzmrpyCRbLFsuYYN7k1ybrUVvK6WpGljqKbduTJ3/XC6qhJuWR',
'YAH9aTwwvRvEJor0EnYc+QpEnv5KHfNkKFU2x3tnnYZT24t2PLpY9AECjgeSUDk+',
'kHQzUGmig5eSSYMpGdLvRtD0BYXQLoD8eAy3y+UCgYEAtQ0jFK7Qlotr/YkzRGm4',
'kfmH0mUR8vqHolVZ7N7+GfRn0T0VQ0go+UKBeuJkX5g7SIOXPG6b3ifOzozXhutC',
'QnNNA8jcqQc0+98lh5UkNdcjjikTbWvWGhEAIywvf404zVOtCKM8AbxbEiA/7vvq',
'989dWW0UcuH1ZoOW+A5sMUkCgYB/E+zPISUyac+DYP/tzWvhLX6mD/f+rlQO8o/E',
'DYswYM8p/tHANlpuhyW3Z5ETbEDpM09D50fEeAAUHfbfWbwNx0pKAX81G+DOBAno',
't33lK46yUtbVUV57Yl9DNxSklI3o4Wtic+xSoG7oPkh7oBOEojVgPIM8M6fEB7qh',
'Se15kQKBgBQ8/Z4A95yoGlv1RYOBuZpOpEtbgi/NiJdRXnzrmQ1m31heRbkfu3w0',
'5WzlYjaQQ3g3rsh+0Ond9bLFcZor6azcPSsu+cjC3Gsxm/0KZKPAroi73Gd4O0QH',
'ih/vJDlTHRS2ArfdYc9cUYTFvs8YuLy7y9Uho35ey6PLX6CEsJel',
'-----END RSA PRIVATE KEY-----',
''
])

    repo_masterkey = '\n'.join([
'-----BEGIN RSA PRIVATE KEY-----',
'MIIEowIBAAKCAQEAueS/yBwR4UlRsgkv7hcMljvt/KyrhkI5y7n7ksLBFumjPhie',
'aWz3L44s4Y1dUJ2H8krRqLXVjQ0X5x/F/nCHerxxjuei4Vu9yG6BFqow0ZdmjqJz',
'U4swRylBkSjf4QVOVSxUcbd7sL2QVbRH9g+ChQ42pB+PD0CcEZp3VEsFV4wI9IY7',
'EMRUC6dwM+LG0jubvhGbvlaqtufGXDESRJEuRM76cnfxh/0qui8Vbs93St2Vhsah',
'JWcNGdeIaXlVsMyI77u1QhztPvF39+oDWEsW2xAkfJ5d6NZJdrmRBD3agh5Zj8Du',
'K0VttsvXwsSMw5gwBSRGLJIB8qXf254uouuqlQIDAQABAoIBAASWKUk1sBc/6N0c',
'rusP9IaMaf3PANhqL+Tf7N4dIgh/sUBp+Rae0qaAuojCJShFCsKmp++itOcrCIjy',
'Vr9FZYJYvfCJtJIc4lzcpSC7CENTmfsw9Ol9yK4ozW5YdNWnfNxLILZBkbK1qqcC',
'sLfYgB7qT9zSzoPQ00j357PTugkD56eiJcNZu80nRy0Ud3D/3dDFJADF1hQkebwu',
'82NLqNQnTO2/KF1fJLgsIU3ymMdOV68k9rjtGfLRoK4qfX0lb8BNrAY2urPzU0yV',
'Y2unrWWbmWT2lDOIqRCfLbGSQuVfLbY7JOq+PwA+H7C2Py6GQLuFi8t5DTVuGke/',
'NtZpHkECgYEA9u+OPbZLISvmGNFZg4hn6k8PfH0GLrEcx0tPv4ReONqwXVobeYKX',
'/x0b6o2BC0bmICMjnGsDrZSZj2wiXAYknSQCxMAGAj0PoBI9KQNU1Simwb/IA0EE',
'd+c6BdR0YdVIQ7esSNaCaAb0zX1/y98U7HOQ2/ornhAM4wKKRtwykMUCgYEAwLeV',
'IvRHnwXls8kux+KOEAHGoWf4KqaOYUbqktSdVB5DziqN2Ktj46/wQxcmaS5gbMNR',
'B+lvveP7t3qKzMMMeBtKEKou1lGC+K7yWo//v1st25p8j9Ue0xlaw5ZiVRyYzZYV',
'uwnaBNFiNk8YH+to8UdwYGDPuNNZjE7JuFcdr5ECgYEAtsTKWBzj8LJoRXg2M+ez',
'WjaYNMDo4YhPz6aLaSpU/unGXeICseYaEEYAUpPXrnwUejbn9a8zcrepDQGxUMFv',
'OivcLLof+GovdX/qar+/e2HyQzdqmBX4c7LePFBqr7rIGO8KgoLa1JpJeQrpmwEL',
'oJNM5bR9sikZELDhnd7/Qi0CgYAV8VEzx6iX/K3oyJFhBPSz8d/R5OqmwIwZm19+',
'FGNNfpytzr6T2v/mntO2b95Zv4QPHjYNtpCYiGrSu0sugU7cJg9K0nW+xU0qT5Ec',
'qqSt/w27oV1paxS1aH+jIW5Uzoq/bcVPpJGEVurd0CepCr7KKh4rexprqvTZOudQ',
'6+pfYQKBgBmC5quiKh2ILLh5IJ1g5UXQPzFgE6J9XcVY3BumXBr41g2CYPC5oklM',
'v5PZ3wY76x8O+2S+sYBKzDHOv3Q8AJPC2PEIJORzTK6XfIetpnN3TR0LZvHiUpES',
'hmCojC2QE3Y7i+XTL2d9rbXLSIbMEWDHdBHKzTWczDIDo+tFPEFo',
'-----END RSA PRIVATE KEY-----',
''
])

    repo_data = '\n'.join([
'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',
'DAbzP+tvIfjNRABwAwA=',
''
        ])
