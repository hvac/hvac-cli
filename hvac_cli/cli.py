import argparse
import base64
import collections
import getpass
import hvac
import logging
import os
import re
import sys

class CLI(object):

    def __init__(self, args):
        self.args = args
        self.open_vault()

    def open_vault(self):
        if self.args.tls_skip_verify:
            verify = False
        else:
            if self.args.ca_cert:
                verify = self.args.ca_cert
            else:
                verify = True
        
        cert = (self.args.client_cert, self.args.client_key)
        self.vault = hvac.Client(url=self.args.address,
                                 token=self.args.token,
                                 cert=cert,
                                 verify=verify)
        self.kv_version = self.args.kv_version
        if not self.kv_version:
            mounts = self.vault.sys.list_mounted_secrets_engines()['data']
            path = self.path + '/'
            assert path in mounts, f'path {path} is not founds in mounts {mounts}'
            self.kv_version = mounts[path]['options']['version']
