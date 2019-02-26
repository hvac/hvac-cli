import json
import logging
from cliff.show import ShowOne
from cliff.lister import Lister
from cliff.command import Command
from hvac_cli.cli import CLI
import re
import sys

logger = logging.getLogger(__name__)


class KVCLI(CLI):

    def __init__(self, super_args, args):
        super().__init__(super_args)
        self.kv_version = args.kv_version
        self.mount_point = args.mount_point
        if not self.kv_version:
            mounts = self.vault.sys.list_mounted_secrets_engines()['data']
            path = self.mount_point + '/'
            assert path in mounts, f'path {path} is not founds in mounts {mounts}'
            self.kv_version = mounts[path]['options']['version']

    def delete_metadata_and_all_versions(self, path):
        if self.kv_version == '2':
            self.vault.secrets.kv.v2.delete_metadata_and_all_versions(
                path, mount_point=self.mount_point)
        else:
            self.vault.secrets.kv.v1.delete_secret(path, mount_point=self.mount_point)

    @staticmethod
    def sanitize(path):
        def log_sanitation(path, fun):
            new_path, reason = fun(path)
            if new_path != path:
                logger.info(f'{path} replaced by {new_path} to {reason}')
            return new_path

        def user_friendly(path):
            """replace control characters and DEL because they would be
            difficult for the user to type in the CLI or the web UI.
            Also replace % because it is used in URLs to express %20 etc.
            """
            return re.sub(r'[\x00-\x1f%\x7f]', '_', path), user_friendly.__doc__
        path = log_sanitation(path, user_friendly)

        def bug_6282(path):
            "workaround https://github.com/hashicorp/vault/issues/6282"
            return re.sub(r'[#*+(\\[]', '_', path), bug_6282.__doc__
        path = log_sanitation(path, bug_6282)

        def bug_6213(path):
            "workaround https://github.com/hashicorp/vault/issues/6213"
            path = re.sub(r'\s+/', '/', path)
            path = re.sub(r'\s+$', '', path)
            return path, bug_6213.__doc__
        path = log_sanitation(path, bug_6213)

        return path

    def create_or_update_secret(self, path, entry):
        path = self.sanitize(path)
        if self.kv_version == '2':
            self.vault.secrets.kv.v2.create_or_update_secret(
                path, entry, mount_point=self.mount_point)
        else:
            self.vault.secrets.kv.v1.create_or_update_secret(
                path, entry, mount_point=self.mount_point)

    def read_secret(self, path):
        if self.kv_version == '2':
            return self.vault.secrets.kv.v2.read_secret_version(
                path, mount_point=self.mount_point)['data']['data']
        else:
            return self.vault.secrets.kv.v1.read_secret(
                path, mount_point=self.mount_point)['data']

    def list_secrets(self, path):
        if self.kv_version == '2':
            r = self.vault.secrets.kv.v2.list_secrets(path, mount_point=self.mount_point)
        else:
            r = self.vault.secrets.kv.v1.list_secrets(path, mount_point=self.mount_point)
        return [[x] for x in r['data']['keys']]

    def dump(self):
        r = {}
        self._dump(r, '')
        json.dump(r, sys.stdout)

    def _dump(self, r, prefix):
        if self.kv_version == '2':
            keys = self.vault.secrets.kv.v2.list_secrets(
                prefix, mount_point=self.mount_point)['data']['keys']
        else:
            keys = self.vault.secrets.kv.v1.list_secrets(
                prefix, mount_point=self.mount_point)['data']['keys']
        for key in keys:
            path = prefix + key
            if path.endswith('/'):
                self._dump(r, path)
            else:
                r[path] = self.read_secret(path)

    def load(self, filepath):
        secrets = json.load(open(filepath))
        for k, v in secrets.items():
            self.create_or_update_secret(k, v)

    def erase(self, prefix=''):
        if self.kv_version == '2':
            keys = self.vault.secrets.kv.v2.list_secrets(
                prefix, mount_point=self.mount_point)['data']['keys']
        else:
            keys = self.vault.secrets.kv.v1.list_secrets(
                prefix, mount_point=self.mount_point)['data']['keys']
        for key in keys:
            path = prefix + key
            if path.endswith('/'):
                self.erase(path)
            else:
                logger.debug(f'erase {path}')
                self.delete_metadata_and_all_versions(path)


class KvCommand(object):

    def set_common_options(self, parser):
        parser.add_argument(
            '--mount-point',
            default='secret',
            help='KV path mount point, as found in vault read /sys/mounts',
        )
        parser.add_argument(
            '--kv-version',
            choices=['1', '2'],
            required=False,
            help=('Force the Vault KV backend version (1 or 2). '
                  'Autodetect from `vault read /sys/mounts` if not set.')
        )


class Get(KvCommand, ShowOne):
    """
    Retrieves the value from Vault's key-value store at the given key name. If no
    key exists with that name, an error is returned. If a key exists with that
    name but has no data, nothing is returned.

      $ hvac-cli kv get secret/foo

    To view the given key name at a specific version in time, specify the "--version"
    flag:

      $ hvac-cli kv get --version=1 secret/foo
    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            '--version',
            help='If passed, the value at the version number will be returned. (KvV2 only)',
        )
        parser.add_argument(
            'key',
            help='key to fetch',
        )
        return parser

    def take_action(self, parsed_args):
        kv = KVCLI(self.app_args, parsed_args)
        return self.dict2columns(kv.read_secret(parsed_args.key))


class Put(KvCommand, ShowOne):
    """
      Writes the data to the given path in the key-value store. The data can be of
      any type.

          $ hvac-cli kv put secret/foo bar=baz

      The data can also be consumed from a file on disk by prefixing with the "@"
      symbol. For example:

          $ hvac-cli kv put secret/foo @data.json

      Or it can be read from stdin using the "-" symbol:

          $ echo "abcd1234" | vault kv put secret/foo bar=-

      To perform a Check-And-Set operation, specify the -cas flag with the
      appropriate version number corresponding to the key you want to perform
      the CAS operation on:

          $ hvac-cli kv put -cas=1 secret/foo bar=baz
     """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            'key',
            help='key to set',
        )
        parser.add_argument(
            'kvs',
            nargs='*',
            help='k=v',
        )
        return parser

    def parse_kvs(self, kvs):
        r = {}
        for kv in kvs:
            k, v = kv.split('=')
            r[k] = v
        return r

    def take_action(self, parsed_args):
        kv = KVCLI(self.app_args, parsed_args)
        kv.create_or_update_secret(parsed_args.key, self.parse_kvs(parsed_args.kvs))
        return self.dict2columns(kv.read_secret(parsed_args.key))


class List(KvCommand, Lister):
    """
    Lists data from Vault's key-value store at the given path.

    List values under the "my-app" folder of the key-value store:

      $ hvac-cli kv list secret/my-app/
    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            'path',
            help='path to list',
        )
        return parser

    def take_action(self, parsed_args):
        kv = KVCLI(self.app_args, parsed_args)
        return (['Keys'], kv.list_secrets(parsed_args.path))


class Dump(KvCommand, Command):
    "Dump the secrets"

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        return parser

    def take_action(self, parsed_args):
        kv = KVCLI(self.app_args, parsed_args)
        return kv.dump()


class Load(KvCommand, Command):
    "Load the secrets"

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            'path',
            help='path containing secrets in json',
        )
        return parser

    def take_action(self, parsed_args):
        kv = KVCLI(self.app_args, parsed_args)
        return kv.load(parsed_args.path)


class Erase(KvCommand, Command):
    "Erase all secrets"

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        return parser

    def take_action(self, parsed_args):
        kv = KVCLI(self.app_args, parsed_args)
        return kv.erase()


class MetadataDelete(KvCommand, Command):
    """
    Deletes all versions and metadata for the provided key.

      $ hvac-cli kv metadata delete secret/foo
    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            'key',
            help='key to delete',
        )
        return parser

    def take_action(self, parsed_args):
        kv = KVCLI(self.app_args, parsed_args)
        return kv.delete_metadata_and_all_versions(parsed_args.key)
