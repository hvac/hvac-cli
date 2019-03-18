import json
import logging
import packaging.version
from cliff.show import ShowOne
from cliff.lister import Lister
from cliff.command import Command
from hvac_cli.cli import CLI
import re
import sys

logger = logging.getLogger(__name__)


class ReadSecretVersion(Exception):
    pass


class SecretVersion(Exception):
    pass


def kvcli_factory(super_args, args):
    cli = CLI(super_args)
    if not args.kv_version:
        try:
            mounts = cli.list_mounts()
        except Exception:
            logger.error('failed to read sys/mount to determine the KV version, '
                         'try setting --kv-version')
            raise
        path = args.mount_point + '/'
        assert path in mounts, f'path {path} is not found in mounts {mounts}'
        args.kv_version = mounts[path]['options']['version']
    if args.kv_version == '1':
        return KVv1CLI(super_args, args)
    else:
        return KVv2CLI(super_args, args)


class KVCLI(CLI):

    def __init__(self, args, parsed_args):
        super().__init__(args)
        self.kv_version = parsed_args.kv_version
        self.mount_point = parsed_args.mount_point
        self.rewrite_key = getattr(parsed_args, 'rewrite_key', None)
        self.parsed_args = parsed_args
        self.status = self.vault.sys.read_health_status(method='GET')

    @staticmethod
    def sanitize(path, status, args):
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

        if not args.no_workaround_6282:
            def bug_6282(path):
                "workaround https://github.com/hashicorp/vault/issues/6282"
                if packaging.version.parse(status['version']) >= packaging.version.parse('1.1.0'):
                    logger.info("Applying workaround for the bug "
                                "https://github.com/hashicorp/vault/issues/6282")
                    logger.info("The bug 6282 was fixed in vault 1.1.0 and the workaround "
                                "can be disabled with --no-workaround-6282")
                return re.sub(r'[#*+(\\[]', '_', path), bug_6282.__doc__
            path = log_sanitation(path, bug_6282)

        def bug_6213(path):
            "workaround https://github.com/hashicorp/vault/issues/6213"
            path = re.sub(r'\s+/', '/', path)
            path = re.sub(r'\s+$', '', path)
            return path, bug_6213.__doc__
        path = log_sanitation(path, bug_6213)

        return path

    def list_secrets(self, path):
        return self.kv.list_secrets(path, mount_point=self.mount_point)['data']['keys']

    def dump(self):
        r = {}
        self._dump(r, '')
        json.dump(r, sys.stdout)

    def _dump(self, r, prefix):
        keys = self.list_secrets(prefix)
        for key in keys:
            path = prefix + key
            if path.endswith('/'):
                self._dump(r, path)
            else:
                r[path] = self.read_secret(path, version=None)

    def load(self, filepath):
        secrets = json.load(open(filepath))
        for k, v in secrets.items():
            self.create_or_update_secret(k, v, cas=None)

    def erase(self, prefix=''):
        keys = self.list_secrets(prefix)
        for key in keys:
            path = prefix + key
            if path.endswith('/'):
                self.erase(path)
            else:
                logger.debug(f'erase {path}')
                self.delete_metadata_and_all_versions(path)


class KVv1CLI(KVCLI):

    def __init__(self, super_args, args):
        super().__init__(super_args, args)
        self.kv = self.vault.secrets.kv.v1

    def delete_metadata_and_all_versions(self, path):
        self.delete(path, versions=None)

    def read_secret_metadata(self, path):
        raise SecretVersion(
            f'{self.mount_point} is KV {self.kv_version} and does not support metadata')

    def update_metadata(self, path, max_version, cas_required):
        raise SecretVersion(
            f'{self.mount_point} is KV {self.kv_version} and does not support metadata')

    def create_or_update_secret(self, path, entry, cas):
        if cas:
            raise SecretVersion(
                f'{self.mount_point} is KV {self.kv_version} and does not support --cas')
        if self.rewrite_key:
            path = self.sanitize(path, self.status, self.parsed_args)
        logger.info(f'put {path} {list(entry.keys())}')
        if not self.args.dry_run:
            self.kv.create_or_update_secret(path, entry, mount_point=self.mount_point)
        return path

    def patch(self, path, entry):
        raise SecretVersion(
            f'{self.mount_point} is KV {self.kv_version} and does not support patch')

    def read_secret(self, path, version):
        if version:
            raise ReadSecretVersion(
                f'{self.mount_point} is KV {self.kv_version} and does not support --from-version')
        return self.kv.read_secret(path, mount_point=self.mount_point)['data']

    def destroy(self, path, versions):
        raise SecretVersion(
            f'{self.mount_point} is KV {self.kv_version} and does not support destroy')

    def delete(self, path, versions):
        if versions:
            raise SecretVersion(
                f'{self.mount_point} is KV {self.kv_version} and does not support --versions')
        logger.info(f'permanently delete {path}')
        if not self.args.dry_run:
            self.kv.delete_secret(path, mount_point=self.mount_point)
        return 0

    def undelete(self, path, versions):
        raise SecretVersion(
            f'{self.mount_point} is KV {self.kv_version} and does not support undelete')

    def rollback(self, path, version):
        raise SecretVersion(
            f'{self.mount_point} is KV {self.kv_version} and does not support rollback')


class KVv2CLI(KVCLI):

    def __init__(self, super_args, args):
        super().__init__(super_args, args)
        self.kv = self.vault.secrets.kv.v2

    def delete_metadata_and_all_versions(self, path):
        logger.info(f'permanently delete metadata and all versions for {path}')
        if not self.args.dry_run:
            self.kv.delete_metadata_and_all_versions(path, mount_point=self.mount_point)
        return 0

    def read_secret_metadata(self, path):
        try:
            return self.kv.read_secret_metadata(path, mount_point=self.mount_point)
        except Exception:
            logger.error(f'failed to read metadata for {path}')
            raise

    def update_metadata(self, path, max_versions, cas_required):
        logger.info(f'set metadata for {path}')
        if not self.args.dry_run:
            self.kv.update_metadata(path, max_versions, cas_required, mount_point=self.mount_point)
        return self.read_secret_metadata(path)

    def create_or_update_secret(self, path, entry, cas):
        if self.rewrite_key:
            path = self.sanitize(path, self.status, self.parsed_args)
        logger.info(f'put {path} {list(entry.keys())}')
        if not self.args.dry_run:
            self.kv.create_or_update_secret(path, entry, cas=cas, mount_point=self.mount_point)
        return path

    def patch(self, path, entry):
        if self.rewrite_key:
            path = self.sanitize(path, self.status, self.parsed_args)
        logger.info(f'patch {path} {list(entry.keys())}')
        if not self.args.dry_run:
            self.kv.patch(path, entry, mount_point=self.mount_point)
        return path

    def read_secret(self, path, version):
        return self.kv.read_secret_version(
            path, version=version, mount_point=self.mount_point)['data']['data']

    def destroy(self, path, versions):
        logger.info(f'permanently delete (i.e. destroy) {path} at versions {versions}')
        if not self.args.dry_run:
            self.kv.destroy_secret_versions(path, versions, mount_point=self.mount_point)
        return 0

    def delete(self, path, versions):
        if versions:
            logger.info(f'delete (can undelete later) {path} at versions {versions}')
            if not self.args.dry_run:
                self.kv.delete_secret_versions(
                    path, versions=versions, mount_point=self.mount_point)
        else:
            logger.info(f'delete (can undelete later) the most recent version of {path}')
            if not self.args.dry_run:
                self.kv.delete_latest_version_of_secret(path, mount_point=self.mount_point)
        return 0

    def undelete(self, path, versions):
        logger.info(f'undelete  {path} at versions {versions}')
        if not self.args.dry_run:
            self.kv.undelete_secret_versions(
                path, versions=versions, mount_point=self.mount_point)
        return 0

    def rollback(self, path, version):
        try:
            entry = self.read_secret(path, version=version)
        except Exception:
            logger.error(f'failed to read_secret {path} at version {version}')
            raise
        logger.info(f'rollback {path} from version {version}')
        if not self.args.dry_run:
            self.kv.create_or_update_secret(path, entry, mount_point=self.mount_point)
        return 0


class KvCommand(object):

    @staticmethod
    def set_rewrite_key(parser):
        parser.add_argument(
            '--rewrite-key',
            action='store_true',
            help=('Rewrite the key to avoid UI problems and print a warning. '
                  'Workaround https://github.com/hashicorp/vault/issues/6282; '
                  'https://github.com/hashicorp/vault/issues/6213; replace '
                  'control characters and percent with an underscore'
                  )
        )
        parser.add_argument(
            '--no-workaround-6282',
            action='store_true',
            help='Do not workaround bug https://github.com/hashicorp/vault/issues/6282'
        )

    @staticmethod
    def set_common_options(parser):
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
    Retrieves the value from Vault key-value store at the given key name
    If no key exists with that name, an error is returned. If a key exists with that
    name but has no data, nothing is returned.

      $ hvac-cli kv get secret/foo

    To view the given key name at a specific version in time, specify the "--from-version"
    flag:

      $ hvac-cli kv get --from-version=1 secret/foo

    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            '--from-version',
            help='If passed, the value at the version number will be returned. (KvV2 only)',
        )
        parser.add_argument(
            'key',
            help='key to fetch',
        )
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        return self.dict2columns(kv.read_secret(parsed_args.key, parsed_args.from_version))


class Delete(KvCommand, Command):
    """
    Deletes the data for the provided version and path in the key-value store
    The versioned data will not be fully removed, but marked as deleted and will no
    longer be returned in normal get requests.

    To delete the latest version of the key "foo":

      $ hvac-cli kv delete secret/foo

    To delete version 3 of key foo:

      $ hvac-cli kv delete --versions=3 secret/foo

    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            '--versions',
            help='The comma separate list of version numbers to delete',
        )
        parser.add_argument(
            'key',
            help='key to delete',
        )
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        if parsed_args.versions:
            versions = parsed_args.versions.split(',')
        else:
            versions = None
        return kv.delete(parsed_args.key, versions)


class Destroy(KvCommand, Command):
    """
    Permanently removes the specified versions data from the key-value store
    If  no key exists at the path, no action is taken.

    To destroy version 3 of key foo:

      $ hvac-cli kv destroy --versions=3 secret/foo

    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            '--versions',
            required=True,
            help='The comma separate list of version numbers to destroy',
        )
        parser.add_argument(
            'key',
            help='key to destroy',
        )
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        return kv.destroy(parsed_args.key, parsed_args.versions.split(','))


class Undelete(KvCommand, Command):
    """
    Undeletes the data for the provided version and path in the key-value store
    This restores the data, allowing it to be returned on get requests.

    To undelete version 3 of key "foo":

      $ hvac-cli kv undelete --versions=3 secret/foo

    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            '--versions',
            required=True,
            help='The comma separate list of version numbers to undelete',
        )
        parser.add_argument(
            'key',
            help='key to undelete',
        )
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        return kv.undelete(parsed_args.key, parsed_args.versions.split(','))


class Rollback(KvCommand, Command):
    """
    Restores a given previous version to the current version at the given path
    The value is written as a new version; for instance, if the current version
    is 5 and the rollback version is 2, the data from version 2 will become
    version 6.

      $ hvac-cli kv rollback --from-version=2 secret/foo

    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            '--from-version',
            required=True,
            help='The version number that should be made current again',
        )
        parser.add_argument(
            'key',
            help='key to rollback',
        )
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        return kv.rollback(parsed_args.key, parsed_args.from_version)


class PutOrPatch(KvCommand, ShowOne):
    """
    Writes the data to the given path in the key-value store
    The data can be of any type.

      $ hvac-cli kv put secret/foo bar=baz

    The data can also be consumed from a JSON file on disk. For example:

      $ hvac-cli kv put secret/foo --file=/path/data.json

     """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        self.set_rewrite_key(parser)
        parser.add_argument(
            '--file',
            help='A JSON object containing the secrets',
        )
        parser.add_argument(
            'key',
            help='key to set',
        )
        parser.add_argument(
            'kvs',
            nargs='*',
            help='k=v secrets that can be repeated. They are ignored if --file is set.',
        )
        return parser

    def parse_kvs(self, kvs):
        r = {}
        for kv in kvs:
            k, v = kv.split('=')
            r[k] = v
        return r

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        if parsed_args.file:
            secrets = json.load(open(parsed_args.file))
        else:
            secrets = self.parse_kvs(parsed_args.kvs)
        path = self.kv_action(kv, parsed_args, secrets)
        if kv.args.dry_run:
            return self.dict2columns({})
        else:
            return self.dict2columns(kv.read_secret(path, version=None))


class Put(PutOrPatch):
    """
    Writes the data to the given path in the key-value store
    The data can be of any type.

      $ hvac-cli kv put secret/foo bar=baz

    The data can also be consumed from a JSON file on disk. For example:

      $ hvac-cli kv put secret/foo --file=/path/data.json

     """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            '--cas',
            help=('Specifies to use a Check-And-Set operation. If not set the write will be '
                  'allowed. If set to 0 a write will only be allowed if the key doesn’t '
                  'exist. If the index is non-zero the write will only be allowed if '
                  'the key’s current version matches the version specified in the cas '
                  'parameter. (KvV2 only)'),
        )
        return parser

    def kv_action(self, kv, parsed_args, secrets):
        return kv.create_or_update_secret(parsed_args.key, secrets, cas=parsed_args.cas)


class Patch(PutOrPatch):
    """
    Read the data from the given path and merge it with the data provided
    If the existing data is a dictionary named OLD and the data provided
    is a dictionary named NEW, the data stored is the merge of OLD and NEW.
    If a key exists in both NEW and OLD, the one from NEW takes precedence.

      $ hvac-cli kv patch secret/foo bar=baz

    The data can also be consumed from a JSON file on disk. For example:

      $ hvac-cli kv patch secret/foo --file=/path/data.json

    """

    def kv_action(self, kv, parsed_args, secrets):
        return kv.patch(parsed_args.key, secrets)


class List(KvCommand, Lister):
    """
    Lists data from Vault key-value store at the given path.

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
        kv = kvcli_factory(self.app_args, parsed_args)
        r = [[x] for x in kv.list_secrets(parsed_args.path)]
        return (['Keys'], r)


class Dump(KvCommand, Command):
    """Dump all secrets as a JSON object where the keys are the path
    and the values are the secrets. For instance::

        {
          "a/secret/path": { "key1": "value1" },
          "another/secret/path": { "key2": "value2" }
        }

    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        return kv.dump()


class Load(KvCommand, Command):
    """Load secrets from a JSON object for which the key is the path
    and the value is the secret. For instance::

        {
          "a/secret/path": { "key1": "value1" },
          "another/secret/path": { "key2": "value2" }
        }

    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        self.set_rewrite_key(parser)
        parser.add_argument(
            'path',
            help='path containing secrets in JSON',
        )
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        return kv.load(parsed_args.path)


class Erase(KvCommand, Command):
    "Erase all secrets"

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        return kv.erase()


class MetadataDelete(KvCommand, Command):
    """
    Deletes all versions and metadata for the provided key

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
        kv = kvcli_factory(self.app_args, parsed_args)
        return kv.delete_metadata_and_all_versions(parsed_args.key)


class MetadataGet(KvCommand, ShowOne):
    """
    Retrieves the metadata from Vault key-value store at the given key name
    If no key exists with that name, an error is returned.

      $ hvac-cli kv metadata get secret/foo

    This command only works with KVv2

    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            'key',
            help='get metadata for this key',
        )
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        return self.dict2columns(kv.read_secret_metadata(parsed_args.key))


class MetadataPut(KvCommand, ShowOne):
    """
    Update the metadata associated with an existing key

    Set a max versions setting on the key:

      $ hvac-cli kv metadata put --max-versions=5 secret/foo

    Require Check-and-Set for this key:

      $ hvac-cli kv metadata put --cas-required=true secret/foo

    This command only works with KVv2
    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.set_common_options(parser)
        parser.add_argument(
            '--cas-required',
            type=bool,
            default=False,
            help=('If true the key will require the cas parameter to be set on all write '
                  'requests. If false, the backend’s configuration will be used. The '
                  'default is false.')
        )
        parser.add_argument(
            '--max-versions',
            type=int,
            help=('The number of versions to keep. If not set, the backend’s configured '
                  'max version is used.')
        )
        parser.add_argument(
            'key',
            help='set metadata for this key',
        )
        return parser

    def take_action(self, parsed_args):
        kv = kvcli_factory(self.app_args, parsed_args)
        r = kv.update_metadata(parsed_args.key,
                               parsed_args.max_versions,
                               parsed_args.cas_required)
        return self.dict2columns(r)
