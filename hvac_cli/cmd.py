import sys
import os

from cliff.app import App
from cliff.commandmanager import CommandManager

from hvac_cli.version import __version__

DEFAULT_VAULT_ADDR = 'http://127.0.0.1:8200'


class HvacApp(App):

    def __init__(self):
        super(HvacApp, self).__init__(
            description="""
            hvac-cli is CLI to Hashicorp Vault with additional features.
            It does not support extensions that are not available
            as Free Software such as namespaces, Sentinel, Policy Overrides
            or Multi-factor Authentication (MFA).
            """,
            version=__version__,
            command_manager=CommandManager('hvac_cli'),
            deferred_help=True,
            )

    def build_option_parser(self, description, version, argparse_kwargs=None):
        parser = super().build_option_parser(description, version, argparse_kwargs)
        self.set_parser_arguments(parser)
        return parser

    @staticmethod
    def set_parser_arguments(parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done but do nothing'
        )
        parser.add_argument(
            '--token',
            required=False,
            default=os.getenv('VAULT_TOKEN'),
            help=('Vault token. It will be prompted interactively if unset. '
                  'This can also be specified via the VAULT_TOKEN environment variable.')
        )
        parser.add_argument(
            '--address', '--agent-address',
            default=os.getenv('VAULT_AGENT_ADDR', os.getenv('VAULT_ADDR', DEFAULT_VAULT_ADDR)),
            required=False,
            dest='address',
            help=('Address of the Vault server or the Vault agent. '
                  '--agent-address was introduced with vault 1.1.0. '
                  'This can also be specified via the VAULT_ADDR '
                  'or the VAULT_AGENT_ADDR environment variable. '
                  'If both VAULT_AGENT_ADDR and VAULT_ADDR are in the environment '
                  'VAULT_AGENT_ADDR has precedence')
        )
        parser.add_argument(
            '--tls-skip-verify',
            action='store_true',
            default=True if os.getenv('VAULT_SKIP_VERIFY', False) else False,
            required=False,
            help=('Disable verification of TLS certificates. Using this option is highly '
                  'discouraged and decreases the security of data transmissions to and from '
                  'the Vault server. The default is false. '
                  'This can also be specified via the VAULT_SKIP_VERIFY environment variable.')
        )
        parser.add_argument(
            '--ca-cert',
            default=os.getenv('VAULT_CACERT'),
            required=False,
            help=('Path on the local disk to a single PEM-encoded CA certificate to verify '
                  'the Vault server\'s SSL certificate. '
                  'This can also be specified via the VAULT_CACERT environment variable. ')
        )
        parser.add_argument(
            '--client-cert',
            default=os.getenv('VAULT_CLIENT_CERT'),
            required=False,
            help=('Path on the local disk to a single PEM-encoded CA certificate to use '
                  'for TLS authentication to the Vault server. If this flag is specified, '
                  '--client-key is also required. '
                  'This can also be specified via the VAULT_CLIENT_CERT environment variable.')
        )
        parser.add_argument(
            '--client-key',
            default=os.getenv('VAULT_CLIENT_KEY'),
            required=False,
            help=('Path on the local disk to a single PEM-encoded private key matching the '
                  'client certificate from -client-cert. '
                  'This can also be specified via the VAULT_CLIENT_KEY environment variable.')
        )


def main(argv=sys.argv[1:]):
    myapp = HvacApp()
    return myapp.run(argv)
