from hvac_cli.cli import CLI
import mock


def test_open(vault_server):
    args = mock.MagicMock()
    args.address = vault_server['http']
    args.token = vault_server['token']
    CLI(args)
