from hvac_cli.cmd import main
from hvac_cli.cli import CLI
import mock
import pytest


def test_get():
    with pytest.raises(SystemExit):
        main(['--help'])

def test_open(vault_server):
    args = mock.MagicMock()
    args.address = vault_server['http']
    args.token = vault_server['token']
    cli = CLI(args)
