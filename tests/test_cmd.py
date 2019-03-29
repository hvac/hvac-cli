from hvac_cli import cmd
import pytest
from tests.modified_environ import modified_environ


def test_help(capsys):
    with pytest.raises(SystemExit):
        cmd.main(['--help'])
    captured = capsys.readouterr()
    assert 'print bash completion command' in captured.out


def test_parse_args_agent_address():
    token_value = 'TOKEN'

    with modified_environ(
            'VAULT_AGENT_ADDR',
    ):
        app = cmd.HvacApp()
        parser = app.build_option_parser('DESCRIPTION', 'version-1')
        args = parser.parse_args([
            '--token', token_value
        ])
        assert args.address == cmd.DEFAULT_VAULT_ADDR

    addr = 'ADDR'

    with modified_environ(
            'VAULT_AGENT_ADDR',
    ):
        app = cmd.HvacApp()
        parser = app.build_option_parser('DESCRIPTION', 'version-1')
        args = parser.parse_args([
            '--token', token_value,
            '--agent-address', addr,
        ])
        assert args.address == addr

    ignored = 'SHOULD BE IGNORED'

    with modified_environ(
            VAULT_ADDR=ignored,
            VAULT_AGENT_ADDR=addr,
    ):
        app = cmd.HvacApp()
        parser = app.build_option_parser('DESCRIPTION', 'version-1')
        args = parser.parse_args([
            '--token', token_value
        ])
        assert args.address == addr


def test_parse_args():
    token_value = 'TOKEN'
    with modified_environ(
            'VAULT_ADDR',
            'VAULT_SKIP_VERIFY',
            'VAULT_CACERT',
            'VAULT_CLIENT_CERT',
            'VAULT_CLIENT_KEY',
    ):
        app = cmd.HvacApp()
        parser = app.build_option_parser('DESCRIPTION', 'version-1')
        args = parser.parse_args([
            '--token', token_value
        ])
        assert args.token == token_value
        assert args.address == cmd.DEFAULT_VAULT_ADDR
        assert args.tls_skip_verify is False
        assert args.ca_cert is None
        assert args.client_cert is None
        assert args.client_key is None

    addr = 'ADDR'
    skip_verify = 'yes'
    cacert = 'CACERT'
    client_cert = 'CLIENT_CERT'
    client_key = 'CLIENT_KEY'
    with modified_environ(
            VAULT_ADDR=addr,
            VAULT_SKIP_VERIFY=skip_verify,
            VAULT_CACERT=cacert,
            VAULT_CLIENT_CERT=client_cert,
            VAULT_CLIENT_KEY=client_key,
    ):
        app = cmd.HvacApp()
        parser = app.build_option_parser('DESCRIPTION', 'version-1')
        args = parser.parse_args([
            '--token', token_value
        ])
        assert args.token == token_value
        assert args.address == addr
        assert args.tls_skip_verify is True
        assert args.ca_cert == cacert
        assert args.client_cert == client_cert
        assert args.client_key == client_key

    with modified_environ(
            'VAULT_ADDR',
            'VAULT_SKIP_VERIFY',
            'VAULT_CACERT',
            'VAULT_CLIENT_CERT',
            'VAULT_CLIENT_KEY',
    ):
        app = cmd.HvacApp()
        parser = app.build_option_parser('DESCRIPTION', 'version-1')
        args = parser.parse_args([
            '--token', token_value, '--ca-cert', cacert
        ])
        assert args.ca_cert == cacert
