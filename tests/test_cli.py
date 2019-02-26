from hvac_cli.cli import CLI
import mock
import pytest
import requests


def test_open(vault_server):
    args = mock.MagicMock()
    args.address = vault_server['http']
    args.token = vault_server['token']
    CLI(args)


def test_client_cert(vault_server):
    args = mock.MagicMock()
    args.address = vault_server['https']
    args.token = vault_server['token']

    # FAILURE with missing client certificate
    with pytest.raises(requests.exceptions.SSLError):
        args.tls_skip_verify = False
        args.ca_cert = vault_server['crt']
        args.client_cert = None
        args.client_key = None
        CLI(args).vault.sys.read_health_status()

    # FAILURE with missing CA
    with pytest.raises(requests.exceptions.SSLError):
        args.tls_skip_verify = False
        args.ca_cert = None
        args.client_cert = vault_server['crt']
        args.client_key = vault_server['key']
        CLI(args).vault.sys.read_health_status()

    # SUCCESS with CA and client certificate provided
    args.tls_skip_verify = False
    args.ca_cert = vault_server['crt']
    args.client_cert = vault_server['crt']
    args.client_key = vault_server['key']
    CLI(args).vault.sys.read_health_status().status_code == 200

    # SUCCESS with CA missing but tls_skip_verify True and client certificate provided
    args.tls_skip_verify = True
    args.ca_cert = None
    args.client_cert = vault_server['crt']
    args.client_key = vault_server['key']
    CLI(args).vault.sys.read_health_status().status_code == 200
