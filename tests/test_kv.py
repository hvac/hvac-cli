import logging
import hvac
from hvac_cli.kv import KVCLI
import mock
import pytest


def test_sanitize_do_nothing():
    assert KVCLI.sanitize('a/b/c') == 'a/b/c'
    path = 'éà'
    assert KVCLI.sanitize(path) == path


def test_sanitize_user_friendly(caplog):
    caplog.set_level(logging.INFO, 'hvac_cli')
    path = '|'.join(["-{:02x}-{}".format(i, chr(i)) for i in range(128)])
    expected = ('-00-_|-01-_|-02-_|-03-_|-04-_|-05-_|-06-_|-07-_|'
                '-08-_|-09-_|-0a-_|-0b-_|-0c-_|-0d-_|-0e-_|-0f-_|'
                '-10-_|-11-_|-12-_|-13-_|-14-_|-15-_|-16-_|-17-_|'
                '-18-_|-19-_|-1a-_|-1b-_|-1c-_|-1d-_|-1e-_|-1f-_|'
                '-20- |-21-!|-22-"|-23-_|-24-$|-25-_|-26-&|-27-\'|'
                '-28-_|-29-)|-2a-_|-2b-_|-2c-,|-2d--|-2e-.|-2f-/|'
                '-30-0|-31-1|-32-2|-33-3|-34-4|-35-5|-36-6|-37-7|'
                '-38-8|-39-9|-3a-:|-3b-;|-3c-<|-3d-=|-3e->|-3f-?|'
                '-40-@|-41-A|-42-B|-43-C|-44-D|-45-E|-46-F|-47-G|'
                '-48-H|-49-I|-4a-J|-4b-K|-4c-L|-4d-M|-4e-N|-4f-O|'
                '-50-P|-51-Q|-52-R|-53-S|-54-T|-55-U|-56-V|-57-W|'
                '-58-X|-59-Y|-5a-Z|-5b-_|-5c-_|-5d-]|-5e-^|-5f-_|'
                '-60-`|-61-a|-62-b|-63-c|-64-d|-65-e|-66-f|-67-g|'
                '-68-h|-69-i|-6a-j|-6b-k|-6c-l|-6d-m|-6e-n|-6f-o|'
                '-70-p|-71-q|-72-r|-73-s|-74-t|-75-u|-76-v|-77-w|'
                '-78-x|-79-y|-7a-z|-7b-{|-7c-||-7d-}|-7e-~|-7f-_')
    assert KVCLI.sanitize(path) == expected
    assert 'replace control characters' in caplog.text
    assert 'issues/6282' in caplog.text


def test_sanitize_bug_6213(caplog):
    caplog.set_level(logging.INFO, 'hvac_cli')
    path = 'A B /C / D '
    assert KVCLI.sanitize(path) == 'A B/C/ D'
    assert 'issues/6213' in caplog.text


@pytest.mark.parametrize("version", ['1', '2'])
def test_kv_version(vault_server, version):
    path = 'mysecrets'
    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    client.sys.enable_secrets_engine(backend_type='kv', options={'version': version}, path=path)

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = version
    KV_args.mount_point = 'mysecrets/'
    kv = KVCLI(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    kv.create_or_update_secret(secret_key, secret_value)
    assert kv.read_secret(secret_key) == secret_value
    kv.erase()
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key)
