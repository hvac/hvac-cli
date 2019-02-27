import json
import textwrap

from hvac_cli.cmd import main


def test_put_get(vault_server, capsys):
    key = 'KEY'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', key, 'a=b', 'c=d']) == 0
    capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', key]) == 0
    captured = capsys.readouterr()
    assert '| a     | b     |' in captured.out
    assert '| c     | d     |' in captured.out


def test_put_file(vault_server, capsys):
    key = 'KEY'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', '--format=json', key, 'E=F', '--file=tests/secrets.json']) == 0
    captured = capsys.readouterr()
    print(captured.out)
    assert json.loads(captured.out) == {'DIR/SECRET': {'a': 'b'}}


def test_list(vault_server, capsys):
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', 'DIR/SECRET', 'a=b']) == 0
    capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'list', 'DIR']) == 0
    captured = capsys.readouterr()
    expected = textwrap.dedent("""\
    +--------+
    | Keys   |
    +--------+
    | SECRET |
    +--------+
    """)
    assert expected in captured.out


def test_load_dump(vault_server, capsys):
    secrets_file = 'tests/secrets.json'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'load', secrets_file]) == 0
    capsys.readouterr()
    secrets = json.load(open('tests/secrets.json'))
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'dump']) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == secrets


def test_metadata_delete(vault_server):
    key = 'KEY'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', key, 'a=b']) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', key]) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'metadata', 'delete', key]) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', key]) == 1


def test_erase(vault_server):
    key = 'KEY'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', key, 'a=b']) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', key]) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'erase']) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', key]) == 1
