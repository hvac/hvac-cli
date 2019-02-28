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


def test_get_from_version(vault_server, capsys):
    key = 'KEY'
    for i in ('1', '2'):
        assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                     'kv', 'put', key, f'a={i}']) == 0

    capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', '--format=json', '--from-version', '1', key]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {'a': '1'}


def test_put_rewrite_key(vault_server, capsys):
    key = 'A / B'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', '--format=json', '--rewrite-key', key, 'a=b', 'c=d']) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {'a': 'b', 'c': 'd'}
    assert 'replaced by' in captured.err


def test_put_dry_run(vault_server, capsys):
    key = 'A/B'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 '--dry-run',
                 'kv', 'put', '--format=json', key, 'a=b', 'c=d']) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {}


def test_patch(vault_server, capsys):
    key = 'KEY'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', key, 'a=b', 'c=d']) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'patch', key, 'a=B', 'e=f']) == 0
    capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', '--format=json', key]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {'a': 'B', 'c': 'd', 'e': 'f'}


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


def test_metadata_get_put(vault_server, capsys):
    key = 'KEY'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', key, 'a=b']) == 0
    captured = capsys.readouterr()

    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'metadata', 'get', '--format=json', key]) == 0
    captured = capsys.readouterr()
    metadata = json.loads(captured.out)
    assert metadata['data']['cas_required'] is False
    assert metadata['data']['max_versions'] == 0

    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'metadata', 'put', '--format=json',
                 '--cas-required=true', '--max-versions=5', key]) == 0
    captured = capsys.readouterr()
    metadata = json.loads(captured.out)
    assert metadata['data']['cas_required'] is True
    assert metadata['data']['max_versions'] == 5


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


def test_delete(vault_server, capsys):
    key = 'KEY'
    for i in ('1', '2'):
        assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                     'kv', 'put', key, 'a=b']) == 0

    captured = capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'metadata', 'get', '--format=json', key]) == 0
    captured = capsys.readouterr()
    versions = json.loads(captured.out)['data']['versions']
    for i in ('1', '2'):
        assert not versions[i]['deletion_time']
        assert not versions[i]['destroyed']

    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'delete', key]) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'delete', '--versions=1,2', key]) == 0

    captured = capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'metadata', 'get', '--format=json', key]) == 0
    captured = capsys.readouterr()
    versions = json.loads(captured.out)['data']['versions']
    for i in ('1', '2'):
        assert versions[i]['deletion_time']
        assert not versions[i]['destroyed']

    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'undelete', '--versions=1,2', key]) == 0

    captured = capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'metadata', 'get', '--format=json', key]) == 0
    captured = capsys.readouterr()
    versions = json.loads(captured.out)['data']['versions']
    for i in ('1', '2'):
        assert not versions[i]['deletion_time']
        assert not versions[i]['destroyed']


def test_destroy(vault_server, capsys):
    key = 'KEY'
    for i in ('1', '2'):
        assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                     'kv', 'put', key, 'a=b']) == 0

    captured = capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'metadata', 'get', '--format=json', key]) == 0
    captured = capsys.readouterr()
    versions = json.loads(captured.out)['data']['versions']
    for i in ('1', '2'):
        assert not versions[i]['deletion_time']
        assert not versions[i]['destroyed']

    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'destroy', '--versions=1,2', key]) == 0

    captured = capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'metadata', 'get', '--format=json', key]) == 0
    captured = capsys.readouterr()
    versions = json.loads(captured.out)['data']['versions']
    for i in ('1', '2'):
        assert not versions[i]['deletion_time']
        assert versions[i]['destroyed']


def test_rollback(vault_server, capsys):
    key = 'KEY'
    for i in ('1', '2'):
        assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                     'kv', 'put', key, f'a={i}']) == 0

    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'rollback', '--from-version=1', key]) == 0

    captured = capsys.readouterr()
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', '--format=json', key]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {'a': '1'}
