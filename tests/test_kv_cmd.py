import textwrap

from hvac_cli.cmd import main


def test_put_get(vault_server, capsys):
    key = 'KEY'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', key, 'a=b']) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', key]) == 0
    captured = capsys.readouterr()
    assert '| a     | b     |' in captured.out

def test_list(vault_server, capsys):
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', 'DIR/SECRET', 'a=b']) == 0
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
