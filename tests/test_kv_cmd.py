from hvac_cli.cmd import main


def test_put_get(vault_server, capsys):
    key = 'KEY'
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'put', key, 'a=b']) == 0
    assert main(['--token', vault_server['token'], '--address', vault_server['http'],
                 'kv', 'get', key]) == 0
    captured = capsys.readouterr()
    assert '| a     | b     |' in captured.out
