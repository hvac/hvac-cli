import json

from hvac_cli.cmd import main


def test_status(vault_server, capsys):
    assert main(['--address', vault_server['http'],
                 'status',
                 '--format=json',
                 ]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)['initialized'] is True
