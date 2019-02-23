from hvac_cli.cmd import main
import pytest


def test_help(capsys):
    with pytest.raises(SystemExit):
        main(['--help'])
    captured = capsys.readouterr()
    assert 'print bash completion command' in captured.out
