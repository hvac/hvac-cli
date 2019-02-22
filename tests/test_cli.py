import os
from hvac_cli.cmd import main


def test_get():
    assert main(['--debug', 'get']) == 0
