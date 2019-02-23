import os

from cliff.command import Command

from hvac_cli.cli import CLI

class Get(Command):
    "get a secret"

    def get_parser(self, prog_name):
        parser = super(Get, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        cli = CLI(parsed_args)
