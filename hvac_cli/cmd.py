import sys

from cliff.app import App
from cliff.commandmanager import CommandManager

from hvac_cli.version import __version__


class HvacApp(App):

    def __init__(self):
        super(HvacApp, self).__init__(
            description='hvac cli',
            version=__version__,
            command_manager=CommandManager('hvac_cli'),
            deferred_help=True,
            )


def main(argv=sys.argv[1:]):
    myapp = HvacApp()
    return myapp.run(argv)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
