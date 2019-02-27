import logging
from cliff.show import ShowOne
from hvac_cli.cli import CLI

logger = logging.getLogger(__name__)


class StatusCLI(CLI):

    def status(self):
        return self.vault.sys.read_health_status(method='GET')


class Status(ShowOne):
    """
    Prints the current state of Vault including whether it is sealed
    and if HA mode is enabled.
    This command prints regardless of whether the Vault is sealed.

      $ hvac-cli status
    """

    def take_action(self, parsed_args):
        status = StatusCLI(self.app_args)
        return self.dict2columns(status.status())
