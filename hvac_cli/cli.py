import hvac


class CLI(object):

    def __init__(self, args):
        self.args = args
        self.open_vault()

    def list_mounts(self):
        return self.vault.sys.list_mounted_secrets_engines()['data']

    def open_vault(self):
        if self.args.tls_skip_verify:
            verify = False
        else:
            if self.args.ca_cert:
                verify = self.args.ca_cert
            else:
                verify = True

        cert = (self.args.client_cert, self.args.client_key)
        self.vault = hvac.Client(url=self.args.address,
                                 token=self.args.token,
                                 cert=cert,
                                 verify=verify)
