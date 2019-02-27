HashiCorp Vault CLI
===================

`hvac-cli` is a replacement for the `HashiCorp Vault CLI
<https://www.vaultproject.io/docs/commands/>`__, with additional
features and workarounds for known bugs.

.. toctree::
  :maxdepth: 2

  quickstart
  reference

Implementation matrix
=====================

========= =========== ========================================
Command   Implemented Description
========= =========== ========================================
kv           yes      Interact with Vault's Key-Value storage
read         no	      Read data and retrieves secrets
write        no	      Write data, configuration, and secrets
delete       no	      Delete secrets and configuration
list         no	      List data or secrets
login        no	      Authenticate locally
status       yes      Print seal and HA status
unwrap       no	      Unwrap a wrapped secret
audit        no	      Interact with audit devices
auth         no	      Interact with auth methods
lease        no	      Interact with leases
operator     no	      Perform operator-specific tasks
path-help    no	      Retrieve API help for paths
plugin       no	      Interact with Vault plugins and catalog
policy       no	      Interact with policies
secrets      no	      Interact with secrets engines
ssh          no	      Initiate an SSH session
token        no	      Interact with tokens
========= =========== ========================================

.. note::
   `hvac-cli` does not implement any Vault features that are not
   available under a Free Software license.

.. toctree::
  :hidden:
  :maxdepth: 1

  development

