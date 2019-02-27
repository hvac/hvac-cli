Quick start use cases
=====================

All use cases assume the `VAULT_ADDR` and `VAULT_TOKEN` environment
variables are set to values that enable interaction with the desired
Vault server.

Dump and reload all secrets
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::
   `kv erase` will permanently erase all secrets, use with caution.
   
.. code::

   $ hvac-cli kv dump > secret.json
   $ emacs secret.json
   $ hvac-cli kv erase
   $ hvac-cli kv load --file secret.json
