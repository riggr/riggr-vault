# Riggr Vault

A client library for OpenBao vault, for use by Riggr projects that require vault access.

There are two available clients:

- `VaultAppClient`: Handles AppRole authentication and token renewal.
- `VaultThinClient`: A minimal client for operations that don't require authentication.

## Usage

You should generally use the client in an async context manager:

### VaultThinClient

```python
async with VaultThinClient(url) as client:
    data = await client.read_cubbyhole("secret/data/my-secret")
```

### VaultAppClient

```python
async with VaultAppClient(url, role_id, secret_id) as client:
    data = await client.get_database_credentials("my-role")
```

If you don't use a context manager, then you should manually call `close()` when you are done with the client instance.
