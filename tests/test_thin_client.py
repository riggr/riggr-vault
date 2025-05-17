import pytest
from httpx import HTTPStatusError, Response
from riggr_vault.thin_client import VaultThinClient

pytestmark = pytest.mark.asyncio

async def test_init_with_valid_url(vault_url):
    """Test initialization with a valid URL"""
    client = VaultThinClient(vault_url)
    assert client._httpx is not None
    await client.close()

async def test_init_with_empty_url():
    """Test initialization with an empty URL"""
    with pytest.raises(ValueError, match="Vault URL is required"):
        VaultThinClient("")

async def test_context_manager(vault_url):
    """Test the async context manager behavior"""
    async with VaultThinClient(vault_url) as client:
        assert client._httpx is not None
    # Client should be closed after context manager exits
    assert client._httpx.is_closed

async def test_close(vault_url):
    """Test manual close method"""
    client = VaultThinClient(vault_url)
    assert not client._httpx.is_closed
    await client.close()
    assert client._httpx.is_closed

async def test_read_cubbyhole_success(vault_url, vault_token, mock_respx):
    """Test successful cubbyhole read"""
    test_data = {"key": "value"}
    mock_respx.get("/v1/cubbyhole/test-path").mock(
        return_value=Response(200, json={"data": test_data})
    )

    async with VaultThinClient(vault_url) as client:
        result = await client.read_cubbyhole("test-path", vault_token)
        assert result == test_data

async def test_read_cubbyhole_error(vault_url, vault_token, mock_respx):
    """Test cubbyhole read with error"""
    mock_respx.get("/v1/cubbyhole/test-path").mock(
        return_value=Response(404, text="Not found")
    )

    async with VaultThinClient(vault_url) as client:
        with pytest.raises(HTTPStatusError):
            await client.read_cubbyhole("test-path", vault_token)

async def test_write_cubbyhole_success(vault_url, vault_token, mock_respx):
    """Test successful cubbyhole write"""
    test_data = {"key": "value"}
    mock_respx.post("/v1/cubbyhole/test-path").mock(
        return_value=Response(200)
    )

    async with VaultThinClient(vault_url) as client:
        await client.write_cubbyhole("test-path", test_data, vault_token)

async def test_write_cubbyhole_error(vault_url, vault_token, mock_respx):
    """Test cubbyhole write with error"""
    test_data = {"key": "value"}
    mock_respx.post("/v1/cubbyhole/test-path").mock(
        return_value=Response(403, text="Permission denied")
    )

    async with VaultThinClient(vault_url) as client:
        with pytest.raises(HTTPStatusError):
            await client.write_cubbyhole("test-path", test_data, vault_token)
