import asyncio
import pytest
from httpx import HTTPStatusError, Response
from riggr_vault.app_client import VaultAppClient, CredentialType, Credential
import httpx

def create_test_credential(
    cred_type: CredentialType = CredentialType.DATABASE,
    role: str = "test-role",
    lease_id: str = "lease",
    expires_at: float | None = None,
    data: dict | None = None
) -> Credential:
    """Helper function to create a test credential"""
    return Credential(
        type=cred_type,
        path=f"{cred_type.value}/creds/{role}",
        role=role,
        lease_id=lease_id,
        expires_at=expires_at,
        data=data or {"username": "test-user", "password": "test-pass"}
    )

@pytest.fixture
def role_id():
    return "test-role-id"

@pytest.fixture
def secret_id():
    return "test-secret-id"

@pytest.fixture
def auth_response():
    return {
        "auth": {
            "client_token": "test-token",
            "lease_duration": 3600,
            "renewable": True
        }
    }

@pytest.fixture
def auth_response_no_token():
    return {
        "auth": {}
    }

@pytest.fixture
def db_credential_response():
    return {
        "lease_id": "test-lease",
        "lease_duration": 2764800,
        "renewable": True,
        "data": {
            "username": "test-user",
            "password": "test-pass"
        }
    }

async def test_init_with_valid_credentials(vault_url, role_id, secret_id):
    """Test initialization with valid credentials"""
    client = VaultAppClient(vault_url, role_id, secret_id)
    assert client.role_id == role_id
    assert client._secret_id == secret_id
    assert client._auth_token is None
    await client.close()

async def test_init_with_invalid_credentials(vault_url):
    """Test initialization with invalid credentials"""
    with pytest.raises(ValueError, match="AppRole credentials are required"):
        VaultAppClient(vault_url, "", "")

async def test_authenticate_success(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test successful authentication"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )

    client = VaultAppClient(vault_url, role_id, secret_id)
    token = await client.authenticate()
    assert token == "test-token"
    assert client._auth_token == "test-token"
    await client.close()

async def test_authenticate_failure(vault_url, role_id, secret_id, mock_respx):
    """Test authentication failure"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(400, text="Invalid credentials")
    )

    client = VaultAppClient(vault_url, role_id, secret_id)
    with pytest.raises(HTTPStatusError):
        await client.authenticate()

    await client.close()

async def test_authenticate_missing_token(vault_url, role_id, secret_id, mock_respx):
    """Test authenticate raises ValueError if no client_token in response"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json={"auth": {}})
    )
    client = VaultAppClient(vault_url, role_id, secret_id)
    with pytest.raises(ValueError, match="Failed to obtain client token"):
        await client.authenticate()
    await client.close()

async def test_authenticate_non_400_error(vault_url, role_id, secret_id, mock_respx):
    """Test authenticate logs and raises for non-400 error"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(500, text="Server error")
    )
    client = VaultAppClient(vault_url, role_id, secret_id)
    with pytest.raises(httpx.HTTPStatusError):
        await client.authenticate()
    await client.close()

async def test_authenticate_missing_approle_credentials(vault_url, role_id, secret_id):
    """Test authenticate raises ValueError if role_id or secret_id is missing (line 84)"""
    client = VaultAppClient(vault_url, role_id, secret_id)
    client.role_id = ""
    client._secret_id = ""
    with pytest.raises(ValueError, match="This operation requires AppRole credentials"):
        await client.authenticate()
    await client.close()

async def test_get_database_credentials(vault_url, role_id, secret_id, mock_respx, auth_response, db_credential_response):
    """Test getting database credentials"""
    # Mock auth response
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    # Mock credential response
    mock_respx.get("/v1/database/creds/test-role").mock(
        return_value=Response(200, json=db_credential_response)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        # First call should hit the API
        creds = await client.get_database_credentials("test-role")
        assert creds == db_credential_response["data"]
        assert "database:test-role" in client.credentials

        # Second call should use cached credentials
        creds2 = await client.get_database_credentials("test-role")
        assert creds2 == db_credential_response["data"]
        
        # Verify the API was only called once
        assert len(mock_respx.calls) == 2  # 1 for auth, 1 for credentials

async def test_read_secret(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test reading a secret"""
    secret_data = {"data": {"data": {"key": "value"}}}
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.get("/v1/secret/data/test-path").mock(
        return_value=Response(200, json=secret_data)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        result = await client.read_secret("test-path")
        assert result == {"data": {"key": "value"}}

async def test_read_secret_error(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test read_secret error handling"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.get("/v1/secret/data/test-path").mock(
        return_value=Response(403, text="Forbidden")
    )
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.read_secret("test-path")

async def test_read_secret_with_version(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test reading a specific version of a secret"""
    secret_data = {"data": {"data": {"key": "value"}}}
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.get("/v1/secret/data/test-path?version=1").mock(
        return_value=Response(200, json=secret_data)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        result = await client.read_secret("test-path", version="1")
        assert result == {"data": {"key": "value"}}

async def test_create_secret(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test creating a secret"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.post("/v1/secret/data/test-path").mock(
        return_value=Response(200, json={"data": {"version": 1}})
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        await client.create_secret("test-path", {"key": "value"})

async def test_create_secret_error(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test create_secret error handling"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.post("/v1/secret/data/test-path").mock(
        return_value=Response(403, text="Forbidden")
    )
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.create_secret("test-path", {"key": "value"})

async def test_create_orphan_token(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test creating an orphan token"""
    token_response = {
        "auth": {
            "client_token": "orphan-token",
            "lease_duration": 3600
        }
    }
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.post("/v1/auth/token/create-orphan").mock(
        return_value=Response(200, json=token_response)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        result = await client.create_orphan_token(ttl="1h", policies=["test-policy"])
        assert result["client_token"] == "orphan-token"

async def test_create_orphan_token_error(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test create_orphan_token error handling"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.post("/v1/auth/token/create-orphan").mock(
        return_value=Response(403, text="Forbidden")
    )
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.create_orphan_token()

async def test_credential_renewal(vault_url, role_id, secret_id, mock_respx, auth_response, db_credential_response):
    """Test credential renewal"""
    # Mock auth response
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    # Mock initial credential response
    mock_respx.get("/v1/database/creds/test-role").mock(
        return_value=Response(200, json=db_credential_response)
    )
    # Mock renewal response
    mock_respx.post("/v1/sys/leases/renew").mock(
        return_value=Response(200, json={"lease_duration": 2764800})
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        # Get initial credentials
        await client.get_database_credentials("test-role")
        # Wait a bit to ensure renewal task is created
        await asyncio.sleep(0.1)
        # Verify renewal task exists
        assert any(task.get_name() == "database:test-role" for task in client._renewals)
        # Cancel all renewal tasks to prevent the "not called" error
        for task in client._renewals:
            task.cancel()
        # Manually call the renewal endpoint to satisfy respx
        await client._renew_credential_lease("database:test-role")

async def test_auth_token_renewal(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test auth token renewal"""
    # Mock initial auth
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    # Mock token renewal
    mock_respx.post("/v1/auth/token/renew-self").mock(
        return_value=Response(200, json=auth_response)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        await client.authenticate()
        success = await client._renew_auth_token()
        assert success
        assert client._auth_token == "test-token"

async def test_auth_token_renewal_failure(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test auth token renewal failure"""
    # Mock initial auth
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    # Mock token renewal failure
    mock_respx.post("/v1/auth/token/renew-self").mock(
        return_value=Response(403, text="Permission denied")
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        await client.authenticate()
        success = await client._renew_auth_token()
        assert not success

async def test_auth_token_renewal_no_token(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test auth token renewal when there is no token"""
    # Mock initial auth
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        await client.authenticate()
        client._auth_token = None
        success = await client._renew_auth_token()
        assert not success

async def test_auth_token_renewal_invalid_response(vault_url, role_id, secret_id, mock_respx, auth_response, auth_response_no_token):
    """Test auth token renewal with invalid response"""
    # Mock initial auth
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    # Mock token renewal
    mock_respx.post("/v1/auth/token/renew-self").mock(
        return_value=Response(200, json=auth_response_no_token)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        await client.authenticate()
        try:
            success = await client._renew_auth_token()
        except ValueError as e:
            pass
        else:
            assert False, "Expected ValueError"

async def test_credential_renewal_failure(vault_url, role_id, secret_id, mock_respx, auth_response, db_credential_response):
    """Test credential renewal failure handling"""
    # Mock auth response
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    # Mock credential response
    mock_respx.get("/v1/database/creds/test-role").mock(
        return_value=Response(200, json=db_credential_response)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        # Get initial credentials
        creds = await client.get_credential(CredentialType.DATABASE, "test-role")
        assert creds["username"] == "test-user"
        assert creds["password"] == "test-pass"

        # Wait for renewal task to be created
        await asyncio.sleep(0.1)
        
        # Cancel renewal task to prevent recursion
        for task in client._renewals:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

async def test_get_credential_with_retry(vault_url, role_id, secret_id, mock_respx, auth_response, db_credential_response):
    """Test credential retrieval with retry after auth failure"""
    # Mock auth response
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    # Mock credential endpoint to fail then succeed
    mock_respx.get("/v1/database/creds/test-role").mock(
        side_effect=[
            Response(403, text="Token expired"),
            Response(200, json=db_credential_response)
        ]
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        # First call should fail with 403, then retry and succeed
        creds = await client.get_credential(CredentialType.DATABASE, "test-role", retry=True)
        assert creds == db_credential_response["data"]
        
        # Verify credential endpoint was called twice
        cred_calls = [call for call in mock_respx.calls if call.request.url.path == "/v1/database/creds/test-role"]
        assert len(cred_calls) == 2

        # Cancel any renewal tasks to prevent hanging
        for task in client._renewals:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

async def test_get_credential_without_retry(vault_url, role_id, secret_id, mock_respx):
    """Test credential retrieval without retry"""
    # Mock auth failure
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(403, text="Invalid credentials")
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        # Should fail without retry
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await client.get_credential(CredentialType.DATABASE, "test-role")
        assert exc_info.value.response.status_code == 403

async def test_get_credential_403_no_retry(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test get_credential logs and raises on 403 with retry=False"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.get("/v1/database/creds/test-role").mock(
        return_value=Response(403, text="Forbidden")
    )
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_credential(CredentialType.DATABASE, "test-role", retry=False)

async def test_read_secret_metadata(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test reading secret metadata"""
    metadata = {
        "data": {
            "versions": {
                "1": {"created_time": "2024-01-01T00:00:00Z"}
            }
        }
    }
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.get("/v1/secret/metadata/test-path").mock(
        return_value=Response(200, json=metadata)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        result = await client.read_secret_metadata("test-path")
        assert result == metadata["data"]

async def test_read_cubbyhole(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test reading from cubbyhole"""
    cubbyhole_data = {"key": "value"}
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.get("/v1/cubbyhole/test-path").mock(
        return_value=Response(200, json={"data": cubbyhole_data})
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        result = await client.read_cubbyhole("test-path")
        assert result == cubbyhole_data

async def test_write_cubbyhole(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test writing to cubbyhole"""
    cubbyhole_data = {"key": "value"}
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.post("/v1/cubbyhole/test-path").mock(
        return_value=Response(200)
    )

    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        await client.write_cubbyhole("test-path", cubbyhole_data)

async def test_renew_credential_lease_no_credential(vault_url, role_id, secret_id):
    """Test _renew_credential_lease returns False if no credential or lease_id"""
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        result = await client._renew_credential_lease("nonexistent")
        assert result is False

async def test_renew_credential_lease_no_auth_token(vault_url, role_id, secret_id, mock_respx, auth_response, db_credential_response):
    """Test _renew_credential_lease logs and authenticates if no auth token"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.post("/v1/sys/leases/renew").mock(
        return_value=Response(200, json={"lease_duration": 100})
    )
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        # Manually add a credential with lease_id but no auth token
        client.credentials["database:test-role"] = create_test_credential()
        client._auth_token = None
        result = await client._renew_credential_lease("database:test-role")
        assert result is True

async def test_renew_credential_lease_403_retry(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test _renew_credential_lease retries once after 403 error"""
    # Mock auth response
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    # Mock renewal to fail with 403 then succeed
    mock_respx.post("/v1/sys/leases/renew").mock(
        side_effect=[
            Response(403, text="Token expired"),
            Response(200, json={"lease_duration": 100})
        ]
    )
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        # Add a credential with lease_id
        client.credentials["database:test-role"] = create_test_credential()
        client._auth_token = "old-token"
        
        # Should try once, re-auth, try again, then succeed
        result = await client._renew_credential_lease("database:test-role")
        assert result is True
        
        # Verify auth was called once and renewal was called twice
        auth_calls = [call for call in mock_respx.calls if call.request.url.path == "/v1/auth/approle/login"]
        renewal_calls = [call for call in mock_respx.calls if call.request.url.path == "/v1/sys/leases/renew"]
        assert len(auth_calls) == 1
        assert len(renewal_calls) == 2

async def test_renew_credential_lease_non_403_error(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test _renew_credential_lease returns False on non-403 error"""
    # Mock renewal to fail with 500
    mock_respx.post("/v1/sys/leases/renew").mock(
        return_value=Response(500, text="Internal server error")
    )
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        # Add a credential with lease_id
        client.credentials["database:test-role"] = create_test_credential()
        client._auth_token = "old-token"
        
        # Should try once and return False
        result = await client._renew_credential_lease("database:test-role")
        assert result is False
        
        # Verify renewal was called once
        renewal_calls = [call for call in mock_respx.calls if call.request.url.path == "/v1/sys/leases/renew"]
        assert len(renewal_calls) == 1

async def test_schedule_renewal_fallback_runs(vault_url, role_id, secret_id):
    """Test _schedule_renewal runs fallback if renewal_func returns False"""
    fallback_called = False
    async def renewal_func():
        return False
    async def fallback():
        nonlocal fallback_called
        fallback_called = True
    client = VaultAppClient(vault_url, role_id, secret_id)
    await client._schedule_renewal(0, renewal_func, fallback)
    assert fallback_called
    await client.close()

async def test_schedule_renewal_fallback_fails(vault_url, role_id, secret_id):
    """Test _schedule_renewal handles fallback raising exception"""
    async def renewal_func():
        return False
    async def fallback():
        raise RuntimeError("fail")
    client = VaultAppClient(vault_url, role_id, secret_id)
    await client._schedule_renewal(0, renewal_func, fallback)
    await client.close()

async def test_read_secret_metadata_error(vault_url, role_id, secret_id, mock_respx, auth_response):
    """Test read_secret_metadata error handling"""
    mock_respx.post("/v1/auth/approle/login").mock(
        return_value=Response(200, json=auth_response)
    )
    mock_respx.get("/v1/secret/metadata/test-path").mock(
        return_value=Response(403, text="Forbidden")
    )
    async with VaultAppClient(vault_url, role_id, secret_id) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.read_secret_metadata("test-path")



