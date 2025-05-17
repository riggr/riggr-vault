import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, List, Callable, Any
from httpx import HTTPStatusError
from .thin_client import VaultThinClient

logger = logging.getLogger(__name__)

class CredentialType(Enum):
    DATABASE = "database"

@dataclass
class Credential:
    """Represents a credential from OpenBao"""
    type: CredentialType
    path: str
    role: str
    lease_id: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    expires_at: Optional[float] = None

class VaultAppClient(VaultThinClient):
    """
    Client for authenticated OpenBao vault operations. The client does not have full API
    coverage, only a subset of operations are implemented as required by the Riggr platform.
    
    This client manages authentication and automatic credential renewal.
    It should be used as an async context manager to ensure proper cleanup of resources:
    
    ```python
    async with VaultClient(url, role_id, secret_id) as client:
        credentials = await client.get_database_credentials("my-role")
    ```
    
    The context manager will automatically:
    - Cancel all renewal tasks
    - Close the underlying HTTP client
    - Clean up any cached credentials
    
    If not used as a context manager, you must call `close()` manually to prevent resource leaks.
    """
    
    DEFAULT_AUTH_TTL = 3600  # 1 hour
    DEFAULT_CRED_TTL = 2764800  # 32 days
    RENEWAL_FACTOR = 0.95  # Renew at 95% of TTL
    
    def __init__(self, url: str, role_id: str, secret_id: str):
        """
        Initialize the OpenBao vault client.
        
        Args:
            url: OpenBao server URL
            role_id: AppRole role ID
            secret_id: AppRole secret ID
        """
        if not role_id or not secret_id:
            raise ValueError("AppRole credentials are required")
        self.role_id = role_id
        self._secret_id = secret_id
        self.credentials: dict[str, Credential] = {}
        self._auth_token: Optional[str] = None
        self._renewals: List[asyncio.Task] = []
        super().__init__(url)
    
    async def close(self):
        """Stop all renewal tasks and close the client"""
        if self._renewals:  
            for task in self._renewals:
                task.cancel()
        
        await super().close()
    
    async def authenticate(self) -> str | None:
        """
        Authenticate with OpenBao using AppRole and return the token.

        Although this can be called directly, it is generally not necessary
        as the client will automatically authenticate when needed.
        """
        if not self.role_id or not self._secret_id:
            raise ValueError("This operation requires AppRole credentials")

        logger.info("Authenticating with OpenBao AppRole")
        
        try:
            response = await self._httpx.post(
                "/v1/auth/approle/login",
                json={
                    "role_id": self.role_id,
                    "secret_id": self._secret_id
                }
            )
            response.raise_for_status()
            auth_data = response.json().get("auth", {})
            
            self._auth_token = auth_data.get("client_token")
            if not self._auth_token:
                raise ValueError("Failed to obtain client token")
            
            if auth_data.get("renewable"):
                ttl = auth_data.get("lease_duration", 0)

                self._create_renewal(
                    "auth",
                    ttl,
                    self._renew_auth_token,
                    fallback=self.authenticate
                )            
            return self._auth_token
            
        except HTTPStatusError as e:
            if hasattr(e, 'response') and e.response.status_code == 400:
                logger.error(f"Invalid AppRole credentials")
                raise
            else:
                logger.error(f"Auth error: {e.response.text if hasattr(e, 'response') else str(e)}")
                raise
    
    def _cancel_renewal_task(self, task_name: str) -> None:
        """Cancel a renewal task by name"""
        for task in list(self._renewals):
            if task.get_name() == task_name:
                task.cancel()
                self._renewals.remove(task)

    def _create_renewal(self, renewal_name: str, ttl: int,
                              renewal_func: Callable, fallback: Callable = None) -> None:
        """Create a renewal task and add it to the list of renewals"""
        delay = ttl * self.RENEWAL_FACTOR
        self._cancel_renewal_task(renewal_name)
        renewal_task = asyncio.create_task(
            self._schedule_renewal(
                delay,
                renewal_func,
                fallback=fallback
            ), 
            name=renewal_name
        )
        self._renewals.append(renewal_task)
    
    async def _renew_auth_token(self) -> bool:
        """Renew the auth token, return True if successful"""
        if not self._auth_token:
            logger.warning("No auth token to renew")
            return False
        
        try:
            response = await self._httpx.post(
                "/v1/auth/token/renew-self",
                headers={"X-Vault-Token": self._auth_token}
            )
            response.raise_for_status()
            auth_data = response.json().get("auth", {})

            self._auth_token = auth_data.get("client_token")
            if not self._auth_token:
                raise ValueError("Failed to obtain client token")

            if auth_data.get("renewable"):
                ttl = auth_data.get("lease_duration", 0)
                if ttl > 0:
                    self._create_renewal(
                        "auth",
                        ttl,
                        self._renew_auth_token,
                        fallback=self.authenticate
                    )
            return True
            
        except HTTPStatusError as e:
            logger.error(f"Auth token renewal error: {e.response.text if hasattr(e, 'response') else str(e)}")
            return False
    
    async def get_credential(self, cred_type: CredentialType, role: str, retry: bool = True) -> Dict[str, Any]:
        """
        Get credentials from OpenBao (or local cache) for the specified type and role.

        If the request fails with a 403 error, it is possible that the auth token has expired
        (renewal failed for some reason). By default, the client will attempt to re-authenticate
        and retry the request one time.
        
        Args:
            cred_type: Type of credential (RABBITMQ, DATABASE)
            role: Role name for the credential
            retry: Whether to retry the request if it fails with a 403 error
        Returns:
            Dictionary containing the credential data
        """
        cred_key = f"{cred_type.value}:{role}"
        if self.credentials.get(cred_key):
            return self.credentials[cred_key].data
        
        cred_path = f"{cred_type.value}/creds/{role}"
        if not self._auth_token:
            await self.authenticate()
        
        try:
            response = await self._httpx.get(
                f"/v1/{cred_path}",
                headers={"X-Vault-Token": self._auth_token}
            )
            response.raise_for_status()
            
            result = response.json()
            data = result.get("data", {})
            
            lease_id = result.get("lease_id")
            ttl = result.get("lease_duration", 0)
            
            credential = Credential(
                type=cred_type,
                path=cred_path,
                role=role,
                lease_id=lease_id,
                data=data,
                expires_at=time.time() + ttl if lease_id else None
            )
            
            self.credentials[cred_key] = credential
            
            if lease_id:
                self._create_renewal(
                    cred_key,
                    ttl,
                    lambda: self._renew_credential_lease(cred_key),
                    fallback=lambda: self.get_credential(cred_type, role)
                )
            
            return data
            
        except HTTPStatusError as e:
            if hasattr(e, 'response') and e.response.status_code == 403 and retry:
                logger.warning(f"Not authenticated for {cred_type.value} {role}: token might be expired, re-authenticating")
                await self.authenticate()
                return await self.get_credential(cred_type, role, retry=False)
            
            logger.error(f"Error fetching credentials for {cred_type.value} {role}: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise
    
    async def _renew_credential_lease(self, cred_key: str) -> bool:
        """
        Renew a credential lease by its key
        
        Args:
            cred_key: The key of the credential to renew
            
        Returns:
            True if renewal was successful, False otherwise
        """
        credential = self.credentials.get(cred_key)
        if not credential or not credential.lease_id:
            logger.warning(f"No credential or lease_id for {cred_key}")
            return False
        
        if not self._auth_token:
            logger.warning(f"No auth token to renew {cred_key}")
            await self.authenticate()
        
        try:
            response = await self._httpx.post(
                f"/v1/sys/leases/renew",
                json={"lease_id": credential.lease_id},
                headers={"X-Vault-Token": self._auth_token}
            )
            response.raise_for_status()
            
            lease_data = response.json()
            ttl = lease_data.get("lease_duration", self.DEFAULT_CRED_TTL)
            credential.expires_at = time.time() + ttl
            
            self._create_renewal(
                cred_key,
                ttl,
                lambda: self._renew_credential_lease(cred_key),
                fallback=lambda: self.get_credential(credential.type, credential.role)
            )
            
            return True
            
        except HTTPStatusError as e:
            logger.error(f"Lease renewal error for {cred_key}: {e.response.text if hasattr(e, 'response') else str(e)}")
            if hasattr(e, 'response') and e.response.status_code == 403:  # Permission denied, token might be expired
                logger.info("Auth token might be expired, re-authenticating")
                await self.authenticate()
                return await self._renew_credential_lease(cred_key)
            return False
    
    async def _schedule_renewal(self, delay: float, renewal_func: Callable, fallback: Callable = None) -> None:
        """
        Schedule a renewal after delay seconds
        
        Args:
            delay: Time in seconds to wait before renewal
            renewal_func: Function to call for renewal
            fallback: Function to call if renewal fails
        """
        try:
            await asyncio.sleep(delay)
            success = await renewal_func()
            
            if not success and fallback:
                logger.info(f"Renewal failed, running fallback")
                await fallback()
                
        except asyncio.CancelledError:
            logger.debug(f"Renewal task cancelled")
        except Exception as e:
            logger.exception(f"Error in renewal task: {e}")
            if fallback:
                try:
                    await fallback()
                except Exception as fallback_error:
                    logger.exception(f"Fallback also failed: {fallback_error}")
    
    async def get_database_credentials(self, role: str) -> Dict[str, Any]:
        """Get PostgreSQL credentials"""
        return await self.get_credential(CredentialType.DATABASE, role)
    
    async def read_secret_metadata(self, path: str, mount_path: str = "secret") -> Dict[str, Any]:
        """Read the metadata for a secret"""
        if not self._auth_token:
            await self.authenticate()
        
        try:
            response = await self._httpx.get(
                f"/v1/{mount_path}/metadata/{path}",
                headers={"X-Vault-Token": self._auth_token}
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except HTTPStatusError as e:
            logger.error(f"Error reading secret metadata for {path}: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise
    
    async def read_secret(self, path: str, version: str | None = None, mount_path: str = "secret") -> Dict[str, Any]:
        """Read a secret"""
        if not self._auth_token:
            await self.authenticate()
        
        try:
            response = await self._httpx.get(
                f"/v1/{mount_path}/data/{path}{f'?version={version}' if version else ''}",
                headers={"X-Vault-Token": self._auth_token}
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except HTTPStatusError as e:
            logger.error(f"Error reading secret for {path}: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise
    
    async def create_secret(self, path: str, data: Dict[str, Any], mount_path: str = "secret") -> Dict[str, Any]:
        """Create a secret"""
        if not self._auth_token:
            await self.authenticate()
        
        try:
            response = await self._httpx.post(
                f"/v1/{mount_path}/data/{path}",
                headers={"X-Vault-Token": self._auth_token},
                json=data
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except HTTPStatusError as e:
            logger.error(f"Error creating secret for {path}: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise
    
    async def write_cubbyhole(self, path: str, data: Dict[str, Any], token: str = None) -> None:
        """Write data to a cubbyhole, either using the provided token or the current auth token"""
        if not token and not self._auth_token:
            await self.authenticate()

        await super().write_cubbyhole(path, data, token or self._auth_token)
    
    async def read_cubbyhole(self, path: str, token: str = None) -> Dict[str, Any]:
        """Read data from a cubbyhole, either using the provided token or the current auth token"""
        if not token and not self._auth_token:
            await self.authenticate()

        return await super().read_cubbyhole(path, token or self._auth_token)
    
    async def create_orphan_token(self, ttl: str = "1h", policies: List[str] = []) -> Dict[str, Any]:
        """Create a new token for the specified role"""
        if not self._auth_token:
            await self.authenticate()
        
        try:
            response = await self._httpx.post(
                f"/v1/auth/token/create-orphan",
                headers={"X-Vault-Token": self._auth_token},
                json={
                    "policies": policies,
                    "ttl": ttl
                }
            )
            response.raise_for_status()
            return response.json().get("auth", {})
        except HTTPStatusError as e:
            logger.error(f"Error creating orphan token: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise
