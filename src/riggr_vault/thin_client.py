import logging
from typing import Any
from httpx import AsyncClient, HTTPStatusError

logger = logging.getLogger(__name__)

class VaultThinClient:
    """
    Base client for unauthenticated vault operations.
    
    It should be used as an async context manager to ensure proper cleanup of resources:
    
    ```python
    async with VaultThinClient(url) as client:
        secret = await client.read_cubbyhole("my-cubbyhole", "my-token")
    ```
    
    The context manager will automatically close the underlying HTTP client
    
    If not used as a context manager, you must call `close()` manually to prevent resource leaks.
    """
    def __init__(self, url: str):
        """
        Initialize the underlying HTTP client
        
        Args:
            url: OpenBao server URL
        """
        if not url:
            raise ValueError("Vault URL is required")
        
        self._httpx = AsyncClient(base_url=url)
    
    async def __aenter__(self):
        """Enter the async context manager"""
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the async context manager"""
        await self.close()
        
    async def close(self):
        """Close the underlying HTTP client"""
        if self._httpx:
            await self._httpx.aclose()
            
    async def read_cubbyhole(self, path: str, token: str) -> dict[str, Any]:
        """Read a secret from the given cubbyhole"""
        try:
            response = await self._httpx.get(
                f"/v1/cubbyhole/{path}",
                headers={"X-Vault-Token": token}
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except HTTPStatusError as e:
            logger.error(f"Error reading cubbyhole: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise
        
    async def write_cubbyhole(self, path: str, data: dict[str, Any], token: str) -> None:
        """Write a secret to the given cubbyhole"""
        try:
            response = await self._httpx.post(
                f"/v1/cubbyhole/{path}",
                headers={"X-Vault-Token": token},
                json=data
            )
            response.raise_for_status()
        except HTTPStatusError as e:
            logger.error(f"Error creating cubbyhole secret for {path}: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise
