"""Vault functions that do not require authentication"""
import logging
from httpx import AsyncClient, HTTPStatusError
from typing import Any

logger = logging.getLogger()

async def read_cubbyhole(url: str, path: str, token: str) -> dict[str, Any]:
    """Read data from a cubbyhole"""
    async with AsyncClient(base_url=url) as client:
        try:
            response = await client.get(
                f"/v1/cubbyhole/{path}",
                headers={"X-Vault-Token": token}
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except HTTPStatusError as e:
            logger.error(f"Error reading cubbyhole: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise

async def write_cubbyhole(urt: str, path: str, data: dict[str, Any], token: str = None) -> None:
    """Write data to a cubbyhole, either using the provided token or the current auth token"""
    async with AsyncClient(base_url=url) as client:
        try:
            response = await client.post(
                f"/v1/cubbyhole/{path}",
                headers={"X-Vault-Token": token},
                json=data
            )
            response.raise_for_status()
        except HTTPStatusError as e:
            logger.error(f"Error creating cubbyhole secret for {path}: {e.response.text if hasattr(e, 'response') else str(e)}")
            raise
