import pytest
import respx
from httpx import Response

@pytest.fixture
def mock_respx():
    """Fixture to provide a respx mock router"""
    with respx.mock() as respx_mock:
        yield respx_mock

@pytest.fixture
def vault_url():
    """Fixture to provide a test vault URL"""
    return "http://vault:8200"

@pytest.fixture
def vault_token():
    """Fixture to provide a test vault token"""
    return "test-token" 