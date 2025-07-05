import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture
def mock_keyring():
    """Mock keyring operations."""
    with patch('keyring.get_password') as get_mock, \
         patch('keyring.set_password') as set_mock:
        get_mock.return_value = "test_password"
        yield {'get': get_mock, 'set': set_mock}

@pytest.fixture
def sample_html():
    """Sample HTML content for testing parsing."""
    return """
    <html>
        <body>
            <table>
                <tbody>
                    <tr>
                        <td>123</td>
                        <td>Test Movie</td>
                        <td><a href="/download/123">Download</a></td>
                    </tr>
                </tbody>
            </table>
        </body>
    </html>
    """