from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from audiovault import AudioVaultDownloaderAsync, ContentParser


def create_downloader(client: httpx.AsyncClient) -> AudioVaultDownloaderAsync:
    """Create a downloader with only the collaborators needed by download tests."""
    downloader = object.__new__(AudioVaultDownloaderAsync)
    downloader.client = client
    downloader.auth = None
    downloader.content_parser = ContentParser()
    return downloader


@pytest.mark.asyncio
@respx.mock
async def test_download_file_streams_response_to_disk(temp_dir: Path) -> None:
    """Stream a successful download to its Content-Disposition filename."""
    url = "https://audiovault.net/download/123"
    payload = b"streamed audio content"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Disposition": 'attachment; filename="movie.mp3"',
                "Content-Length": str(len(payload)),
            },
            stream=httpx.ByteStream(payload),
        )
    )

    async with httpx.AsyncClient() as client:
        downloader = create_downloader(client)
        result = await downloader.download_file(url, temp_dir)

    assert result == (True, len(payload))
    assert (temp_dir / "movie.mp3").read_bytes() == payload


@pytest.mark.asyncio
@respx.mock
async def test_download_file_reauthenticates_and_retries(temp_dir: Path) -> None:
    """Re-authenticate once when an expired session returns HTML."""
    url = "https://audiovault.net/download/456"
    payload = b"audio after login"
    route = respx.get(url).mock(
        side_effect=[
            httpx.Response(200, headers={"Content-Type": "text/html"}),
            httpx.Response(
                200,
                headers={
                    "Content-Disposition": 'attachment; filename="retry.mp3"',
                    "Content-Length": str(len(payload)),
                },
                stream=httpx.ByteStream(payload),
            ),
        ]
    )
    authentication = SimpleNamespace(logged_in=True, ensure_login=AsyncMock())

    async with httpx.AsyncClient() as client:
        downloader = create_downloader(client)
        downloader.auth = authentication
        result = await downloader.download_file(url, temp_dir)

    assert result == (True, len(payload))
    assert authentication.logged_in is False
    authentication.ensure_login.assert_awaited_once_with()
    assert route.call_count == 2
    assert (temp_dir / "retry.mp3").read_bytes() == payload


@pytest.mark.asyncio
@respx.mock
async def test_download_file_returns_failure_for_not_found(temp_dir: Path) -> None:
    """Return a failed result without writing a 404 response to disk."""
    url = "https://audiovault.net/download/missing"
    respx.get(url).mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        downloader = create_downloader(client)
        result = await downloader.download_file(url, temp_dir)

    assert result == (False, 0)
    assert list(temp_dir.iterdir()) == []
