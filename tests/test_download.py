import io
import shutil
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from audiovault import AudioVaultDownloaderAsync, ContentParser, TVShowExtractor


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


@pytest.mark.asyncio
@respx.mock
async def test_movie_download_copies_to_dropbox(temp_dir: Path) -> None:
    """Copy a completed movie download into a new Dropbox subdirectory."""
    url = "https://audiovault.net/download/dropbox-movie"
    payload = b"movie copied to Dropbox"
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
    download_dir = temp_dir / "downloads"
    dropbox_copy_dir = temp_dir / "Dropbox" / "movies"

    async with httpx.AsyncClient() as client:
        downloader = create_downloader(client)
        result = await downloader.download_file(
            url, download_dir, dropbox_copy_dir=dropbox_copy_dir
        )

    assert result == (True, len(payload))
    assert (dropbox_copy_dir / "movie.mp3").read_bytes() == payload


@pytest.mark.asyncio
@respx.mock
async def test_dropbox_copy_failure_does_not_fail_download(temp_dir: Path) -> None:
    """Keep a successful local download when its Dropbox copy fails."""
    url = "https://audiovault.net/download/copy-failure"
    payload = b"local download survives"
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
    download_dir = temp_dir / "downloads"

    async with httpx.AsyncClient() as client:
        downloader = create_downloader(client)
        with patch.object(shutil, "copy2", side_effect=OSError("copy failed")):
            result = await downloader.download_file(
                url,
                download_dir,
                dropbox_copy_dir=temp_dir / "Dropbox" / "movies",
            )

    assert result == (True, len(payload))
    assert (download_dir / "movie.mp3").read_bytes() == payload


@pytest.mark.asyncio
@respx.mock
async def test_tv_download_copies_zip_to_dropbox(temp_dir: Path) -> None:
    """Extract a TV download locally and copy its source zip to Dropbox."""
    url = "https://audiovault.net/download/dropbox-show"
    episode_payload = b"episode audio"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zip_file:
        zip_file.writestr("episode.mp3", episode_payload)
    zip_payload = zip_buffer.getvalue()
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Length": str(len(zip_payload))},
            stream=httpx.ByteStream(zip_payload),
        )
    )
    tv_dir = temp_dir / "tv"
    dropbox_copy_dir = temp_dir / "Dropbox" / "tv"

    async with httpx.AsyncClient() as client:
        downloader = create_downloader(client)
        downloader.tv_extractor = TVShowExtractor(tv_dir)
        result = await downloader.download_file(
            url,
            tv_dir,
            is_tv_show=True,
            show_name="Test Show",
            season_info="Season 1",
            dropbox_copy_dir=dropbox_copy_dir,
        )

    assert result == (True, len(zip_payload))
    assert (tv_dir / "Test Show - Season 1" / "episode.mp3").read_bytes() == (
        episode_payload
    )
    copied_zip = dropbox_copy_dir / "Test Show - Season 1.zip"
    assert copied_zip.exists()
    assert copied_zip.read_bytes() == zip_payload
