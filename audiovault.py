import asyncio
import httpx
import getpass
import keyring
import sys
import configparser
import re
import zipfile
import tempfile
import shutil
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any, Union
from bs4 import BeautifulSoup
from bs4.element import Tag
from tqdm.asyncio import tqdm as tqdm_asyncio
from tqdm.asyncio import tqdm_asyncio as tqdm_asyncio_gather

CONFIG_FILE = "config.ini"
DEFAULT_DOWNLOAD_DIR = "downloads"
VERSION = "1.2-async"
BASE_URL = "https://audiovault.net"
KEYRING_SERVICE = "audiovault_downloader"
DOWNLOAD_CONCURRENCY_LIMIT = 2
DOWNLOAD_RATE_LIMIT_SECONDS = 1.0


def find_tag(soup: Union[BeautifulSoup, Tag], *args, **kwargs) -> Tag | None:
    """Find a tag and return it if it's a Tag instance, None otherwise."""
    result = soup.find(*args, **kwargs)
    return result if isinstance(result, Tag) else None


def find_all_tags(soup: Union[BeautifulSoup, Tag], *args, **kwargs) -> List[Tag]:
    """Find all tags and return only Tag instances."""
    return [el for el in soup.find_all(*args, **kwargs) if isinstance(el, Tag)]


def bytes2human(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    symbols = ("KB", "MB", "GB", "TB", "PB")
    for i, s in enumerate(symbols):
        power = 1 << ((i + 1) * 10)
        if n < power:
            value = float(n) / (1 << (i * 10))
            return f"{value:.1f}{symbols[i - 1] if i > 0 else 'B'}"
    return f"{n}B"


def sanitize_name(name: str) -> str:
    """Replace filesystem-invalid characters in a name with underscores."""
    return re.sub(r'[<>:"/\\|?*]', "_", name)


class ConfigManager:
    """Configuration file management for application settings.

    Handles reading, writing, and managing configuration data stored in INI format.
    Provides convenient methods for accessing common settings like download directory
    and email address.

    Attributes:
        filename: Path to the INI configuration file.
        config: ConfigParser instance containing the configuration data.
    """

    def __init__(self, filename: str = CONFIG_FILE):
        self.filename = Path(filename)
        self.config = configparser.ConfigParser()
        self.read()

    def read(self) -> None:
        if self.filename.exists():
            try:
                self.config.read(self.filename, encoding="utf-8")
            except Exception as e:
                print(f"Error reading config file: {e}")
                self.config = configparser.ConfigParser()
        else:
            # Create default section
            self.config.add_section("settings")

    def write(self) -> None:
        with self.filename.open("w", encoding="utf-8") as f:
            self.config.write(f)

    def get(self, key: str, default=None) -> str | None:
        return self.config.get("settings", key, fallback=default)

    def set(self, key: str, value) -> None:
        if not self.config.has_section("settings"):
            self.config.add_section("settings")
        self.config.set("settings", key, str(value))
        self.write()

    def get_download_dir(self) -> Path:
        dir_path = self.get("download_dir", DEFAULT_DOWNLOAD_DIR)
        return Path(dir_path or DEFAULT_DOWNLOAD_DIR).expanduser().resolve()

    def set_download_dir(self, dir_path: Path) -> None:
        self.set("download_dir", str(dir_path.expanduser().resolve()))

    def get_dropbox_dir(self) -> Path | None:
        dir_path = self.get("dropbox_dir")
        if not dir_path or not dir_path.strip():
            return None
        return Path(dir_path).expanduser().resolve()

    def set_dropbox_dir(self, dir_path: Path | None) -> None:
        value = str(dir_path.expanduser().resolve()) if dir_path else ""
        self.set("dropbox_dir", value)

    def get_email(self) -> str | None:
        return self.get("email")

    def set_email(self, email: str) -> None:
        self.set("email", email)


class AsyncLimiter:
    """Async context manager for rate limiting operations.

    Ensures a minimum time interval between operations when used as an async context
    manager. Uses a lock to serialize access and maintains the last call timestamp
    to enforce the minimum interval.

    Attributes:
        min_interval_seconds: Minimum time in seconds between operations.
        _lock: Asyncio lock for thread-safe access to timing state.
        _last_call: Timestamp of the last operation completion.
    """

    def __init__(self, min_interval_seconds=1.0):
        self.min_interval_seconds = min_interval_seconds
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def __aenter__(self):
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_call
            if elapsed < self.min_interval_seconds:
                await asyncio.sleep(self.min_interval_seconds - elapsed)
            self._last_call = asyncio.get_event_loop().time()

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass


class AudioVaultAuth:
    """Handles authentication and session management for AudioVault.net.

    Manages login credentials, session tokens, and authentication state.
    Provides methods for logging in, checking authentication status, and
    handling authentication failures with retry logic.

    Attributes:
        config: ConfigManager instance for accessing stored email.
        client: HTTP client for making authentication requests.
        logged_in: Boolean flag indicating current authentication status.
        login_failures: Counter for tracking consecutive login failures.
    """

    def __init__(self, config: ConfigManager, client: httpx.AsyncClient):
        self.config = config
        self.client = client
        self.logged_in = False
        self.login_failures = 0

    async def authenticate(self) -> bool:
        """Authenticate user with stored or prompted credentials.

        Returns:
            True if authentication successful, False otherwise.
        """
        try:
            email = self.config.get_email()
            if not email:
                email = input("Email: ").strip()
                self.config.set_email(email)
            password = keyring.get_password(KEYRING_SERVICE, email)
            if not password:
                password = getpass.getpass("Password: ")
                save_password_response = (
                    input("Save password in system keyring? (y/N): ").strip().lower()
                )
                if save_password_response == "y":
                    keyring.set_password(KEYRING_SERVICE, email, password)
        except KeyboardInterrupt:
            print("\nAuthentication cancelled.")
            return False
        retry = 0
        while retry < 3:
            ok = await self.login(email, password or "")
            if ok:
                self.logged_in = True
                print("Login successful.\n")
                self.login_failures = 0
                return True
            else:
                print("Incorrect email or password.")
                retry += 1
                self.login_failures += 1
                if retry >= 3:
                    print("Too many login failures.")
                    break
                try:
                    retry_authentication_response = (
                        input("Try again or update password? (y/N): ").strip().lower()
                    )
                    if retry_authentication_response.startswith("y"):
                        self.set_password_interactively(email)
                        password = keyring.get_password(KEYRING_SERVICE, email)
                    else:
                        break
                except KeyboardInterrupt:
                    print("\nAuthentication cancelled.")
                    break
        return False

    async def login(self, email: str, password: str) -> bool:
        """Perform login with email and password.

        Args:
            email: User email address.
            password: User password.

        Returns:
            True if login successful, False otherwise.
        """
        try:
            resp = await self.client.get(f"{BASE_URL}/login")
            text = resp.text
            soup = BeautifulSoup(text, "html.parser")
            token_tag = find_tag(soup, "input", {"name": "_token"})
            if not token_tag:
                print("Failed to get login token.")
                return False
            token_value = token_tag.get("value")
            if not token_value:
                print("Token element missing 'value' attribute.")
                return False
            data = {"_token": token_value, "email": email, "password": password}
            resp2 = await self.client.post(f"{BASE_URL}/login", data=data)
            location = resp2.headers.get("Location", "")
            redirects_to_login = (
                httpx.URL(location).path.rstrip("/") == "/login" if location else False
            )
            return resp2.status_code in (301, 302, 303) and not redirects_to_login
        except Exception as e:
            print("Login error:", e)
            return False

    async def ensure_login(self) -> None:
        """Ensure user is authenticated, prompt for login if not.

        Raises:
            RuntimeError: If authentication fails.
        """
        if not self.logged_in:
            ok = await self.authenticate()
            if not ok:
                raise RuntimeError("Authentication failed, cannot continue.")

    def set_password_interactively(self, email: str) -> None:
        """Prompt user to set password interactively.

        Args:
            email: Email address for password storage.
        """
        try:
            new_password = getpass.getpass(f"Enter new password for {email}: ")
            password_confirmation = getpass.getpass("Confirm password: ")
            if new_password != password_confirmation:
                print("Passwords do not match.")
                return self.set_password_interactively(email)
            keyring.set_password(KEYRING_SERVICE, email, new_password)
            print("Password saved in system keyring.")
        except KeyboardInterrupt:
            print("\nPassword setup cancelled.")
            return


class ContentParser:
    """Handles parsing of HTML content from AudioVault.net.

    Provides methods for extracting movie and TV show information from
    HTML pages, including search results and recent content listings.
    """

    @staticmethod
    def parse_table(html: str) -> List[Tuple[str, str, str]]:
        """Parse HTML table containing content listings.

        Args:
            html: HTML content containing table.

        Returns:
            List of tuples (id, name, url) for each content item.
        """
        soup = BeautifulSoup(html, "html.parser")
        tbody = find_tag(soup, "tbody")
        if not tbody:
            return []
        return ContentParser.parse_rows(tbody)

    @staticmethod
    def parse_rows(table: Tag) -> List[Tuple[str, str, str]]:
        """Parse table rows to extract content information.

        Args:
            table: BeautifulSoup table element.

        Returns:
            List of tuples (id, name, url) for each content item.
        """
        results: List[Tuple[str, str, str]] = []
        for row in find_all_tags(table, "tr"):
            cells = find_all_tags(row, "td")
            if len(cells) < 3:
                continue
            id_ = cells[0].get_text(strip=True)
            name = cells[1].get_text(strip=True)
            link_tag = find_tag(cells[2], "a")
            if not (link_tag and "href" in link_tag.attrs):
                continue
            link = str(link_tag["href"])
            results.append((id_, name, link))
        return results

    @staticmethod
    def find_recent_table(html: str, kind: str) -> Tag | None:
        """Find recent content table in HTML.

        Args:
            html: HTML content from main page.
            kind: Content type ('movies' or 'shows').

        Returns:
            BeautifulSoup table element or None if not found.
        """
        soup = BeautifulSoup(html, "html.parser")
        h5_tags = find_all_tags(soup, "h5")
        for h5 in h5_tags:
            if h5.text.strip().startswith("Recent") and kind.capitalize() in h5.text:
                table_candidate = h5.find_next("tbody")
                if isinstance(table_candidate, Tag):
                    return table_candidate
        return None

    @staticmethod
    def extract_filename(response: httpx.Response) -> str | None:
        """Extract filename from HTTP response headers.

        Args:
            response: HTTP response object.

        Returns:
            Extracted filename or None if not found.
        """
        cd = response.headers.get("Content-Disposition")
        if not cd:
            return None
        match = re.search(r"filename\*?=(?:UTF-8\'\')?\"?([^\";\n]*)", cd)
        return match.group(1) if match else None


class TVShowExtractor:
    """Handles TV show specific operations including parsing and file extraction.

    Provides methods for parsing TV show names, extracting season information,
    and handling zip file extraction to organized directory structures.

    Attributes:
        tv_dir: Base directory for TV show downloads.
    """

    def __init__(self, tv_dir: Path):
        self.tv_dir = tv_dir

    @staticmethod
    def parse_tv_show_season(name: str) -> Tuple[str, str]:
        """Parse TV show name to extract show name and season.

        Args:
            name: Full show name from website (e.g., "Breaking Bad - Season 1")

        Returns:
            Tuple of (show_name, season) where season is formatted as "Season X"
        """
        # Handle "Show Name - Season X" pattern
        if " - Season " in name:
            parts = name.split(" - Season ", 1)
            if len(parts) == 2:
                show_name = parts[0].strip()
                season_num = parts[1].strip()
                return show_name, f"Season {season_num}"

        # Handle "Show Name S01" or "Show Name S1" pattern
        season_match = re.search(r"^(.+?)\s+S(\d+)$", name, re.IGNORECASE)
        if season_match:
            show_name = season_match.group(1).strip()
            season_num = season_match.group(2).lstrip("0") or "0"
            return show_name, f"Season {season_num}"

        # Handle "Show Name (Season X)" pattern
        season_match = re.search(r"^(.+?)\s*\(Season\s+(\d+)\)$", name, re.IGNORECASE)
        if season_match:
            show_name = season_match.group(1).strip()
            season_num = season_match.group(2)
            return show_name, f"Season {season_num}"

        # Fallback: use full name as show name, no season
        return name.strip(), "Season 1"

    def extract_tv_zip(self, zip_path: Path, show_name: str, season: str) -> bool:
        """Extract TV show zip file to season-specific directory.

        Args:
            zip_path: Path to the downloaded zip file
            show_name: Name of the TV show
            season: Season identifier (e.g., "Season 1")

        Returns:
            True if extraction successful, False otherwise
        """
        try:
            # Sanitize directory name
            safe_show_name = sanitize_name(show_name)
            safe_season = sanitize_name(season)
            season_dir = self.tv_dir / f"{safe_show_name} - {safe_season}"

            # Create season directory
            season_dir.mkdir(parents=True, exist_ok=True)

            # Extract zip file using temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                with zipfile.ZipFile(zip_path, "r") as zip_ref:
                    # Extract all files to temp directory first
                    zip_ref.extractall(temp_path)

                    # Move all extracted files to season directory
                    for item in temp_path.rglob("*"):
                        if item.is_file():
                            # Use just the filename to flatten the structure
                            target_path = season_dir / item.name

                            # Handle filename conflicts by adding numbers
                            counter = 1
                            original_target = target_path
                            while target_path.exists():
                                stem = original_target.stem
                                suffix = original_target.suffix
                                target_path = season_dir / f"{stem}_{counter}{suffix}"
                                counter += 1

                            # Move file to final destination using shutil for cross-filesystem moves
                            shutil.move(str(item), str(target_path))

            print(f"Extracted to: {season_dir}")

            return True

        except Exception as e:
            print(f"Extraction error for {zip_path}: {e}")
            return False


class AudioVaultDownloaderAsync:
    """Main application class for downloading audio described content from AudioVault.net.

    Provides an interactive command-line interface for searching, browsing, and downloading
    movies and TV shows with audio descriptions. Focuses on UI and download orchestration
    while delegating specialized tasks to helper classes.

    Attributes:
        config: ConfigManager instance for managing application settings.
        client: HTTP client for making requests to the AudioVault website.
        auth: AudioVaultAuth instance for handling authentication.
        content_parser: ContentParser instance for HTML parsing.
        tv_extractor: TVShowExtractor instance for TV show operations.
        download_dir: Base directory for all downloads.
        movies_dir: Subdirectory for movie downloads.
        tv_dir: Subdirectory for TV show downloads.
        download_semaphore: Semaphore for limiting concurrent downloads.
        download_limiter: AsyncLimiter for rate limiting download requests.
    """

    def __init__(self):
        self.config = ConfigManager()
        self.client: httpx.AsyncClient | None = None
        self.auth: AudioVaultAuth | None = None
        self.content_parser = ContentParser()

        self.download_dir = self.config.get_download_dir()
        self.movies_dir = self.download_dir / "movies"
        self.tv_dir = self.download_dir / "tv"
        self.tv_extractor = TVShowExtractor(self.tv_dir)
        self.check_and_prepare_dirs()
        self.download_semaphore = asyncio.Semaphore(DOWNLOAD_CONCURRENCY_LIMIT)
        self.download_limiter = AsyncLimiter(DOWNLOAD_RATE_LIMIT_SECONDS)

    def check_and_prepare_dirs(self) -> None:
        while not self.download_dir.is_dir():
            print(f"Download directory does not exist: {self.download_dir}")
            try:
                create_directory_response = (
                    input(f"Create directory {self.download_dir}? (y/N): ")
                    .strip()
                    .lower()
                )
            except KeyboardInterrupt:
                print("\nExiting: Directory setup cancelled.")
                sys.exit(0)
            if create_directory_response == "y":
                self.download_dir.mkdir(parents=True, exist_ok=True)
                print("Directory created:", self.download_dir)
                break
            else:
                try:
                    alternative_directory = input(
                        "Enter a different download directory: "
                    ).strip()
                except KeyboardInterrupt:
                    print("\nExiting: Directory setup cancelled.")
                    sys.exit(0)
                if alternative_directory:
                    self.download_dir = (
                        Path(alternative_directory).expanduser().resolve()
                    )
                    self.config.set_download_dir(self.download_dir)
                    self.movies_dir = self.download_dir / "movies"
                    self.tv_dir = self.download_dir / "tv"
                else:
                    print("Exiting: No valid download directory.")
                    sys.exit(1)
        self.movies_dir.mkdir(parents=True, exist_ok=True)
        self.tv_dir.mkdir(parents=True, exist_ok=True)

    async def run(self) -> None:
        print(f"\nAudioVault.net Downloader v{VERSION}")
        print(f"All downloads will be stored in: {self.download_dir}")
        print()
        timeout_config = httpx.Timeout(
            connect=30.0,  # 30s to establish connection
            read=300.0,  # 5 minutes for reading large files
            write=30.0,  # 30s for writing
            pool=30.0,  # 30s to acquire connection from pool
        )
        async with httpx.AsyncClient(
            timeout=timeout_config,
            headers={"User-Agent": f"audiovault-downloader/{VERSION}"},
        ) as client:
            self.client = client
            self.auth = AudioVaultAuth(self.config, client)
            while True:
                action = self.show_menu(
                    "Choose an action:",
                    [
                        "Find/download a movie",
                        "Find/download a TV show",
                        "List recent movies",
                        "List recent TV shows",
                        "Change settings",
                        "Exit",
                    ],
                )
                if action == 0:
                    await self.handle_search(kind="movies")
                elif action == 1:
                    await self.handle_search(kind="shows")
                elif action == 2:
                    await self.handle_recent(kind="movies")
                elif action == 3:
                    await self.handle_recent(kind="shows")
                elif action == 4:
                    self.change_settings()
                elif action == 5:
                    print("Goodbye!")
                    break

    def show_menu(self, prompt: str, options: List[str]) -> int:
        while True:
            print()
            for idx, opt in enumerate(options, 1):
                print(f"{idx}. {opt}")
            try:
                user_input = input(f"{prompt} [1-{len(options)}]: ")
                if not user_input.strip():
                    continue
                choice = int(user_input.strip())
                if 1 <= choice <= len(options):
                    return choice - 1
            except KeyboardInterrupt:
                print("\nExiting...")
                sys.exit(0)
            except EOFError:
                print("\nNo input available. Exiting...")
                sys.exit(0)
            except (ValueError, TypeError):
                pass
            print("Invalid input, try again.")

    def change_settings(self) -> None:
        while True:
            choice = self.show_menu(
                "Choose a setting to change:",
                [
                    f"Download directory ({self.download_dir})",
                    f"Email ({self.config.get_email() or 'none'})",
                    "Password",
                    f"Dropbox folder ({self.config.get_dropbox_dir() or 'not set'})",
                    "Back to main menu",
                ],
            )
            try:
                if choice == 0:
                    self.change_download_dir()
                elif choice == 1:
                    self.change_email()
                elif choice == 2:
                    self.change_password()
                elif choice == 3:
                    self.change_dropbox_dir()
                elif choice == 4:
                    return
            except KeyboardInterrupt:
                print("\nChange cancelled.")

    def change_download_dir(self) -> None:
        download_directory = input("New download directory (blank to cancel): ").strip()
        if not download_directory:
            return
        self.download_dir = Path(download_directory).expanduser().resolve()
        self.config.set_download_dir(self.download_dir)
        self.movies_dir = self.download_dir / "movies"
        self.tv_dir = self.download_dir / "tv"
        self.check_and_prepare_dirs()
        print(f"Download directory set to: {self.download_dir}")

    def change_email(self) -> None:
        email_address = input("New email address (blank to cancel): ").strip()
        if not email_address:
            return
        self.config.set_email(email_address)
        print(f"Email set to: {email_address}")

    def change_password(self) -> None:
        email_address = self.config.get_email()
        if not email_address:
            print("Set an email address first.")
            return
        if self.auth:
            self.auth.set_password_interactively(email_address)

    def change_dropbox_dir(self) -> None:
        dropbox_input = input(
            "New Dropbox folder ('-' to disable, blank to cancel): "
        ).strip()
        if not dropbox_input:
            return
        if dropbox_input == "-":
            self.config.set_dropbox_dir(None)
            print("Dropbox copying disabled.")
            return
        dropbox_path = Path(dropbox_input).expanduser().resolve()
        if dropbox_path.is_dir():
            self.config.set_dropbox_dir(dropbox_path)
            print(f"Dropbox folder set to: {dropbox_path}")
        else:
            print(f"Folder does not exist: {dropbox_path}. Dropbox folder not changed.")

    async def handle_search(self, kind: str) -> None:
        try:
            search_query = input(f"Search {kind} title: ").strip()
            if not search_query:
                print("Search cancelled.")
                return
            entries = await self.search(search_query, kind)
            await self.choose_and_download(entries, kind=kind)
        except KeyboardInterrupt:
            print("\nSearch cancelled.")
            return
        except EOFError:
            print("\nNo input available. Search cancelled.")
            return

    async def handle_recent(self, kind: str) -> None:
        entries = await self.get_recents(kind)
        await self.choose_and_download(entries, kind=kind)

    async def choose_and_download(
        self, entries: List[Tuple[str, str, str]], kind: str = "movies"
    ) -> None:
        if not entries:
            print("No results found.\n")
            return
        titles = [
            f"{i + 1}. {name} (ID: {id})" for i, (id, name, _) in enumerate(entries)
        ]
        for title_with_number in titles:
            print(title_with_number)
        print("Enter item numbers to download (separated by spaces). Blank to cancel.")
        try:
            user_selection = input("Selection: ").strip()
        except KeyboardInterrupt:
            print("\nSelection cancelled.")
            return
        if not user_selection:
            return
        valid_indexes = []
        for value in user_selection.split():
            try:
                index = int(value) - 1
                if 0 <= index < len(entries):
                    valid_indexes.append(index)
            except Exception:
                continue
        if not valid_indexes:
            print("No valid selection.")
            return
        targets = [entries[i] for i in valid_indexes]
        if self.auth:
            await self.auth.ensure_login()

        dropbox_copy_dir = None
        dropbox_dir = self.config.get_dropbox_dir()
        if dropbox_dir:
            try:
                copy_to_dropbox = (
                    input("Copy finished downloads to your Dropbox folder? (y/N): ")
                    .strip()
                    .lower()
                    == "y"
                )
            except KeyboardInterrupt:
                print("\nDropbox copy skipped.")
                copy_to_dropbox = False
            if copy_to_dropbox:
                dropbox_copy_dir = dropbox_dir / (
                    "movies" if kind == "movies" else "tv"
                )

        # Prepare tasks
        kind_dir = self.movies_dir if kind == "movies" else self.tv_dir
        status: Dict[str, Dict[str, Any]] = {
            name: {"status": "queued", "size": 0, "duration": 0.0, "speed": 0.0}
            for _, name, _ in targets
        }
        tasks = []
        for id, name, url in targets:
            task = asyncio.create_task(
                self.download_with_status(
                    url,
                    kind_dir,
                    name,
                    status,
                    kind,
                    dropbox_copy_dir=dropbox_copy_dir,
                )
            )
            tasks.append(task)

        print("Starting downloads...")
        start_time = time.time()
        try:
            await tqdm_asyncio_gather.gather(*tasks, desc="Downloading files")
        except KeyboardInterrupt:
            print("\nDownload cancelled by user.")
            # Cancel remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
            # Wait a moment for tasks to clean up
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=2.0,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
        except Exception as e:
            print("Download process interrupted:", e)
        total_time = time.time() - start_time

        print("\nSummary:")
        total_size = 0
        successful_downloads = 0
        for _, name, _ in targets:
            download_info = status[name]
            if download_info["status"] == "done":
                successful_downloads += 1
                file_size = int(download_info["size"])
                total_size += file_size
                size_str = bytes2human(file_size) if file_size > 0 else "unknown size"
                speed_val = float(download_info["speed"])
                speed_str = (
                    f"{bytes2human(int(speed_val))}/s"
                    if speed_val > 0
                    else "unknown speed"
                )
                duration_val = float(download_info["duration"])
                time_str = (
                    f"{duration_val:.1f}s" if duration_val > 0 else "unknown time"
                )
                print(
                    f"  {name}: {download_info['status']} ({size_str}, {speed_str}, {time_str})"
                )
            else:
                print(f"  {name}: {download_info['status']}")

        if successful_downloads > 0:
            avg_speed = total_size / total_time if total_time > 0 else 0
            print(
                f"\nTotal: {successful_downloads} files, {bytes2human(total_size)}, {total_time:.1f}s, avg {bytes2human(int(avg_speed))}/s"
            )

        # Collect failed
        failed = [
            t
            for t, (_, name, _) in zip(tasks, targets)
            if str(status[name]["status"]).startswith("failed")
        ]
        if failed:
            print(f"\nFailed downloads: {len(failed)}")
            try:
                retry_response = (
                    input("Retry failed downloads? (y/N): ").strip().lower() == "y"
                )
            except KeyboardInterrupt:
                print("\nRetry cancelled.")
                return
            if retry_response:
                for item_id, name, url in targets:
                    if str(status[name]["status"]).startswith("failed"):
                        await self.download_with_status(
                            url,
                            kind_dir,
                            name,
                            status,
                            kind,
                            dropbox_copy_dir=dropbox_copy_dir,
                        )

    async def download_with_status(
        self,
        url,
        dest_dir,
        name,
        status_dict,
        kind="movies",
        dropbox_copy_dir: Path | None = None,
    ):
        status_dict[name]["status"] = "downloading"
        start_time = time.time()
        try:
            async with self.download_semaphore:
                async with self.download_limiter:
                    # For TV shows, parse the name to get show and season info
                    if kind == "shows":
                        show_name, season = self.tv_extractor.parse_tv_show_season(name)
                        ok, file_size = await self.download_file(
                            url,
                            dest_dir,
                            is_tv_show=True,
                            show_name=show_name,
                            season_info=season,
                            dropbox_copy_dir=dropbox_copy_dir,
                        )
                    else:
                        ok, file_size = await self.download_file(
                            url, dest_dir, dropbox_copy_dir=dropbox_copy_dir
                        )

                    end_time = time.time()
                    duration = end_time - start_time
                    speed = file_size / duration if duration > 0 else 0

                    status_dict[name]["status"] = "done" if ok else "failed"
                    status_dict[name]["size"] = file_size
                    status_dict[name]["duration"] = duration
                    status_dict[name]["speed"] = speed
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            status_dict[name]["status"] = f"failed: {e}"
            status_dict[name]["duration"] = duration

    async def search(self, query: str, kind: str) -> List[Tuple[str, str, str]]:
        if not self.client:
            raise RuntimeError("Client not initialized")
        resp = await self.client.get(f"{BASE_URL}/{kind}", params={"search": query})
        text = resp.text
        return self.content_parser.parse_table(text)  # type: ignore[no-any-return]

    async def get_recents(self, kind: str) -> List[Tuple[str, str, str]]:
        if not self.client:
            raise RuntimeError("Client not initialized")
        resp = await self.client.get(BASE_URL)
        text = resp.text
        table = self.content_parser.find_recent_table(text, kind)
        if not table:
            print(f"Could not find recent section for {kind}.\n")
            return []
        return self.content_parser.parse_rows(table)  # type: ignore[no-any-return]

    async def copy_to_dropbox(
        self, source: Path, dropbox_copy_dir: Path, target_name: str
    ) -> None:
        """Copy a finished download into the configured Dropbox folder.

        Args:
            source: Path to the completed local download.
            dropbox_copy_dir: Dropbox subdirectory for the content type.
            target_name: Filename to use for the copied download.
        """
        try:
            dropbox_copy_dir.mkdir(parents=True, exist_ok=True)
            target_path = dropbox_copy_dir / target_name
            await asyncio.to_thread(shutil.copy2, source, target_path)
            print(f"Copied to Dropbox: {target_path}")
        except Exception as e:
            print(f"Dropbox copy failed for {target_name}: {e}")

    async def download_file(
        self,
        url: str,
        dest_dir: Path,
        is_tv_show: bool = False,
        show_name: str = "",
        season_info: str = "",
        dropbox_copy_dir: Path | None = None,
    ) -> Tuple[bool, int]:
        # For TV shows, create the show-specific directory structure
        if is_tv_show and show_name and season_info:
            safe_show_name = sanitize_name(show_name)
            safe_season = sanitize_name(season_info)
            final_dest_dir = dest_dir / f"{safe_show_name} - {safe_season}"
            final_dest_dir.mkdir(parents=True, exist_ok=True)
        else:
            final_dest_dir = dest_dir
            final_dest_dir.mkdir(parents=True, exist_ok=True)

        try:
            if not self.client:
                raise RuntimeError("Client not initialized")

            for attempt in range(2):
                authentication_to_retry: AudioVaultAuth | None = None
                retry_delay: int | None = None

                async with self.client.stream("GET", url) as resp:
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if resp.status_code in (302, 401) or "text/html" in content_type:
                        if attempt == 1 or not self.auth:
                            print("Access error, stopping download.")
                            return False, 0
                        authentication_to_retry = self.auth
                    elif resp.status_code == 429 or resp.status_code >= 500:
                        if attempt == 1:
                            resp.raise_for_status()
                        retry_after = resp.headers.get("Retry-After", "")
                        try:
                            retry_delay = int(retry_after)
                        except ValueError:
                            retry_delay = 30
                    else:
                        resp.raise_for_status()
                        total = int(resp.headers.get("Content-Length", 0))

                        # For TV shows, download to a temporary file first
                        if is_tv_show and show_name and season_info:
                            with tempfile.NamedTemporaryFile(
                                delete=False, suffix=".zip"
                            ) as temp_file:
                                temp_path = Path(temp_file.name)

                                # Create progress bar for TV show download
                                desc = f"{show_name} - {season_info}"
                                progress_bar = tqdm_asyncio(
                                    desc=desc,
                                    total=total,
                                    unit="B",
                                    unit_scale=True,
                                    unit_divisor=1024,
                                    disable=total == 0,
                                )

                                bytes_downloaded = 0
                                async for chunk in resp.aiter_bytes(65536):
                                    if chunk:
                                        temp_file.write(chunk)
                                        bytes_downloaded += len(chunk)
                                        progress_bar.update(len(chunk))

                                progress_bar.close()

                            # Extract directly to final destination
                            extraction_success = self.tv_extractor.extract_tv_zip(
                                temp_path, show_name, season_info
                            )

                            if extraction_success and dropbox_copy_dir:
                                await self.copy_to_dropbox(
                                    temp_path,
                                    dropbox_copy_dir,
                                    f"{sanitize_name(show_name)} - "
                                    f"{sanitize_name(season_info)}.zip",
                                )

                            # Clean up temp file
                            temp_path.unlink()

                            if not extraction_success:
                                print("Warning: Failed to extract TV show")
                                return False, bytes_downloaded

                            return True, bytes_downloaded

                        filename = self.content_parser.extract_filename(resp) or (
                            f"download_{url.rsplit('/', 1)[-1] or 'file'}"
                        )
                        destination = final_dest_dir / filename

                        # Create progress bar for movie download
                        progress_bar = tqdm_asyncio(
                            desc=filename,
                            total=total,
                            unit="B",
                            unit_scale=True,
                            unit_divisor=1024,
                            disable=total == 0,
                        )

                        bytes_downloaded = 0
                        with open(destination, "wb") as destination_file:
                            async for chunk in resp.aiter_bytes(65536):
                                if chunk:
                                    destination_file.write(chunk)
                                    bytes_downloaded += len(chunk)
                                    progress_bar.update(len(chunk))

                        progress_bar.close()
                        if dropbox_copy_dir:
                            await self.copy_to_dropbox(
                                destination, dropbox_copy_dir, filename
                            )
                        return True, bytes_downloaded

                if authentication_to_retry:
                    authentication_to_retry.logged_in = False
                    await authentication_to_retry.ensure_login()
                elif retry_delay is not None:
                    print(f"Server unavailable, retrying in {retry_delay} seconds.")
                    await asyncio.sleep(retry_delay)
        except Exception as e:
            print(f"Download error for {url}: {e}")
            return False, 0

        return False, 0


if __name__ == "__main__":
    try:
        asyncio.run(AudioVaultDownloaderAsync().run())
    except KeyboardInterrupt:
        print("\nExited.")
        sys.exit(0)
