import asyncio
import httpx
import getpass
import keyring
import sys
import configparser
import re
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
from bs4 import BeautifulSoup
from bs4.element import Tag

CONFIG_FILE = "config.ini"
DEFAULT_DOWNLOAD_DIR = "downloads"
VERSION = "1.2-async"
BASE_URL = "https://audiovault.net"
KEYRING_SERVICE = "audiovault_downloader"
DOWNLOAD_CONCURRENCY_LIMIT = 5
DOWNLOAD_RATE_LIMIT_SECONDS = 1.0


def bytes2human(n: int) -> str:
    symbols = ("KB", "MB", "GB", "TB", "PB")
    for i, s in enumerate(symbols):
        power = 1 << ((i + 1) * 10)
        if n < power:
            value = float(n) / (1 << (i * 10))
            return f"{value:.1f}{symbols[i - 1] if i > 0 else 'B'}"
    return f"{n}B"


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

    def get(self, key: str, default=None) -> Optional[str]:
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

    def get_email(self) -> Optional[str]:
        return self.get("email")

    def set_email(self, email: str) -> None:
        self.set("email", email)


class AsyncLimiter:
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


class AudioVaultDownloaderAsync:
    def __init__(self):
        self.config = ConfigManager()
        self.client: Optional[httpx.AsyncClient] = None
        self.logged_in = False
        self.login_failures = 0

        self.download_dir = self.config.get_download_dir()
        self.movies_dir = self.download_dir / "movies"
        self.tv_dir = self.download_dir / "tv"
        self.check_and_prepare_dirs()
        self.download_semaphore = asyncio.Semaphore(DOWNLOAD_CONCURRENCY_LIMIT)
        self.download_limiter = AsyncLimiter(DOWNLOAD_RATE_LIMIT_SECONDS)
        self.failed_downloads = []

    def check_and_prepare_dirs(self) -> None:
        while not self.download_dir.is_dir():
            print(f"Download directory does not exist: {self.download_dir}")
            create = (
                input(f"Create directory {self.download_dir}? (y/N): ").strip().lower()
            )
            if create == "y":
                self.download_dir.mkdir(parents=True, exist_ok=True)
                print("Directory created:", self.download_dir)
                break
            else:
                new_dir = input("Enter a different download directory: ").strip()
                if new_dir:
                    self.download_dir = Path(new_dir).expanduser().resolve()
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
        async with httpx.AsyncClient() as client:
            self.client = client
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
                choice = int(input(f"{prompt} [1-{len(options)}]: "))
                if 1 <= choice <= len(options):
                    return choice - 1
            except Exception:
                pass
            print("Invalid input, try again.")

    def change_settings(self) -> None:
        print("\nSettings:")
        print(f"Current download directory: {self.download_dir}")
        print(f"Current email: {self.config.get_email() or '(none)'}")
        print("Leave blank to keep current value.")
        d = input("New download directory: ").strip()
        if d:
            self.download_dir = Path(d).expanduser().resolve()
            self.config.set_download_dir(self.download_dir)
            self.movies_dir = self.download_dir / "movies"
            self.tv_dir = self.download_dir / "tv"
            self.check_and_prepare_dirs()
        e = input("New email address: ").strip()
        if e:
            self.config.set_email(e)
        # Password change logic
        if (e or self.config.get_email()) and input(
            "Update password? (y/N): "
        ).strip().lower() == "y":
            self.set_password_interactively(self.config.get_email() or e)
        print("Settings saved.\n")

    def set_password_interactively(self, email: str) -> None:
        password = getpass.getpass(f"Enter new password for {email}: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            return self.set_password_interactively(email)
        keyring.set_password(KEYRING_SERVICE, email, password)
        print("Password saved in system keyring.")

    async def authenticate(self) -> bool:
        email = self.config.get_email()
        if not email:
            email = input("Email: ").strip()
            self.config.set_email(email)
        password = keyring.get_password(KEYRING_SERVICE, email)
        if not password:
            password = getpass.getpass("Password: ")
            save_pw = input("Save password in system keyring? (y/N): ").strip().lower()
            if save_pw == "y":
                keyring.set_password(KEYRING_SERVICE, email, password)
        retry = 0
        while retry < 3:
            ok = await self.login(email, password)
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
                if (
                    input("Try again or update password? (y/N): ")
                    .strip()
                    .lower()
                    .startswith("y")
                ):
                    self.set_password_interactively(email)
                    password = keyring.get_password(KEYRING_SERVICE, email)
                else:
                    break
        return False

    async def login(self, email: str, password: str) -> bool:
        try:
            if not self.client:
                raise RuntimeError("Client not initialized")
            resp = await self.client.get(f"{BASE_URL}/login")
            text = resp.text
            soup = BeautifulSoup(text, "html.parser")
            token_tag = soup.find("input", {"name": "_token"})
            if not isinstance(token_tag, Tag):
                print("Failed to get login token.")
                return False
            token_value = token_tag.get("value")
            if not token_value:
                print("Token element missing 'value' attribute.")
                return False
            data = {"_token": token_value, "email": email, "password": password}
            resp2 = await self.client.post(f"{BASE_URL}/login", data=data)
            t = resp2.text
            if t.startswith("<form method="):
                return False
            return True
        except Exception as e:
            print("Login error:", e)
            return False

    async def ensure_login(self) -> None:
        if not self.logged_in:
            ok = await self.authenticate()
            if not ok:
                raise RuntimeError("Authentication failed, cannot continue.")

    async def handle_search(self, kind: str) -> None:
        query = input(f"Search {kind} title: ").strip()
        if not query:
            print("Search cancelled.")
            return
        entries = await self.search(query, kind)
        await self.choose_and_download(entries, kind=kind)

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
        for t in titles:
            print(t)
        print("Enter item numbers to download (separated by spaces). Blank to cancel.")
        choice = input("Selection: ").strip()
        if not choice:
            return
        valid_indexes = []
        for val in choice.split():
            try:
                idx = int(val) - 1
                if 0 <= idx < len(entries):
                    valid_indexes.append(idx)
            except Exception:
                continue
        if not valid_indexes:
            print("No valid selection.")
            return
        targets = [entries[i] for i in valid_indexes]
        await self.ensure_login()

        # Prepare tasks
        kind_dir = self.movies_dir if kind == "movies" else self.tv_dir
        status = {name: "queued" for _, name, _ in targets}
        tasks = []
        for id, name, url in targets:
            task = asyncio.create_task(
                self.download_with_status(url, kind_dir, name, status)
            )
            tasks.append(task)

        print("Starting downloads...")
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            print("Download process interrupted:", e)
        print("\nSummary:")
        for _, name, _ in targets:
            print(f"  {name}: {status[name]}")
        # Collect failed
        failed = [
            t for t, (_, name, _) in zip(tasks, targets) if status[name] == "failed"
        ]
        if failed:
            print(f"\nFailed downloads: {len(failed)}")
            retry = input("Retry failed downloads? (y/N): ").strip().lower() == "y"
            if retry:
                for i, (id, name, url) in enumerate(targets):
                    if status[name] == "failed":
                        await self.download_with_status(url, kind_dir, name, status)

    async def download_with_status(self, url, dest_dir, name, status_dict):
        status_dict[name] = "downloading"
        try:
            async with self.download_semaphore:
                async with self.download_limiter:
                    ok = await self.download_file(url, dest_dir)
                    status_dict[name] = "done" if ok else "failed"
        except Exception as e:
            status_dict[name] = "failed"

    async def search(self, query: str, kind: str) -> List[Tuple[str, str, str]]:
        if not self.client:
            raise RuntimeError("Client not initialized")
        resp = await self.client.get(f"{BASE_URL}/{kind}", params={"search": query})
        text = resp.text
        return self.parse_table(text)

    async def get_recents(self, kind: str) -> List[Tuple[str, str, str]]:
        if not self.client:
            raise RuntimeError("Client not initialized")
        resp = await self.client.get(BASE_URL)
        text = resp.text
        soup = BeautifulSoup(text, "html.parser")
        h5_tags = soup.find_all("h5")
        table: Optional[Tag] = None
        for h5 in h5_tags:
            if (
                h5.text.strip().startswith("Recent")
                and kind.capitalize() in h5.text
            ):
                table_candidate = h5.find_next("tbody")
                if isinstance(table_candidate, Tag):
                    table = table_candidate
                    break
        if not isinstance(table, Tag):
            print(f"Could not find recent section for {kind}.\n")
            return []
        return self.parse_rows(table)

    def parse_table(self, html: str) -> List[Tuple[str, str, str]]:
        soup = BeautifulSoup(html, "html.parser")
        tbody = soup.find("tbody")
        if not isinstance(tbody, Tag):
            return []
        return self.parse_rows(tbody)

    @staticmethod
    def parse_rows(table: Tag) -> List[Tuple[str, str, str]]:
        results: List[Tuple[str, str, str]] = []
        for row in table.find_all("tr"):
            if not isinstance(row, Tag):
                continue
            cells = row.find_all("td")
            if len(cells) < 3 or any(not isinstance(cell, Tag) for cell in cells):
                continue
            id_ = cells[0].get_text(strip=True)
            name = cells[1].get_text(strip=True)
            link_tag = cells[2].find("a") if isinstance(cells[2], Tag) else None
            if not (isinstance(link_tag, Tag) and "href" in link_tag.attrs):
                continue
            link = str(link_tag["href"])
            results.append((id_, name, link))
        return results

    async def download_file(self, url: str, dest_dir: Path) -> bool:
        dest_dir.mkdir(parents=True, exist_ok=True)
        try:
            async with asyncio.timeout(300):
                if not self.client:
                    raise RuntimeError("Client not initialized")
                resp = await self.client.get(url)
                if resp.status_code in (302, 401) or "text/html" in resp.headers.get(
                    "Content-Type", ""
                ):
                    # Session expired or not allowed; retry login (up to 3)
                    if not self.logged_in:
                        await self.ensure_login()
                        return await self.download_file(url, dest_dir)
                    else:
                        print("Access error, stopping all downloads.")
                        raise Exception("Access error, batch stopped")
                total = int(resp.headers.get("Content-Length", 0))
                filename = (
                    self.extract_filename(resp)
                    or Path(url.split("?")[0]).name
                    or "downloaded_file"
                )
                destination = dest_dir / filename
                with open(destination, "wb") as f:
                    async for chunk in resp.aiter_bytes(8192):
                        if chunk:
                            f.write(chunk)
                print(
                    f"Saved: {destination} ({bytes2human(total)})"
                    if total
                    else f"Saved: {destination}"
                )
            # If it's a zip, could call self.unzip_file(destination, dest_dir)
            return True
        except Exception as e:
            print(f"Download error for {url}: {e}")
            return False

    @staticmethod
    def extract_filename(response: httpx.Response) -> Optional[str]:
        cd = response.headers.get("Content-Disposition")
        if not cd:
            return None
        match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";\n]*)', cd)
        return match.group(1) if match else None


if __name__ == "__main__":
    try:
        asyncio.run(AudioVaultDownloaderAsync().run())
    except KeyboardInterrupt:
        print("\nExited.")
        sys.exit(0)
