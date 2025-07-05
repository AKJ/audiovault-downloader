# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AudioVault Downloader is a Python application for downloading audio described movies and TV shows from audiovault.net. It's designed as a command-line tool with an interactive menu system for browsing and downloading content with real-time progress tracking.

## Architecture

- **Single-file application**: All functionality is contained in `audiovault.py`
- **Async architecture**: Uses httpx and asyncio for concurrent downloads with rate limiting
- **Configuration management**: INI-based config with system keyring for password storage
- **Authentication**: Login session management with automatic retry logic
- **Download management**: Concurrent downloads with semaphore-based limiting and progress tracking
- **Progress tracking**: Real-time progress bars using tqdm.asyncio for individual and batch downloads

## Key Components

- `AudioVaultDownloaderAsync`: Main application class handling UI, authentication, and download orchestration
- `ConfigManager`: INI configuration file management for settings like download directory and email
- `AsyncLimiter`: Rate limiting for API requests to avoid overwhelming the server
- `AudioVaultAuth`: Authentication flow with login token extraction and session management
- `ContentParser`: HTML parsing for search results and content extraction
- `TVShowExtractor`: TV show-specific operations including ZIP extraction and directory organization

## Development Commands

### Package Management
Uses `uv` for modern Python package management:
- `uv sync` - Install/update dependencies from uv.lock
- `uv add <package>` - Add new dependency to main dependencies
- `uv add --group dev <package>` - Add development dependency
- `uv add --group test <package>` - Add test dependency
- `uv remove <package>` - Remove dependency

### Testing
Comprehensive test suite with pytest:
- `uv run --group test pytest` - Run all tests
- `uv run --group test pytest tests/test_config.py` - Run specific test file
- `uv run --group test pytest --cov=audiovault` - Run tests with coverage
- `uv run --group test pytest -v` - Run tests with verbose output
- `uv run --group test pytest -k "test_download"` - Run tests matching pattern

### Code Quality
- `uv run ruff check .` - Run linting
- `uv run ruff check --fix .` - Run linting with auto-fixes
- `uv run ruff format .` - Format code
- `uv run mypy audiovault.py --ignore-missing-imports` - Type checking

### Building Executable
- `uv run pyinstaller --clean -F audiovault.py` - Build standalone executable
- Alternative: Use `build.bat` on Windows which runs the same PyInstaller command

### Running the Application
- `uv run audiovault.py` - Run the application directly
- `python audiovault.py` - Standard Python execution (if environment is set up)

## Dependencies

### Main Dependencies
- `httpx>=0.28.1` - Modern HTTP client with async support
- `beautifulsoup4>=4.13.4` - HTML parsing for content extraction
- `keyring>=25.6.0` - Secure password storage
- `tqdm>=4.67.1` - Progress bars and download tracking
- `keyrings-alt>=5.0.2` - Alternative keyring backends

### Development Dependencies
- `mypy>=1.16.1` - Static type checking
- `pyinstaller>=6.14.1` - Executable building
- `ruff>=0.12.1` - Fast Python linter and formatter

### Test Dependencies
- `pytest>=8.0.0` - Testing framework
- `pytest-asyncio>=0.24.0` - Async test support
- `pytest-mock>=3.12.0` - Mocking utilities
- `respx>=0.21.0` - HTTP request mocking
- `pytest-cov>=6.0.0` - Coverage reporting

## Configuration

- `config.ini`: User settings (download directory, email) in INI format
- System keyring: Secure password storage
- Default download structure: `downloads/movies/` and `downloads/tv/`

## Progress Tracking Features

- **Individual file progress**: Real-time progress bars for each download showing size, speed, and ETA
- **Batch progress**: Overall progress when downloading multiple files concurrently
- **Download statistics**: Detailed summary with file sizes, download speeds, and total time
- **Speed calculation**: Accurate speed tracking and average speed calculation across all downloads

## Important Implementation Details

- Downloads are rate-limited (1 second between requests) and concurrent (max 5 simultaneous)
- Authentication tokens are extracted from login forms via BeautifulSoup parsing
- Session management handles expired logins with automatic retry
- File downloads support resume and proper filename extraction from Content-Disposition headers
- Error handling includes retry logic for failed downloads and network issues
- TV shows are automatically extracted from ZIP files into organized season directories
- Progress bars are disabled during testing to avoid output interference

## Testing

The project includes a comprehensive test suite covering:
- **Unit tests**: Individual component testing (ConfigManager, ContentParser, TVShowExtractor, etc.)
- **Integration tests**: End-to-end download workflows
- **Async testing**: Proper async function testing with pytest-asyncio
- **Mocking**: HTTP requests, file system operations, and keyring interactions
- **Progress tracking**: Progress bar functionality and statistics calculation
- **Error handling**: Network failures, authentication errors, and edge cases

Test files are organized in the `tests/` directory with fixtures and sample data.

## Code Style

- **Docstrings**: Use Google-style docstrings for all functions, classes, and methods
- **Type hints**: Use type hints for function parameters and return values
- **Formatting**: Code is automatically formatted with ruff
- **Comments**: Avoid unnecessary comments; code should be self-documenting
- Always use descriptive variable names, and prefer full words

## Security Considerations

- Passwords are stored in system keyring, not in config files
- Login sessions are properly managed with CSRF token handling
- Network requests include proper timeout handling (300 seconds for downloads)
- No sensitive information is logged or exposed in error messages