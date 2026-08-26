from audiovault import ConfigManager


def test_config_manager_init(temp_dir):
    """Test ConfigManager initialization."""
    config_file = temp_dir / "test_config.ini"
    config = ConfigManager(str(config_file))
    assert config.filename == config_file
    assert config.config.has_section("settings")


def test_config_get_set(temp_dir):
    """Test getting and setting configuration values."""
    config_file = temp_dir / "test_config.ini"
    config = ConfigManager(str(config_file))

    # Test setting and getting values
    config.set("test_key", "test_value")
    assert config.get("test_key") == "test_value"

    # Test default values
    assert config.get("nonexistent", "default") == "default"


def test_download_dir_operations(temp_dir):
    """Test download directory operations."""
    config_file = temp_dir / "test_config.ini"
    config = ConfigManager(str(config_file))

    test_dir = temp_dir / "downloads"
    config.set_download_dir(test_dir)

    retrieved_dir = config.get_download_dir()
    assert retrieved_dir == test_dir.expanduser().resolve()


def test_email_operations(temp_dir):
    """Test email configuration operations."""
    config_file = temp_dir / "test_config.ini"
    config = ConfigManager(str(config_file))

    # Test setting email
    test_email = "test@example.com"
    config.set_email(test_email)
    assert config.get_email() == test_email


def test_get_dropbox_dir_returns_none_when_unset(temp_dir):
    """Return None when no Dropbox directory is configured."""
    config = ConfigManager(str(temp_dir / "test_config.ini"))

    assert config.get_dropbox_dir() is None


def test_dropbox_dir_roundtrip(temp_dir):
    """Store and retrieve a resolved Dropbox directory."""
    config = ConfigManager(str(temp_dir / "test_config.ini"))
    dropbox_dir = temp_dir / "Dropbox"

    config.set_dropbox_dir(dropbox_dir)

    assert config.get_dropbox_dir() == dropbox_dir.expanduser().resolve()


def test_set_dropbox_dir_none_unsets_value(temp_dir):
    """Treat a Dropbox directory cleared with None as unset."""
    config = ConfigManager(str(temp_dir / "test_config.ini"))
    config.set_dropbox_dir(temp_dir / "Dropbox")

    config.set_dropbox_dir(None)

    assert config.get_dropbox_dir() is None


def test_blank_dropbox_dir_is_unset(temp_dir):
    """Treat a blank configured Dropbox directory as unset."""
    config = ConfigManager(str(temp_dir / "test_config.ini"))

    config.set("dropbox_dir", "   ")

    assert config.get_dropbox_dir() is None
