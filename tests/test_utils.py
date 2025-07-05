import pytest
from audiovault import bytes2human

def test_bytes2human():
    """Test human-readable byte formatting."""
    assert bytes2human(0) == "0B"
    assert bytes2human(512) == "512B"
    assert bytes2human(1024) == "1.0KB"
    assert bytes2human(1536) == "1.5KB" 
    assert bytes2human(1048576) == "1.0MB"
    assert bytes2human(1073741824) == "1.0GB"