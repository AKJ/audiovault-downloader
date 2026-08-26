from audiovault import bytes2human, sanitize_name


def test_sanitize_name():
    """Test replacement of filesystem-invalid characters, including backslash."""
    assert sanitize_name("Show: The/Return\\Home?") == "Show_ The_Return_Home_"
    assert sanitize_name('a<b>c"d|e*f') == "a_b_c_d_e_f"
    assert sanitize_name("Plain Name - Season 1") == "Plain Name - Season 1"


def test_bytes2human():
    """Test human-readable byte formatting."""
    assert bytes2human(0) == "0B"
    assert bytes2human(512) == "512B"
    assert bytes2human(1024) == "1.0KB"
    assert bytes2human(1536) == "1.5KB"
    assert bytes2human(1048576) == "1.0MB"
    assert bytes2human(1073741824) == "1.0GB"
