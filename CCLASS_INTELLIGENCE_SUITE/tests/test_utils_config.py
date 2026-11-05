import pytest

from cclass_suite.config import Settings, SettingsError
from cclass_suite.utils import (clean_text, detect_type, normalise_value, parse_coordinates, valid_domain,
                                valid_email, valid_ip, valid_username)


@pytest.mark.parametrize("value,expected", [
    ("a@b.example", "email"), ("203.0.113.9", "ip"), ("2001:db8::1", "ip"), ("example.com", "domain"),
    ("https://github.com/octocat", "url"), ("CVE-2021-44228", "cve"), ("6.52,3.37", "coordinates"),
    ("192.168.0.0/24", "network"), ("d41d8cd98f00b204e9800998ecf8427e", "hash"), ("aa:bb:cc:dd:ee:ff", "mac"),
    ("@octo_cat", "username"), ("octo_cat", "username"), ("Lagos", "text"), ("two words here", "text"), ("", "text"),
])
def test_detect_type(value, expected):
    assert detect_type(value) == expected


def test_validators():
    assert valid_email("first.last+tag@sub.example.org")
    assert not valid_email("no-at-sign.example") and not valid_email("a@b") and not valid_email("a b@c.example")
    assert valid_domain("xn--bcher-kva.example") and not valid_domain("-bad-.example") and not valid_domain("nodot")
    assert valid_ip("::1") and not valid_ip("999.1.1.1")
    assert valid_username("demo_user") and not valid_username("a") and not valid_username("bad name")
    assert parse_coordinates("91,0") is None and parse_coordinates("10, 20") == (10.0, 20.0)


def test_normalisation_and_cleaning():
    assert normalise_value("email", " A@B.Example ") == "a@b.example"
    assert normalise_value("ip", "2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalise_value("asn", "64500") == "AS64500"
    assert normalise_value("mac", "AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert clean_text("ok\x00\x1b[31mtext", 100) == "ok[31mtext"
    assert len(clean_text("x" * 5000, 100)) == 100


def test_settings_validation_and_persistence(tmp_path):
    s = Settings.load(tmp_path)
    s.update({"http_timeout": 5, "scan_ports": [443, 22, 22]})
    assert s.scan_ports == [22, 443] and s.http_timeout == 5.0
    for bad in ({"port": 0}, {"offline_mode": "yes"}, {"scan_ports": []}, {"host": "bad host!"},
                {"feeds": {"x": {"type": "rss", "url": "http://insecure"}}}, {"nope": 1}, {"user_agent": "a\nb"}):
        with pytest.raises(SettingsError):
            s.update(bad)
    s.save()
    assert Settings.load(tmp_path).http_timeout == 5.0


def test_secrets_never_persisted(tmp_path, monkeypatch):
    monkeypatch.setenv("CCLASS_NVD_API_KEY", "super-secret")
    s = Settings.load(tmp_path)
    assert s.nvd_api_key == "super-secret"
    s.save()
    assert "super-secret" not in s.settings_file.read_text()
    assert "super-secret" not in str(s.to_public_dict()) and s.to_public_dict()["nvd_api_key_configured"] is True


def test_corrupt_settings_file_falls_back(tmp_path):
    (tmp_path).mkdir(exist_ok=True)
    (tmp_path / "settings.json").write_text("{not json")
    assert Settings.load(tmp_path).port == 8000


def test_deployment_env_switches(tmp_path, monkeypatch):
    from cclass_suite.config import Settings

    s = Settings.load(tmp_path / "d")
    assert s.auth_enabled and not s.cookie_secure and not s.trust_proxy and s.allowed_hosts == []
    monkeypatch.setenv("CCLASS_AUTH", "off")
    monkeypatch.setenv("CCLASS_COOKIE_SECURE", "1")
    monkeypatch.setenv("CCLASS_TRUST_PROXY", "true")
    monkeypatch.setenv("CCLASS_ALLOWED_HOSTS", " Cclass.Example.org , intranet ")
    s = Settings.load(tmp_path / "d")
    assert not s.auth_enabled and s.cookie_secure and s.trust_proxy
    assert s.allowed_hosts == ["cclass.example.org", "intranet"]


def test_security_switches_cannot_be_changed_through_the_settings_api(tmp_path):
    import pytest as _pt
    from cclass_suite.config import Settings, SettingsError

    s = Settings.load(tmp_path / "d")
    for key in ("auth_enabled", "cookie_secure", "trust_proxy", "allowed_hosts"):
        with _pt.raises(SettingsError):
            s.update({key: True})
    s.update({"backup_keep": 5, "retention_alert_days": 90})
    assert s.backup_keep == 5
    with _pt.raises(SettingsError):
        s.update({"backup_keep": 0})
    s.save()
    assert "auth_enabled" not in s.settings_file.read_text()
