"""
Geo-resolution smoke tests: the non-routable guard, the deterministic synthetic
land scatter, enrichment-country centroids, and (when a .mmdb is available) the
real MaxMind reader whose pointer-decode path carried the bug fixed in d4d332d.
"""
import os

import pytest

import geo

REQUIRED_KEYS = {"lat", "lon", "country", "cc", "synthetic"}


# ── routable guard ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "192.168.0.1", "10.0.0.5", "127.0.0.1", "0.0.0.0",
    "169.254.1.1", "::1", "", "not-an-ip",
])
def test_non_routable_returns_none(ip):
    assert geo.locate(ip) is None


def test_public_ip_resolves(monkeypatch):
    monkeypatch.delenv("GEOIP_MMDB", raising=False)
    r = geo.locate("45.155.205.233")
    assert set(r) == REQUIRED_KEYS
    assert -90 <= r["lat"] <= 90 and -180 <= r["lon"] <= 180


def test_documentation_net_is_mappable_by_default(monkeypatch):
    # socops synthetic feeds use RFC5737 TEST-NET; map keeps them unless opted out
    monkeypatch.delenv("MAP_INCLUDE_TESTNET", raising=False)
    assert geo.locate("203.0.113.5") is not None


def test_testnet_excluded_when_disabled(monkeypatch):
    monkeypatch.setenv("MAP_INCLUDE_TESTNET", "0")
    assert geo.locate("203.0.113.5") is None


# ── synthetic scatter is deterministic + flagged ──────────────────────────────

def test_synthetic_is_deterministic(monkeypatch):
    monkeypatch.delenv("GEOIP_MMDB", raising=False)
    a = geo.locate("91.92.93.94")
    b = geo.locate("91.92.93.94")
    assert a == b
    assert a["synthetic"] is True


def test_different_ips_differ(monkeypatch):
    monkeypatch.delenv("GEOIP_MMDB", raising=False)
    a = geo.locate("11.22.33.44")
    b = geo.locate("55.66.77.88")
    assert (a["lat"], a["lon"]) != (b["lat"], b["lon"])


def test_jitter_stays_in_bounds():
    lat, lon = geo._jitter("1.2.3.4", 80.0, 178.0, spread=6.0)
    assert -85.0 <= lat <= 85.0
    assert -179.0 <= lon <= 179.0


# ── enrichment country -> real centroid ───────────────────────────────────────

def test_country_name_gives_real_point(monkeypatch):
    monkeypatch.delenv("GEOIP_MMDB", raising=False)
    r = geo.locate("45.155.205.233", country="United States")
    assert r["cc"] == "US"
    assert r["synthetic"] is False


def test_country_iso_code_resolves(monkeypatch):
    monkeypatch.delenv("GEOIP_MMDB", raising=False)
    r = geo.locate("45.155.205.233", country="DE")
    assert r["cc"] == "DE"
    assert r["synthetic"] is False


# ── real mmdb reader (guards the pointer-decode bug) ───────────────────────────

_MMDB_CANDIDATES = [
    os.environ.get("GEOIP_MMDB", ""),
    "/home/openclaw/socops/GeoLite2-City.mmdb",
]
_MMDB = next((p for p in _MMDB_CANDIDATES if p and os.path.exists(p)), None)


@pytest.mark.skipif(_MMDB is None, reason="no GeoLite2 .mmdb available")
def test_mmdb_decodes_real_location(monkeypatch):
    monkeypatch.setenv("GEOIP_MMDB", _MMDB)
    geo._MMDB["path"] = None  # bust the module cache so it re-reads our path
    r = geo.locate("8.8.8.8")
    assert r is not None
    assert r["synthetic"] is False, "real mmdb hit should not be synthetic"
    # 8.8.8.8 is US; pointer-decode corruption produced garbage coords/cc
    assert r["cc"] == "US"
    assert -90 <= r["lat"] <= 90 and -180 <= r["lon"] <= 180
