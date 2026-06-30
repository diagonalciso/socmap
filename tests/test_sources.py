"""
Feed-parser smoke tests. Every fetcher is driven with a saved sample blob
(network monkeypatched out) so parsing logic — IP validation, comment/CIDR
tolerance, CSV host/IP split, JSON shape handling, and the swallow-and-return-[]
error path — is pinned without hitting the live sources.
"""
import json

import pytest

import sources


# ── pure helpers ──────────────────────────────────────────────────────────────

def test_is_ip():
    assert sources._is_ip("8.8.8.8")
    assert sources._is_ip("2001:db8::1")
    assert not sources._is_ip("not-an-ip")
    assert not sources._is_ip("999.1.1.1")


def test_iter_text_ips_skips_comments_blanks_and_cidr():
    blob = "\n".join([
        "# header comment",
        "",
        "8.8.8.8",
        "1.2.3.0/24",          # CIDR -> network address kept
        "203.0.113.7 80",      # trailing port column
        "   ",
        "garbage line",
        "9.9.9.9",
    ])
    assert list(sources._iter_text_ips(blob)) == ["8.8.8.8", "1.2.3.0", "203.0.113.7", "9.9.9.9"]


# ── JSON feeds ────────────────────────────────────────────────────────────────

def test_fetch_feodo(monkeypatch):
    sample = json.dumps([
        {"ip_address": "45.9.148.99", "malware": "Dridex", "country": "RU"},
        {"ip_address": "bad-ip", "malware": "x"},          # dropped: invalid ip
        {"malware": "no-ip"},                              # dropped: no ip
    ])
    monkeypatch.setattr(sources, "_text", lambda *a, **k: sample)
    out = sources.fetch_feodo()
    assert len(out) == 1
    ev = out[0]
    assert ev["ip"] == "45.9.148.99"
    assert ev["source"] == "feodo" and ev["type"] == "intrusion"
    assert ev["label"] == "Dridex" and ev["country"] == "RU"


def test_fetch_dshield_handles_list_and_dict(monkeypatch):
    rows = [{"ipaddr": "1.2.3.4"}, {"source": "5.6.7.8"}, {"nope": 1}, "junk"]
    monkeypatch.setattr(sources, "_text", lambda *a, **k: json.dumps(rows))
    out = sources.fetch_dshield()
    assert sorted(e["ip"] for e in out) == ["1.2.3.4", "5.6.7.8"]
    assert all(e["source"] == "dshield" for e in out)


# ── CSV feed (urlhaus) ────────────────────────────────────────────────────────

def test_fetch_urlhaus_splits_host_and_ip(monkeypatch):
    blob = "\n".join([
        "# banner",
        "# id,dateadded,url,...",
        '1,2026-01-01,http://5.5.5.5/x.exe,online,,malware_download,,link,rep',
        '2,2026-01-01,https://evil.example/p,online,,exploit,,link,rep',
        '3,2026-01-01,not-a-url,online,,x,,link,rep',     # dropped: no scheme
    ])
    monkeypatch.setattr(sources, "_text", lambda *a, **k: blob)
    out = sources.fetch_urlhaus()
    assert len(out) == 2
    by_ip = next(e for e in out if e.get("ip"))
    by_host = next(e for e in out if e.get("host"))
    assert by_ip["ip"] == "5.5.5.5"
    assert by_host["host"] == "evil.example"
    assert all(e["source"] == "urlhaus" for e in out)


# ── plaintext blocklists ──────────────────────────────────────────────────────

@pytest.mark.parametrize("fn,source,typ", [
    ("fetch_blocklist", "blocklist.de", "bruteforce"),
    ("fetch_cins", "cins", "malware"),
    ("fetch_greensnow", "greensnow", "bruteforce"),
    ("fetch_blocklist_ssh", "blocklist.de-ssh", "bruteforce"),
])
def test_plaintext_blocklists(monkeypatch, fn, source, typ):
    monkeypatch.setattr(sources, "_text", lambda *a, **k: "# c\n8.8.8.8\n9.9.9.9\n")
    out = getattr(sources, fn)()
    assert [e["ip"] for e in out] == ["8.8.8.8", "9.9.9.9"]
    assert all(e["source"] == source and e["type"] == typ for e in out)


# ── error path: network failure -> empty list, never raises ───────────────────

@pytest.mark.parametrize("fn", [
    "fetch_feodo", "fetch_dshield", "fetch_urlhaus",
    "fetch_blocklist", "fetch_cins",
])
def test_fetch_swallows_errors(monkeypatch, fn):
    def boom(*a, **k):
        raise OSError("network down")
    monkeypatch.setattr(sources, "_text", boom)
    monkeypatch.setattr(sources, "_req", boom)
    assert getattr(sources, fn)() == []


def test_threatfox_without_key_returns_empty(monkeypatch):
    monkeypatch.delenv("THREATFOX_KEY", raising=False)
    assert sources.fetch_threatfox() == []
