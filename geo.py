"""Offline IP -> (lat, lon, country) resolver for the attack map.

Zero external deps, zero network. Resolution order:

  1. Caller-supplied country (from enrichment's OTX/AbuseIPDB country field) ->
     country centroid. Honest, coarse ("approximate origin"), no lookup cost.
  2. Optional MaxMind/DB-IP GeoLite2 City .mmdb at $GEOIP_MMDB -> city-precise
     (only if the file exists; parsed by a tiny stdlib reader, see _mmdb).
  3. Synthetic fallback: deterministic hash(ip) -> a land country centroid with
     a small jitter. Keeps the map alive for synthetic/RFC5737 test traffic and
     for real IPs we can't geolocate. ALWAYS flagged synthetic=True so the UI
     never presents it as real attribution.

Private / reserved / non-routable IPs return None (nothing to map).
"""
import hashlib
import ipaddress
import os
import struct

# ISO-3166 alpha-2 -> (lat, lon, display name). Capital / population centroid,
# enough for a Norse-style country-resolution map. Not exhaustive; misses fall
# through to the synthetic land scatter, which draws from this same table.
CENTROIDS = {
    "US": (38.0, -97.0, "United States"), "CA": (56.1, -106.3, "Canada"),
    "MX": (23.6, -102.5, "Mexico"), "BR": (-14.2, -51.9, "Brazil"),
    "AR": (-38.4, -63.6, "Argentina"), "CL": (-35.7, -71.5, "Chile"),
    "CO": (4.6, -74.3, "Colombia"), "PE": (-9.2, -75.0, "Peru"),
    "VE": (6.4, -66.6, "Venezuela"), "GB": (54.0, -2.0, "United Kingdom"),
    "IE": (53.4, -8.2, "Ireland"), "FR": (46.2, 2.2, "France"),
    "DE": (51.2, 10.4, "Germany"), "NL": (52.1, 5.3, "Netherlands"),
    "BE": (50.5, 4.5, "Belgium"), "LU": (49.8, 6.1, "Luxembourg"),
    "ES": (40.5, -3.7, "Spain"), "PT": (39.4, -8.2, "Portugal"),
    "IT": (41.9, 12.6, "Italy"), "CH": (46.8, 8.2, "Switzerland"),
    "AT": (47.5, 14.6, "Austria"), "DK": (56.3, 9.5, "Denmark"),
    "NO": (60.5, 8.5, "Norway"), "SE": (60.1, 18.6, "Sweden"),
    "FI": (61.9, 25.7, "Finland"), "IS": (64.9, -19.0, "Iceland"),
    "PL": (51.9, 19.1, "Poland"), "CZ": (49.8, 15.5, "Czechia"),
    "SK": (48.7, 19.7, "Slovakia"), "HU": (47.2, 19.5, "Hungary"),
    "RO": (45.9, 25.0, "Romania"), "BG": (42.7, 25.5, "Bulgaria"),
    "GR": (39.1, 21.8, "Greece"), "TR": (38.9, 35.2, "Turkey"),
    "UA": (48.4, 31.2, "Ukraine"), "RU": (61.5, 105.3, "Russia"),
    "BY": (53.7, 27.9, "Belarus"), "RS": (44.0, 21.0, "Serbia"),
    "HR": (45.1, 15.2, "Croatia"), "SI": (46.2, 15.0, "Slovenia"),
    "LT": (55.2, 23.9, "Lithuania"), "LV": (56.9, 24.6, "Latvia"),
    "EE": (58.6, 25.0, "Estonia"), "MD": (47.4, 28.4, "Moldova"),
    "IN": (20.6, 79.0, "India"), "PK": (30.4, 69.3, "Pakistan"),
    "BD": (23.7, 90.4, "Bangladesh"), "CN": (35.9, 104.2, "China"),
    "JP": (36.2, 138.3, "Japan"), "KR": (35.9, 127.8, "South Korea"),
    "KP": (40.3, 127.5, "North Korea"), "TW": (23.7, 121.0, "Taiwan"),
    "HK": (22.3, 114.2, "Hong Kong"), "VN": (14.1, 108.3, "Vietnam"),
    "TH": (15.9, 100.9, "Thailand"), "MY": (4.2, 101.9, "Malaysia"),
    "SG": (1.35, 103.8, "Singapore"), "ID": (-0.8, 113.9, "Indonesia"),
    "PH": (12.9, 121.8, "Philippines"), "AU": (-25.3, 133.8, "Australia"),
    "NZ": (-40.9, 174.9, "New Zealand"), "IR": (32.4, 53.7, "Iran"),
    "IQ": (33.2, 43.7, "Iraq"), "SA": (23.9, 45.1, "Saudi Arabia"),
    "AE": (23.4, 53.8, "UAE"), "IL": (31.0, 34.9, "Israel"),
    "JO": (30.6, 36.2, "Jordan"), "LB": (33.9, 35.9, "Lebanon"),
    "SY": (34.8, 39.0, "Syria"), "EG": (26.8, 30.8, "Egypt"),
    "KZ": (48.0, 66.9, "Kazakhstan"), "UZ": (41.4, 64.6, "Uzbekistan"),
    "AF": (33.9, 67.7, "Afghanistan"), "ZA": (-30.6, 22.9, "South Africa"),
    "NG": (9.1, 8.7, "Nigeria"), "KE": (-0.0, 37.9, "Kenya"),
    "GH": (7.9, -1.0, "Ghana"), "MA": (31.8, -7.1, "Morocco"),
    "DZ": (28.0, 1.7, "Algeria"), "TN": (33.9, 9.6, "Tunisia"),
    "ET": (9.1, 40.5, "Ethiopia"), "TZ": (-6.4, 34.9, "Tanzania"),
    "CM": (7.4, 12.4, "Cameroon"), "CI": (7.5, -5.5, "Cote d'Ivoire"),
}
_LAND = sorted(CENTROIDS)  # stable order for deterministic synthetic mapping


# RFC5737 documentation / TEST-NET ranges. Python marks these is_private, but
# socops' synthetic event feeds use them, so for the map we treat them as
# mappable (synthetic geo) unless MAP_INCLUDE_TESTNET=0. Real LAN (10/192.168/
# 172.16) and loopback/link-local stay excluded — those are our own agents.
_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _routable(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if os.environ.get("MAP_INCLUDE_TESTNET", "1") != "0":
        if any(a in n for n in _DOC_NETS):
            return True
    return not (a.is_private or a.is_loopback or a.is_reserved
                or a.is_link_local or a.is_multicast or a.is_unspecified)


def _jitter(ip, lat, lon, spread=4.0):
    """Deterministic +/- jitter so many IPs from one country don't stack on a
    single pixel. Seeded by the IP so a given IP always lands the same spot."""
    h = hashlib.md5(ip.encode()).digest()
    dx = (h[4] / 255.0 - 0.5) * 2 * spread
    dy = (h[5] / 255.0 - 0.5) * 2 * spread
    return (max(-85.0, min(85.0, lat + dy)), max(-179.0, min(179.0, lon + dx)))


def locate(ip, country=None):
    """Return {lat, lon, country, cc, synthetic} or None for non-routable IPs.

    `country` may be an ISO2 code or a full name pulled from enrichment; if it
    resolves to a known centroid the point is real (synthetic=False)."""
    if not ip or not _routable(ip):
        return None

    # 1. enrichment-supplied country -> centroid (real, coarse)
    if country:
        cc = _name_to_cc(country)
        if cc and cc in CENTROIDS:
            lat, lon, name = CENTROIDS[cc]
            lat, lon = _jitter(ip, lat, lon, spread=2.5)
            return {"lat": lat, "lon": lon, "country": name, "cc": cc,
                    "synthetic": False}

    # 2. optional GeoLite2 City mmdb (real, precise) if present
    mm = _mmdb_lookup(ip)
    if mm:
        return mm

    # 3. synthetic deterministic land scatter (flagged)
    seed = int.from_bytes(hashlib.md5(ip.encode()).digest()[:4], "big")
    cc = _LAND[seed % len(_LAND)]
    lat, lon, name = CENTROIDS[cc]
    lat, lon = _jitter(ip, lat, lon, spread=6.0)
    return {"lat": lat, "lon": lon, "country": name, "cc": cc, "synthetic": True}


# --- country name/code normalisation -------------------------------------
_NAME_TO_CC = {name.lower(): cc for cc, (_, _, name) in CENTROIDS.items()}
_ALIASES = {
    "united states of america": "US", "usa": "US", "u.s.": "US",
    "russian federation": "RU", "south korea": "KR", "korea, republic of": "KR",
    "korea": "KR", "north korea": "KP", "viet nam": "VN", "uae": "AE",
    "united arab emirates": "AE", "united kingdom": "GB", "uk": "GB",
    "czech republic": "CZ", "the netherlands": "NL", "iran, islamic republic of": "IR",
}


def _name_to_cc(val):
    v = val.strip()
    if len(v) == 2 and v.upper() in CENTROIDS:
        return v.upper()
    lv = v.lower()
    return _NAME_TO_CC.get(lv) or _ALIASES.get(lv)


# --- minimal MaxMind GeoLite2/DB-IP .mmdb city reader --------------------
# Only used if $GEOIP_MMDB points to a file. Pure stdlib. Returns precise
# city coords. Kept small: enough to read the lat/lon + country of one IP.
_MMDB = {"path": None, "buf": None, "meta": None}


def _mmdb_lookup(ip):
    path = os.environ.get("GEOIP_MMDB", "")
    if not path or not os.path.exists(path):
        return None
    try:
        if _MMDB["path"] != path:
            with open(path, "rb") as f:
                _MMDB["buf"] = f.read()
            _MMDB["path"] = path
            _MMDB["meta"] = _mmdb_meta(_MMDB["buf"])
        rec = _mmdb_get(_MMDB["buf"], _MMDB["meta"], ip)
        if not rec:
            return None
        loc = rec.get("location", {})
        lat, lon = loc.get("latitude"), loc.get("longitude")
        if lat is None or lon is None:
            return None
        cc = (rec.get("country", {}).get("iso_code")
              or rec.get("registered_country", {}).get("iso_code") or "")
        name = (rec.get("country", {}).get("names", {}).get("en")
                or CENTROIDS.get(cc, (0, 0, cc))[2])
        return {"lat": float(lat), "lon": float(lon), "country": name,
                "cc": cc, "synthetic": False}
    except Exception:
        return None  # any parse trouble -> fall through to synthetic


_MD = b"\xab\xcd\xefMaxMind.com"


def _mmdb_meta(buf):
    i = buf.rfind(_MD)
    meta, _ = _mmdb_decode(buf, i + len(_MD), 0)
    rs = meta["record_size"]
    return {"node_count": meta["node_count"], "record_size": rs,
            "node_bytes": rs * 2 // 8,
            "tree_size": meta["node_count"] * (rs * 2 // 8),
            "ip_version": meta["ip_version"]}


def _mmdb_get(buf, meta, ip):
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address) and meta["ip_version"] == 6:
        bits = [0] * 96 + _bits(int(addr), 32)
    else:
        nbits = 128 if addr.version == 6 else 32
        bits = _bits(int(addr), nbits)
    node = 0
    nc = meta["node_count"]
    for b in bits:
        if node >= nc:
            break
        node = _mmdb_read_node(buf, meta, node, b)
    if node == nc:
        return None
    if node > nc:
        off = (node - nc) + meta["tree_size"]
        val, _ = _mmdb_decode(buf, off, meta["tree_size"] + 16)
        return val
    return None


def _bits(n, width):
    return [(n >> (width - 1 - i)) & 1 for i in range(width)]


def _mmdb_read_node(buf, meta, node, side):
    rs = meta["record_size"]
    nb = meta["node_bytes"]
    base = node * nb
    if rs == 24:
        rec = buf[base:base + 3] if side == 0 else buf[base + 3:base + 6]
        return int.from_bytes(rec, "big")
    if rs == 28:
        if side == 0:
            return ((buf[base + 3] & 0xF0) << 20) | int.from_bytes(buf[base:base + 3], "big")
        return ((buf[base + 3] & 0x0F) << 24) | int.from_bytes(buf[base + 4:base + 7], "big")
    if rs == 32:
        rec = buf[base:base + 4] if side == 0 else buf[base + 4:base + 8]
        return int.from_bytes(rec, "big")
    raise ValueError("record_size")


def _mmdb_decode(buf, off, base):
    ctrl = buf[off]; off += 1
    t = ctrl >> 5
    if t == 0:  # pointer to extended type
        t = 7 + buf[off]; off += 1
    size = ctrl & 0x1F
    if t == 1:  # pointer
        ss = (ctrl >> 3) & 0x3
        if ss == 0:
            p = ((ctrl & 0x7) << 8) | buf[off]; off += 1
        elif ss == 1:
            p = ((ctrl & 0x7) << 16) | (buf[off] << 8) | buf[off + 1] + 2048; off += 2
        elif ss == 2:
            p = ((ctrl & 0x7) << 24) | int.from_bytes(buf[off:off + 3], "big") + 526336; off += 3
        else:
            p = int.from_bytes(buf[off:off + 4], "big"); off += 4
        val, _ = _mmdb_decode(buf, base + p, base)
        return val, off
    if size >= 29:
        if size == 29:
            size = 29 + buf[off]; off += 1
        elif size == 30:
            size = 285 + int.from_bytes(buf[off:off + 2], "big"); off += 2
        else:
            size = 65821 + int.from_bytes(buf[off:off + 3], "big"); off += 3
    if t == 2:  # utf8
        return buf[off:off + size].decode("utf-8", "replace"), off + size
    if t == 5:  # uint16
        return int.from_bytes(buf[off:off + size], "big"), off + size
    if t == 6:  # uint32
        return int.from_bytes(buf[off:off + size], "big"), off + size
    if t == 8:  # int32
        return int.from_bytes(buf[off:off + size], "big", signed=True), off + size
    if t == 9 or t == 10:  # uint64/128
        return int.from_bytes(buf[off:off + size], "big"), off + size
    if t == 3:  # double
        return struct.unpack(">d", buf[off:off + 8])[0], off + 8
    if t == 4:  # bytes
        return buf[off:off + size], off + size
    if t == 15:  # float
        return struct.unpack(">f", buf[off:off + 4])[0], off + 4
    if t == 14:  # bool
        return bool(size), off
    if t == 7:  # map
        d = {}
        for _ in range(size):
            k, off = _mmdb_decode(buf, off, base)
            v, off = _mmdb_decode(buf, off, base)
            d[k] = v
        return d, off
    if t == 11:  # array
        a = []
        for _ in range(size):
            v, off = _mmdb_decode(buf, off, base)
            a.append(v)
        return a, off
    if t in (12, 13):  # data cache container / end marker
        return None, off
    raise ValueError(f"mmdb type {t}")


if __name__ == "__main__":
    import sys
    for ip in sys.argv[1:] or ["8.8.8.8", "1.2.3.4", "192.168.0.1", "203.0.113.7"]:
        print(ip, "->", locate(ip))
