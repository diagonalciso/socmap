# attackmap — standalone live threat-feed attack map

A self-contained, Norse-Corp-style real-time attack map. Polls **free public
threat feeds**, geolocates each malicious IP, and animates the hits as glowing
arcs on an HTML5-canvas world map. Pure Python stdlib + one bundled geo helper.
No framework, no database, no build step. Serves on **http://localhost:8100**.

## What it shows (and what it doesn't)

Arcs represent **known-bad infrastructure** (botnet C2, malware hosts, reported
attackers) geolocated to an **approximate origin**, terminating at a configurable
sensor "home". This is *not* live victim attribution — no free source streams the
real global attack graph (Norse Corp, which did, died in 2016). IPs that can't be
geolocated are drawn faded and flagged synthetic.

## Data sources (all free)

| Feed | What | Auth | Poll |
|------|------|------|------|
| abuse.ch **Feodo Tracker** | active botnet C2 IPs (+malware, +country) | none | 30m |
| abuse.ch **ThreatFox** | recent malware IOC IPs | free Auth-Key | 5m |
| abuse.ch **URLhaus** | live malware-hosting URLs (host→IP) | none | 5m |
| SANS **DShield** | top attacking source IPs | none (UA email) | 60m |
| **blocklist.de** | reported ssh/mail/web brute-forcers | none | 30m |
| **CINS Army** | community bad-actor IPs | none | 60m |

Feeds return big batches; new IPs are diffed each poll and **rate-smoothed**
(`EMIT_RATE`/s) into a flowing stream so the map animates continuously instead of
dumping thousands of arcs at once. First poll of each feed shows `FIRST_BURST`
arcs, the rest silently seed the dedup set.

## Setup

```bash
cd ~/attackmap
cp .env.example .env          # then edit:
#  - GEOIP_MMDB  -> path to a free MaxMind GeoLite2-City.mmdb (real geolocation)
#  - THREATFOX_KEY -> free key from https://auth.abuse.ch/ (optional)
#  - CONTACT_EMAIL -> your email (DShield ToS requires it in the User-Agent)
env $(grep -v '^#' .env | xargs) python3 app.py
```

Open **http://localhost:8100**.

### GeoIP

Drop a `GeoLite2-City.mmdb` at the `GEOIP_MMDB` path for city-precise origins
(parsed by a tiny stdlib reader in `geo.py` — no `geoip2` dependency). Without
it: feeds that carry a country (Feodo) plot to the country centroid, everything
else falls to a deterministic synthetic land scatter (flagged, faded).

## systemd

```bash
sudo cp attackmap.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now attackmap
journalctl -u attackmap -f
```

## Endpoints

| Path | Purpose |
|------|---------|
| `/` | the map |
| `/api/attackmap/stream` | SSE event stream (one JSON event per arc) |
| `/api/attackmap/recent?limit=N` | recent events + home anchor (initial paint) |
| `/api/attackmap/stats` | running totals by source/type/country |
| `/api/attackmap/world` | bundled `world.geojson` |
| `/healthz` | liveness + total event count |

## Files

```
app.py        server + SSE + emitter + pollers + embedded canvas front-end
sources.py    one fetch fn per feed -> normalized raw events (registry: SOURCES)
geo.py        IP -> {lat,lon,country} (mmdb reader + centroid + synthetic fallback)
world.geojson coastlines for the base map
```

## Tuning (`.env`)

- `EMIT_RATE` — arcs/sec; raise for a busier map, lower to calm it.
- `FIRST_BURST` — arcs on a feed's first poll.
- `HOME_LAT/LON` — where arcs terminate.
- `DNS_CAP` — URLhaus hostname lookups per cycle (DNS is the only slow bit).
