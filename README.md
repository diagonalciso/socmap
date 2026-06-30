# Attack Map — live threat-feed cyber attack map

A standalone, Norse-style real-time attack map. Polls **free public threat
feeds**, geolocates every malicious IP, and animates the hits as glowing arcs
flying into a sensor "home" on an HTML5 canvas world map — with a synthesized
ambient soundtrack and per-attack audio. Pure Python **stdlib**, no framework,
no database, no API keys required.

> **Honesty:** arcs are **known-bad infrastructure** (botnet C2, malware hosts,
> reported attackers, honeypot-seen scanners) geolocated to an *approximate
> origin*. This is **not** live victim attribution — no such free real-time
> global stream exists. IPs that can't be geolocated are drawn faded and
> flagged synthetic.

---

## Quick start

### Option A — prebuilt binary (no Python needed)

Download from the [latest release](../../releases/latest):

| Platform | File |
|----------|------|
| Windows  | `attackmap-windows-x64.exe` |
| Linux    | `attackmap-linux-x64` |

**Windows:** double-click `attackmap-windows-x64.exe` (SmartScreen may warn on an
unsigned binary → *More info → Run anyway*). A console window opens; browse to
**http://localhost:8100**.

**Linux:**
```bash
chmod +x attackmap-linux-x64
./attackmap-linux-x64
# -> open http://localhost:8100
```

### Option B — from source (Python 3.8+)

```bash
git clone https://github.com/diagonalciso/attackmap
cd attackmap
cp .env.example .env          # optional — tweak home location, etc.
./run.sh                      # Windows: run.bat
# -> http://localhost:8100
```

The server binds `0.0.0.0:8100` by default, so it's reachable from other devices
on your LAN at `http://<this-machine-ip>:8100`.

---

## Sound

Click the **🔇 button (top-right)** to enable audio (browsers block autoplay
until you interact). You get:

- an **ambient drone** (detuned low oscillators through a slowly sweeping filter), and
- a **per-attack "zap"** — pitch by attack type, **stereo-panned by the source's
  longitude** (Asia → right, Americas → left), volume by feed weight.

All sound is synthesized in the browser with the Web Audio API — no audio files.
Click again to mute.

---

## Configuration (`.env`)

Copy `.env.example` to `.env` (next to the binary or `app.py`). It is auto-loaded
— no need to export shell variables.

| Key | Default | Meaning |
|-----|---------|---------|
| `HOST` | `0.0.0.0` | Bind address (`127.0.0.1` = localhost only) |
| `PORT` | `8100` | HTTP port |
| `HOME_LAT` / `HOME_LON` | `52.37` / `4.90` | Sensor "home" anchor (default Amsterdam) |
| `EMIT_RATE` | `6` | Arcs/second drained from feed bursts (smoothing) |
| `REPLAY_RATE` | `1.6` | Arcs/second replayed from the pool so the map never goes idle (`0` = off) |
| `POOL_MAX` | `6000` | Geolocated events kept for replay |
| `FIRST_BURST` | `40` | Arcs emitted on a feed's first poll |
| `GEOIP_MMDB` | — | Path to a MaxMind **GeoLite2-City.mmdb** for city-precise geo (optional) |
| `THREATFOX_KEY` | — | abuse.ch [Auth-Key](https://auth.abuse.ch/) to enable the ThreatFox feed |
| `CONTACT_EMAIL` | `admin@example.com` | Sent in the User-Agent (DShield requires a real contact) |
| `FEED_TIMEOUT` | `25` | Per-request timeout (seconds) |

**GeoIP accuracy:** without an mmdb, Feodo IPs fall back to country centroids and
the rest to a deterministic synthetic land scatter (faded). Drop a free
GeoLite2-City `.mmdb` next to the app and point `GEOIP_MMDB` at it for precise
placement.

---

## Feeds (all free)

| Source | Data | Auth |
|--------|------|------|
| abuse.ch **Feodo Tracker** | active botnet C2 IPs (+ country) | none |
| abuse.ch **URLhaus** | live malware-hosting URLs (IP hosts) | none |
| abuse.ch **ThreatFox** | recent malware IOC IPs | free key |
| SANS **DShield/ISC** | top attacking source IPs (honeypot-derived) | email in UA |
| **blocklist.de** (+ ssh) | reported attackers / SSH brute-forcers | none |
| **CINS Army** | community bad-actor IPs | none |
| **GreenSnow** | attacker IPs | none |
| **Emerging Threats** | compromised hosts | none |
| **DataPlane.org** | SSH / telnet / VNC / SIP scanners — **real sensor/honeypot data** | none |

A dead or rate-limited feed never takes the map down (every fetch is wrapped).

---

## Controls & endpoints

- **Zoom:** mouse wheel / `+` `−` buttons / pinch. **Pan:** drag. **Reset:** `□`.
- `GET /` — the map UI
- `GET /healthz` — `{ok, total}`
- `GET /api/attackmap/stream` — Server-Sent Events live feed
- `GET /api/attackmap/recent?limit=N` — recent events + home
- `GET /api/attackmap/stats` — totals by source/type/country
- `GET /api/attackmap/world` — bundled coastline GeoJSON

---

## Run as a service (Linux)

```bash
sudo cp attackmap.service /etc/systemd/system/
sudo systemctl enable --now attackmap
```
Edit the unit's `WorkingDirectory`/`ExecStart` to match where you put the app.

---

## Build your own packages

Self-contained executables are produced with **PyInstaller** from `attackmap.spec`:

```bash
pip install pyinstaller
pyinstaller attackmap.spec
# -> dist/attackmap         (Linux ELF)
# -> dist/attackmap.exe     (when run on Windows)
```

A real **Windows .exe** can only be built on Windows. The bundled GitHub Actions
workflow (`.github/workflows/release.yml`) builds **both** Linux and Windows
binaries on their native runners and attaches them to a release:

```bash
git tag v0.1 && git push origin v0.1     # -> CI builds + publishes both binaries
```

---

## See also

Companion **standalone Android app** (on-device feeds + WebView map + the same
audio): [`attackmap-android`](https://github.com/diagonalciso/attackmap-android).
