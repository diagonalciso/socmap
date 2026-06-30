# SOCmap — Android (standalone)

A self-contained Norse-style live attack map for Android tablets/phones. Polls
**free public threat feeds directly on the device**, geolocates each malicious IP,
and animates the hits as glowing arcs on a canvas world map. No backend, no login,
no API keys.

The Android half of the [socmap](../) monorepo — companion to the desktop server
at the repo root. Same feeds, same look, but the whole pipeline runs on-device.

## What it shows

Arcs = **known-bad infrastructure** (botnet C2, malware hosts, reported attackers)
geolocated to an approximate origin, terminating at a sensor "home" (Amsterdam by
default). Not live victim attribution. IPs that can't be geolocated fall back to a
deterministic synthetic scatter, drawn faded.

## Architecture

```
FeedEngine (Kotlin, background threads)
  ├─ one poller per feed  → diff new IPs (FIRST_BURST cap, then trickle)
  ├─ ipwho.is geolocation (HTTPS, free, no key) → lat/lon/country, cached
  └─ rate-smoothed emitter (EMIT_PER_SEC) ─┐
                                           ▼
MainActivity → WebView (assets/map.html) ── window.pushEvent(ev)
                 HTML5 canvas: arcs, impact pings, panels, ticker
```

- `app/src/main/java/.../FeedEngine.kt` — feeds, parsing, geolocation, emitter.
- `app/src/main/java/.../MainActivity.kt` — fullscreen WebView + JS bridge.
- `app/src/main/assets/map.html` — the canvas renderer (shared design with the server).
- `app/src/main/assets/world.geojson` — coastlines.

## Feeds (all free, HTTPS, no key)

feodo (abuse.ch botnet C2) · urlhaus (abuse.ch malware URLs, IP-host rows) ·
dshield (SANS top attackers) · blocklist.de · CINS Army. Geolocation: **ipwho.is**.

> Note: `ip-api.com` was the obvious geo choice but is HTTP-only on the free tier;
> ipwho.is is HTTPS so the app stays cleartext-denied (`network_security_config`).

## Build

```bash
cd android          # from the repo root
ANDROID_HOME=$HOME/android-sdk JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
  ./gradlew :app:assembleDebug
# -> app/build/outputs/apk/debug/app-debug.apk   (~3.4 MB, universal)
```

## Install on the tablet

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
# or copy SOCmap-debug.apk to the tablet and tap it (allow unknown sources)
```

The debug APK is self-signed and installs directly — fine for personal use. For a
distributable build, add a keystore (`RELEASE_STORE_FILE` etc.) and
`./gradlew assembleRelease`.

## Config (compile-time, `FeedEngine.kt`)

- `FIRST_BURST` — arcs on a feed's first poll.
- `EMIT_PER_SEC` — arc stream rate (burst smoothing).
- Home anchor: `MainActivity.onMapReady()` → `setHome(lat, lon)`.

## Tested

Built with AGP 8.6.1 / Kotlin 2.4.0, minSdk 24, targetSdk 35. Verified on the
`yf_tablet10` emulator (API 29, 2560×1600): live feeds fetched on-device,
geolocated (China/Korea/US/Thailand/NL/Russia), arcs animate to home.
