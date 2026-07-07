#!/usr/bin/env python3
"""Standalone Norse-style real-time attack map.

Feeds-only: polls free public threat feeds (abuse.ch Feodo/ThreatFox/URLhaus,
SANS DShield, blocklist.de, CINS), geolocates each malicious IP with a bundled
MaxMind GeoLite2-City mmdb (falls back to country-centroid / synthetic scatter),
rate-smooths the bursts into a flowing stream of animated arcs, and serves an
SSE-driven HTML5 canvas map. No framework, stdlib only (+ bundled geo.py).

Honesty: arcs are KNOWN-BAD INFRASTRUCTURE geolocated to an approximate origin,
terminating at a configurable sensor "home" — NOT live victim attribution. IPs
we cannot geolocate are drawn faded and flagged synthetic.

Run:  cp .env.example .env && env $(grep -v '^#' .env | xargs) python3 app.py
"""
import json
import os
import queue
import random
import socket
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _app_dir():
    """Directory of the running app — the PyInstaller exe dir when frozen,
    else this source file's dir. Used for .env and bundled data."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _resource(name):
    """Path to a bundled data file (world.geojson, the mmdb): PyInstaller
    unpacks data into sys._MEIPASS; fall back to the app dir / source dir."""
    for base in (getattr(sys, "_MEIPASS", None), _app_dir()):
        if base:
            p = os.path.join(base, name)
            if os.path.exists(p):
                return p
    return os.path.join(_app_dir(), name)


def _load_dotenv():
    """Load KEY=VALUE lines from a .env beside the app (no deps) so the
    packaged binary is configurable without setting shell env vars."""
    try:
        with open(os.path.join(_app_dir(), ".env"), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    except OSError:
        pass


_load_dotenv()

import geo        # noqa: E402  (after dotenv so GEOIP_MMDB is honoured)
import sources    # noqa: E402

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8100"))
HOME = {"lat": float(os.getenv("HOME_LAT", "52.37")),
        "lon": float(os.getenv("HOME_LON", "4.90"))}   # default: Amsterdam, NL
EMIT_RATE = float(os.getenv("EMIT_RATE", "6"))          # arcs per second (smoothing)
RING = int(os.getenv("RING", "400"))                    # history kept for /recent
FIRST_BURST = int(os.getenv("FIRST_BURST", "40"))       # arcs emitted on a feed's 1st poll
SEEN_MAX = int(os.getenv("SEEN_MAX", "60000"))          # per-feed dedup memory cap
DNS_CAP = int(os.getenv("DNS_CAP", "25"))               # urlhaus host lookups / cycle
REPLAY_RATE = float(os.getenv("REPLAY_RATE", "1.6"))    # arcs/s replayed from pool (0 = off)
POOL_MAX = int(os.getenv("POOL_MAX", "6000"))           # geolocated events kept for replay

TYPE_COLOR = {
    "ddos": "#ff3860", "ransomware": "#ff4444", "malware": "#ff8c00",
    "bruteforce": "#ffd166", "webattack": "#06d6a0", "intrusion": "#bc8cff",
    "recon": "#58a6ff", "other": "#8b949e",
}

# --------------------------------------------------------------------------- #
# Shared state
# --------------------------------------------------------------------------- #
_events = deque(maxlen=RING)          # recent emitted events (for initial paint)
_pool = deque(maxlen=POOL_MAX)        # geolocated events available for replay trickle
_subs = set()                         # set[queue.Queue] live SSE subscribers
_emitq = queue.Queue(maxsize=5000)    # poller -> emitter backlog (rate-smoothed)
_lock = threading.Lock()
_stats = {"total": 0, "by_source": {}, "by_type": {}, "by_country": {},
          "started": time.time()}


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _make_event(raw):
    """RAW feed dict -> mappable event, or None if non-routable / unresolvable."""
    ip = raw.get("ip")
    if not ip and raw.get("host"):
        ip = _resolve_host(raw["host"])
    if not ip:
        return None
    loc = geo.locate(ip, country=raw.get("country"))
    if not loc:
        return None
    typ = raw.get("type", "other")
    return {
        "ip": ip,
        "src": {"lat": loc["lat"], "lon": loc["lon"]},
        "country": loc.get("country") or raw.get("country") or "?",
        "cc": loc.get("cc"),
        "type": typ,
        "color": TYPE_COLOR.get(typ, TYPE_COLOR["other"]),
        "source": raw.get("source", "?"),
        "label": raw.get("label", ""),
        "weight": float(raw.get("weight", 0.6)),
        "level": 2 if raw.get("weight", 0) >= 0.9 else 1,
        "synthetic": bool(loc.get("synthetic")),
        "ts": _now_iso(),
    }


def _broadcast(ev):
    with _lock:
        _events.append(ev)
        if not ev.get("replay"):
            _pool.append(ev)
        _stats["total"] += 1
        for k, d in (("by_source", ev["source"]), ("by_type", ev["type"]),
                     ("by_country", ev["country"])):
            _stats[k][d] = _stats[k].get(d, 0) + 1
        dead = []
        for q in _subs:
            try:
                q.put_nowait(ev)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _subs.discard(q)


# --------------------------------------------------------------------------- #
# Emitter — drains the backlog at EMIT_RATE so feed bursts flow like a stream
# --------------------------------------------------------------------------- #
def _emitter():
    interval = 1.0 / EMIT_RATE if EMIT_RATE > 0 else 0
    while True:
        ev = _emitq.get()
        _broadcast(ev)
        if interval:
            time.sleep(interval)


# --------------------------------------------------------------------------- #
# Pollers — one thread per feed; emit only NEW IPs (natural trickle)
# --------------------------------------------------------------------------- #
def _poller(name, fetch, interval):
    seen = set()
    first = True
    while True:
        try:
            raw = fetch() or []
        except Exception as e:
            print(f"[{name}] fetch error: {e}", flush=True)
            raw = []
        emitted = 0
        cap = FIRST_BURST if first else 10**9
        dns_used = 0
        for r in raw:
            key = r.get("ip") or r.get("host")
            if not key or key in seen:
                continue
            seen.add(key)
            # bound DNS work for host-only (urlhaus) entries per cycle
            if not r.get("ip") and r.get("host"):
                if dns_used >= DNS_CAP:
                    continue
                dns_used += 1
            if emitted >= cap:
                continue   # seed dedup silently; don't storm on first poll
            ev = _make_event(r)
            if ev:
                try:
                    _emitq.put_nowait(ev)
                    emitted += 1
                except queue.Full:
                    pass
        if len(seen) > SEEN_MAX:                 # trim oldest-ish (set has no order)
            seen = set(list(seen)[-SEEN_MAX // 2:])
        print(f"[{name}] fetched={len(raw)} emitted={emitted} "
              f"seen={len(seen)} first={first}", flush=True)
        first = False
        time.sleep(interval)


def _replayer():
    """Re-emit known-bad IPs from the pool at a steady baseline so the map
    never goes dead between (slow) feed refreshes. Same real malicious infra,
    redrawn — flagged replay so the front-end can treat it lightly."""
    if REPLAY_RATE <= 0:
        return
    interval = 1.0 / REPLAY_RATE
    while True:
        time.sleep(interval)
        with _lock:
            ev = random.choice(_pool) if _pool else None
        if ev is None:
            continue
        clone = dict(ev)
        clone["replay"] = True
        clone["ts"] = _now_iso()
        try:
            _emitq.put_nowait(clone)
        except queue.Full:
            pass


def start_workers():
    threading.Thread(target=_emitter, daemon=True, name="emitter").start()
    threading.Thread(target=_replayer, daemon=True, name="replayer").start()
    for name, fetch, interval in sources.SOURCES:
        threading.Thread(target=_poller, args=(name, fetch, interval),
                         daemon=True, name=f"poll-{name}").start()


# --------------------------------------------------------------------------- #
# HTTP / SSE
# --------------------------------------------------------------------------- #
_WORLD = _resource("world.geojson")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def do_GET(self):
        if self.path.split("?")[0].rstrip("/") == "/manual":
            _serve_manual(self); return
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, PAGE)
        elif path == "/healthz":
            self._json(200, {"ok": True, "total": _stats["total"]})
        elif path == "/api/socmap/world":
            try:
                with open(_WORLD, "rb") as f:
                    self._send(200, f.read(), "application/json",
                               {"Cache-Control": "max-age=86400"})
            except OSError:
                self._json(404, {"error": "world map missing"})
        elif path == "/api/socmap/recent":
            limit = 200
            if "limit=" in self.path:
                try:
                    limit = max(1, min(int(self.path.split("limit=")[1].split("&")[0]), RING))
                except ValueError:
                    pass
            with _lock:
                evs = list(_events)[-limit:]
            self._json(200, {"home": HOME, "events": evs})
        elif path == "/api/socmap/stats":
            with _lock:
                self._json(200, dict(_stats))
        elif path == "/api/socmap/stream":
            self._stream()
        else:
            self._json(404, {"error": "not found"})

    def _stream(self):
        q = queue.Queue(maxsize=500)
        with _lock:
            _subs.add(q)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            last = time.time()
            while True:
                try:
                    ev = q.get(timeout=5)
                    self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
                    self.wfile.flush()
                    last = time.time()
                except queue.Empty:
                    if time.time() - last > 15:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        last = time.time()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            pass
        finally:
            with _lock:
                _subs.discard(q)


def main():
    start_workers()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"socmap on http://{HOST}:{PORT}  "
          f"(home={HOME['lat']},{HOME['lon']} rate={EMIT_RATE}/s)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye", flush=True)


# --------------------------------------------------------------------------- #
# Front-end (HTML5 canvas, no deps) — adapted from the socops live map
# --------------------------------------------------------------------------- #
PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOC Threatmap — Live Threat Feeds</title>
<style>
:root{--border:#222c38;--muted:#7d8590;--text:#c9d1d9;--accent:#58a6ff;--surface2:#161b22;}
*{box-sizing:border-box;margin:0;padding:0;}
body{height:100vh;overflow:hidden;background:#05080f;color:var(--text);
  font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;}
#map{position:fixed;inset:0;width:100vw;height:100vh;display:block;z-index:1;}
.panel{position:fixed;z-index:20;background:rgba(13,17,23,.8);border:1px solid var(--border);
  border-radius:10px;padding:12px 14px;backdrop-filter:blur(8px);font-size:12px;}
#title{top:12px;left:14px;font-weight:800;font-size:15px;letter-spacing:.4px;color:#fff;
  display:flex;align-items:center;gap:8px;}
.live-dot{width:8px;height:8px;border-radius:50%;background:#3fb950;display:inline-block;
  animation:lp 1.4s ease-in-out infinite;}
@keyframes lp{0%,100%{opacity:1;}50%{opacity:.25;}}
#stats{top:52px;left:14px;width:210px;}
#ticker{right:12px;top:52px;width:290px;max-height:calc(100vh - 76px);overflow:hidden;}
.panel h3{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);
  margin-bottom:8px;font-weight:700;}
.big{font-size:30px;font-weight:800;color:#fff;line-height:1;}
.big small{font-size:11px;color:var(--muted);font-weight:500;letter-spacing:.5px;}
.row{display:flex;align-items:center;gap:8px;padding:3px 0;}
.row .lbl{flex:1;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.row .ct{font-weight:700;color:#fff;}
.swatch{width:9px;height:9px;border-radius:2px;flex-shrink:0;}
.sec{margin-top:12px;}
.tick{display:flex;gap:8px;align-items:baseline;padding:4px 0;border-top:1px solid rgba(48,54,61,.5);
  font-size:11px;animation:fadein .4s;}
.tick .ip{font-family:Courier New,monospace;color:#fff;}
.tick .cn{color:var(--muted);}
.tick .sr{font-size:9px;color:var(--muted);}
.tick .ty{font-weight:700;margin-left:auto;}
.tick.syn{opacity:.55;}
@keyframes fadein{from{opacity:0;transform:translateX(8px);}to{opacity:1;}}
#legend{position:fixed;bottom:12px;left:14px;z-index:20;display:flex;gap:10px;flex-wrap:wrap;
  background:rgba(13,17,23,.7);border:1px solid var(--border);border-radius:8px;padding:6px 10px;font-size:11px;}
.lg{display:flex;align-items:center;gap:5px;color:var(--muted);}
#note{position:fixed;bottom:12px;right:12px;z-index:20;font-size:10px;color:var(--muted);
  background:rgba(13,17,23,.7);border:1px solid var(--border);border-radius:8px;padding:5px 9px;max-width:330px;}
#zoomctl{position:fixed;right:12px;bottom:46px;z-index:25;display:flex;flex-direction:column;gap:4px;}
#zoomctl button{width:32px;height:32px;font-size:18px;line-height:1;cursor:pointer;
  background:rgba(13,17,23,.8);color:var(--text);border:1px solid var(--border);border-radius:7px;
  backdrop-filter:blur(6px);transition:.15s;}
#zoomctl button:hover{background:var(--surface2);border-color:var(--accent);color:var(--accent);}
#sound{position:fixed;top:12px;right:12px;z-index:30;width:40px;height:40px;border-radius:50%;
  background:rgba(13,17,23,.85);border:1px solid var(--border);color:var(--muted);font-size:18px;
  display:flex;align-items:center;justify-content:center;cursor:pointer;user-select:none;backdrop-filter:blur(6px);}
#sound.on{color:var(--accent);border-color:var(--accent);}
#sound.hint{animation:sh 1.3s ease-in-out infinite;border-color:var(--accent);color:var(--accent);}
@keyframes sh{0%,100%{box-shadow:0 0 0 0 rgba(88,166,255,.55);}50%{box-shadow:0 0 0 9px rgba(88,166,255,0);}}
</style></head><body><a href="/manual" target="_blank" title="Manual / Help" style="position:fixed;top:12px;right:14px;z-index:99999;width:30px;height:30px;border-radius:50%;background:#161b22;border:1px solid #30363d;color:#58a6ff;font:700 16px/30px system-ui,sans-serif;text-align:center;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.4)" onmouseover="this.style.borderColor='#58a6ff'" onmouseout="this.style.borderColor='#30363d'">?</a>
<canvas id="map"></canvas>
<div id="title"><span class="live-dot"></span>SOC Threatmap <span style="color:var(--muted);font-weight:500;font-size:11px">live threat feeds</span></div>
<div class="panel" id="stats">
  <div class="big"><span id="total">0</span> <small>events</small></div>
  <div class="big" style="font-size:16px;margin-top:6px;"><span id="rate">0</span> <small>/min</small></div>
  <div class="sec"><h3>Top Origins</h3><div id="origins"></div></div>
  <div class="sec"><h3>By Source</h3><div id="srcs"></div></div>
  <div class="sec"><h3>By Type</h3><div id="types"></div></div>
</div>
<div class="panel" id="ticker"><h3>Latest</h3><div id="ticks"></div></div>
<div id="zoomctl">
  <button id="zin" title="Zoom in">+</button>
  <button id="zout" title="Zoom out">&minus;</button>
  <button id="zreset" title="Reset view">&#9633;</button>
</div>
<div id="sound" class="hint" title="sound on/off">🔇</div>
<div id="legend"></div>
<div id="note">Arcs = malicious IPs from public threat feeds (abuse.ch, DShield, blocklist.de, CINS), geolocated to an <b>approximate origin</b> — known-bad infrastructure, not live victim attribution. <span id="synnote"></span></div>
<script>
const TYPES={ddos:'#ff3860',ransomware:'#ff4444',malware:'#ff8c00',bruteforce:'#ffd166',
  webattack:'#06d6a0',intrusion:'#bc8cff',recon:'#58a6ff',other:'#8b949e'};
const cv=document.getElementById('map'),ctx=cv.getContext('2d');
let W=0,H=0,DPR=Math.min(window.devicePixelRatio||1,2);
let base=null,world=null,HOME={lat:52.37,lon:4.90};
const arcs=[],pings=[],dots=[];
const counts={total:0,origins:{},types:{},srcs:{}};
const recentTimes=[];
function proj(lat,lon){return [(lon+180)/360*W,(90-lat)/180*H];}
const view={zoom:1,panX:0,panY:0};
function tx(x){return view.panX+x*view.zoom;} function ty(y){return view.panY+y*view.zoom;}
const ZMIN=0.35,ZMAX=8;
function clampPan(){const wW=W*view.zoom,wH=H*view.zoom;
  view.panX=wW>=W?Math.min(0,Math.max(W-wW,view.panX)):(W-wW)/2;
  view.panY=wH>=H?Math.min(0,Math.max(H-wH,view.panY)):(H-wH)/2;}
function zoomAt(sx,sy,f){const nz=Math.min(ZMAX,Math.max(ZMIN,view.zoom*f));if(nz===view.zoom)return;
  const wx=(sx-view.panX)/view.zoom,wy=(sy-view.panY)/view.zoom;
  view.zoom=nz;view.panX=sx-wx*nz;view.panY=sy-wy*nz;clampPan();}
function resize(){W=window.innerWidth;H=window.innerHeight;
  cv.width=W*DPR;cv.height=H*DPR;cv.style.width=W+'px';cv.style.height=H+'px';
  ctx.setTransform(DPR,0,0,DPR,0,0);drawBase();}
window.addEventListener('resize',resize);
function drawBase(){base=document.createElement('canvas');base.width=W;base.height=H;
  const b=base.getContext('2d');b.fillStyle='#05080f';b.fillRect(0,0,W,H);
  b.strokeStyle='rgba(40,60,90,.25)';b.lineWidth=1;
  for(let lon=-180;lon<=180;lon+=30){const[x]=proj(0,lon);b.beginPath();b.moveTo(x,0);b.lineTo(x,H);b.stroke();}
  for(let lat=-60;lat<=60;lat+=30){const[,y]=proj(lat,0);b.beginPath();b.moveTo(0,y);b.lineTo(W,y);b.stroke();}
  if(world){b.lineWidth=0.7;for(const f of world.features){const g=f.geometry;if(!g)continue;
    const polys=g.type==='Polygon'?[g.coordinates]:g.type==='MultiPolygon'?g.coordinates:[];
    for(const poly of polys)for(const ring of poly){b.beginPath();
      for(let i=0;i<ring.length;i++){const[x,y]=proj(ring[i][1],ring[i][0]);i===0?b.moveTo(x,y):b.lineTo(x,y);}
      b.closePath();b.fillStyle='rgba(28,42,64,.55)';b.fill();b.strokeStyle='rgba(70,100,140,.45)';b.stroke();}}}
  const[hx,hy]=proj(HOME.lat,HOME.lon);b.fillStyle='#58a6ff';b.beginPath();b.arc(hx,hy,3,0,7);b.fill();}
function addEvent(ev){counts.total++;
  const t=ev.type||'other';counts.types[t]=(counts.types[t]||0)+1;
  const cn=ev.country||'?';counts.origins[cn]=(counts.origins[cn]||0)+1;
  const sr=ev.source||'?';counts.srcs[sr]=(counts.srcs[sr]||0)+1;
  recentTimes.push(Date.now());
  const[x0,y0]=proj(ev.src.lat,ev.src.lon),[x1,y1]=proj(HOME.lat,HOME.lon);
  const dist=Math.hypot(x1-x0,y1-y0),lift=Math.min(dist*0.3,220);
  const ctrl=[(x0+x1)/2,(y0+y1)/2-lift],col=ev.color||TYPES[t]||TYPES.other;
  const w=ev.weight!==undefined?ev.weight:0.6;
  arcs.push({x0,y0,x1,y1,cx:ctrl[0],cy:ctrl[1],col,w,t:0,dur:900+dist*0.6,syn:ev.synthetic});
  dots.push({x:x0,y:y0,col,t:0,syn:ev.synthetic,w});addTick(ev);
  try{Sound.zap(ev);}catch(e){}}
function addTick(ev){const box=document.getElementById('ticks');const d=document.createElement('div');
  d.className='tick'+(ev.synthetic?' syn':'');
  d.innerHTML='<span class="ip">'+esc(ev.ip)+'</span><span class="cn">'+esc(ev.country||'')+(ev.synthetic?' ~':'')+
    '</span><span class="sr">'+esc(ev.source||'')+'</span><span class="ty" style="color:'+(ev.color||'#888')+'">'+esc(ev.type||'')+'</span>';
  box.insertBefore(d,box.firstChild);while(box.children.length>14)box.removeChild(box.lastChild);}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function rows(obj,colorMap){return Object.entries(obj).sort((a,b)=>b[1]-a[1]).slice(0,6).map(function(e){
  const sw=colorMap?'<span class="swatch" style="background:'+(colorMap[e[0]]||'#888')+'"></span>':'';
  return '<div class="row">'+sw+'<span class="lbl">'+esc(e[0])+'</span><span class="ct">'+e[1]+'</span></div>';
}).join('')||'<div class="row" style="color:var(--muted)">—</div>';}
function renderPanels(){document.getElementById('total').textContent=counts.total;
  const cut=Date.now()-60000;while(recentTimes.length&&recentTimes[0]<cut)recentTimes.shift();
  document.getElementById('rate').textContent=recentTimes.length;
  document.getElementById('origins').innerHTML=rows(counts.origins,null);
  document.getElementById('srcs').innerHTML=rows(counts.srcs,null);
  document.getElementById('types').innerHTML=rows(counts.types,TYPES);}
setInterval(renderPanels,1000);
function loop(){ctx.clearRect(0,0,W,H);
  if(base)ctx.drawImage(base,view.panX,view.panY,W*view.zoom,H*view.zoom);
  ctx.globalCompositeOperation='lighter';
  for(let i=arcs.length-1;i>=0;i--){const a=arcs[i];a.t+=16/a.dur;const p=Math.min(a.t,1);
    ctx.beginPath();const steps=Math.ceil(28*p)+1;
    for(let s=0;s<=steps;s++){const u=(s/steps)*p,iu=1-u;
      const x=iu*iu*a.x0+2*iu*u*a.cx+u*u*a.x1,y=iu*iu*a.y0+2*iu*u*a.cy+u*u*a.y1;
      s===0?ctx.moveTo(tx(x),ty(y)):ctx.lineTo(tx(x),ty(y));}
    const w=a.w!==undefined?a.w:0.6;
    ctx.strokeStyle=a.col;ctx.globalAlpha=(a.syn?0.5:1)*w*(1-Math.max(0,a.t-1)*2);
    ctx.lineWidth=(0.7+1.6*w)*(a.syn?0.8:1);ctx.shadowBlur=4+10*w;ctx.shadowColor=a.col;ctx.stroke();ctx.shadowBlur=0;
    const iu=1-p,hx=iu*iu*a.x0+2*iu*p*a.cx+p*p*a.x1,hy=iu*iu*a.y0+2*iu*p*a.cy+p*p*a.y1;
    if(p<1){ctx.globalAlpha=(a.syn?0.6:1)*w;ctx.fillStyle=a.col;ctx.beginPath();ctx.arc(tx(hx),ty(hy),1.2+2*w,0,7);ctx.fill();}
    if(a.t>=1&&!a.hit){a.hit=true;if(w>=0.7)pings.push({x:a.x1,y:a.y1,t:0,col:a.col});}
    if(a.t>1.5)arcs.splice(i,1);}
  for(let i=pings.length-1;i>=0;i--){const p=pings[i];p.t+=0.03;
    ctx.globalAlpha=Math.max(0,1-p.t);ctx.strokeStyle=p.col;ctx.lineWidth=1.5;
    ctx.beginPath();ctx.arc(tx(p.x),ty(p.y),p.t*26*view.zoom,0,7);ctx.stroke();if(p.t>=1)pings.splice(i,1);}
  for(let i=dots.length-1;i>=0;i--){const d=dots[i];d.t+=0.012;const dw=d.w!==undefined?d.w:0.6;
    ctx.globalAlpha=Math.max(0,(d.syn?0.5:0.9)*(0.4+0.6*dw)-d.t);ctx.fillStyle=d.col;
    ctx.beginPath();ctx.arc(tx(d.x),ty(d.y),1.6+2*dw+d.t*2,0,7);ctx.fill();if(d.t>=1)dots.splice(i,1);}
  ctx.globalAlpha=1;ctx.globalCompositeOperation='source-over';
  if(arcs.length>240)arcs.splice(0,arcs.length-240);
  if(dots.length>400)dots.splice(0,dots.length-400);
  requestAnimationFrame(loop);}
function buildLegend(){document.getElementById('legend').innerHTML=Object.keys(TYPES).map(function(k){
  return '<span class="lg"><span class="swatch" style="background:'+TYPES[k]+'"></span>'+k+'</span>';}).join('');}
function wireControls(){
  cv.addEventListener('wheel',function(e){e.preventDefault();zoomAt(e.offsetX,e.offsetY,e.deltaY<0?1.15:1/1.15);},{passive:false});
  cv.addEventListener('dblclick',function(e){zoomAt(e.offsetX,e.offsetY,1.5);});
  let drag=false,lx=0,ly=0;
  cv.addEventListener('mousedown',function(e){drag=true;lx=e.clientX;ly=e.clientY;cv.style.cursor='grabbing';});
  window.addEventListener('mouseup',function(){drag=false;cv.style.cursor='grab';});
  window.addEventListener('mousemove',function(e){if(!drag)return;view.panX+=e.clientX-lx;view.panY+=e.clientY-ly;lx=e.clientX;ly=e.clientY;clampPan();});
  cv.style.cursor='grab';
  let pdist=0,tlx=0,tly=0;const rect=()=>cv.getBoundingClientRect();
  cv.addEventListener('touchstart',function(e){if(e.touches.length===1){tlx=e.touches[0].clientX;tly=e.touches[0].clientY;}
    else if(e.touches.length===2){const a=e.touches[0],b=e.touches[1];pdist=Math.hypot(a.clientX-b.clientX,a.clientY-b.clientY);}},{passive:false});
  cv.addEventListener('touchmove',function(e){e.preventDefault();
    if(e.touches.length===1){const t=e.touches[0];view.panX+=t.clientX-tlx;view.panY+=t.clientY-tly;tlx=t.clientX;tly=t.clientY;clampPan();}
    else if(e.touches.length===2){const a=e.touches[0],b=e.touches[1];const nd=Math.hypot(a.clientX-b.clientX,a.clientY-b.clientY);
      const r=rect(),mx=(a.clientX+b.clientX)/2-r.left,my=(a.clientY+b.clientY)/2-r.top;if(pdist>0)zoomAt(mx,my,nd/pdist);pdist=nd;}},{passive:false});
  document.getElementById('zin').onclick=function(){zoomAt(W/2,H/2,1.3);};
  document.getElementById('zout').onclick=function(){zoomAt(W/2,H/2,1/1.3);};
  document.getElementById('zreset').onclick=function(){view.zoom=1;view.panX=0;view.panY=0;};}
// ---- audio: synthesized ambient drone + per-attack zaps (Web Audio) ------
const Sound=(function(){
  let ctx,master,padGain,enabled=false;
  const TYPE_F={ddos:70,ransomware:90,malware:165,bruteforce:240,webattack:330,intrusion:200,recon:540,other:300};
  let bucket=5,lastT=performance.now();
  function init2(){
    const AC=window.AudioContext||window.webkitAudioContext;if(!AC)return false;
    ctx=new AC();master=ctx.createGain();master.gain.value=0;
    const comp=ctx.createDynamicsCompressor();
    comp.threshold.value=-10;comp.knee.value=18;comp.ratio.value=12;comp.attack.value=0.003;comp.release.value=0.25;
    master.connect(comp);comp.connect(ctx.destination);
    padGain=ctx.createGain();padGain.gain.value=0.09;
    const filt=ctx.createBiquadFilter();filt.type='lowpass';filt.frequency.value=360;filt.Q.value=7;
    padGain.connect(filt);filt.connect(master);
    [55,82.5,110].forEach(function(f,i){const o=ctx.createOscillator();o.type=(i===2)?'triangle':'sawtooth';
      o.frequency.value=f;o.detune.value=(i-1)*7;const g=ctx.createGain();g.gain.value=(i===2)?0.22:0.45;
      o.connect(g);g.connect(padGain);o.start();});
    const lfo=ctx.createOscillator();lfo.frequency.value=0.05;const lg=ctx.createGain();lg.gain.value=190;
    lfo.connect(lg);lg.connect(filt.frequency);lfo.start();return true;}
  function enable(){if(!ctx&&!init2())return;if(ctx.state==='suspended')ctx.resume();
    enabled=true;master.gain.cancelScheduledValues(ctx.currentTime);
    master.gain.linearRampToValueAtTime(1.6,ctx.currentTime+0.8);}
  function disable(){if(!ctx)return;enabled=false;master.gain.cancelScheduledValues(ctx.currentTime);
    master.gain.linearRampToValueAtTime(0,ctx.currentTime+0.3);}
  function zap(ev){if(!enabled||!ctx)return;
    const now=performance.now();bucket=Math.min(5,bucket+(now-lastT)/1000*5);lastT=now;
    if(bucket<1)return;bucket-=1;
    const rep=!!ev.replay;if(rep&&Math.random()<0.55)return;
    const t0=ctx.currentTime,f0=TYPE_F[ev.type]||300;
    const o=ctx.createOscillator();o.type='sine';
    o.frequency.setValueAtTime(f0*3,t0);o.frequency.exponentialRampToValueAtTime(f0,t0+0.17);
    const w=(ev.weight!==undefined)?ev.weight:0.6,vol=(rep?0.32:0.7)*(0.5+0.5*w);
    const g=ctx.createGain();g.gain.setValueAtTime(0.0001,t0);
    g.gain.exponentialRampToValueAtTime(vol,t0+0.008);g.gain.exponentialRampToValueAtTime(0.0001,t0+0.22);
    o.connect(g);const lon=(ev.src&&ev.src.lon)||0;
    if(ctx.createStereoPanner){const p=ctx.createStereoPanner();p.pan.value=Math.max(-1,Math.min(1,lon/180));
      g.connect(p);p.connect(master);}else g.connect(master);
    o.start(t0);o.stop(t0+0.24);}
  return {enable:enable,disable:disable,zap:zap,isOn:function(){return enabled;}};
})();
(function(){const b=document.getElementById('sound');if(!b)return;
  b.addEventListener('click',function(){b.classList.remove('hint');
    if(Sound.isOn()){Sound.disable();b.textContent='🔇';b.classList.remove('on');}
    else{Sound.enable();b.textContent='🔊';b.classList.add('on');}});})();

let synSeen=false;
async function init(){resize();buildLegend();wireControls();loop();
  try{world=await fetch('/api/socmap/world').then(r=>r.json());drawBase();}catch(e){}
  try{const h=await fetch('/api/socmap/recent?limit=120').then(r=>r.json());
    if(h.home){HOME=h.home;drawBase();}
    (h.events||[]).forEach(function(ev){addEvent(ev);if(ev.synthetic)synSeen=true;});renderPanels();}catch(e){}
  document.getElementById('synnote').textContent=synSeen?'Faded arcs = un-geolocatable IPs (synthetic placement).':'';
  const es=new EventSource('/api/socmap/stream');
  es.onmessage=function(e){try{const ev=JSON.parse(e.data);addEvent(ev);
    if(ev.synthetic&&!synSeen){synSeen=true;document.getElementById('synnote').textContent='Faded arcs = un-geolocatable IPs (synthetic placement).';}}catch(_){}};}
init();
</script></body></html>"""




# ---- injected: /manual help page (stdlib markdown renderer) ----------------
def _md_to_html(md):
    import html, re as _re
    lines = md.split("\n")
    out = []; i = 0; n = len(lines)
    def inline(t):
        t = html.escape(t)
        t = _re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        t = _re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
        t = _re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)",
                    r'<a href="\2" target="_blank" rel="noopener">\1</a>', t)
        return t
    while i < n:
        ln = lines[i]
        if ln.startswith("```"):
            i += 1; buf = []
            while i < n and not lines[i].startswith("```"):
                buf.append(html.escape(lines[i])); i += 1
            i += 1
            out.append("<pre><code>" + "\n".join(buf) + "</code></pre>"); continue
        m = _re.match(r"(#{1,6})\s+(.*)", ln)
        if m:
            lv = len(m.group(1)); out.append("<h%d>%s</h%d>" % (lv, inline(m.group(2)), lv)); i += 1; continue
        if _re.match(r"\s*[-*]\s+", ln):
            out.append("<ul>")
            while i < n and _re.match(r"\s*[-*]\s+", lines[i]):
                out.append("<li>" + inline(_re.sub(r"\s*[-*]\s+", "", lines[i], count=1)) + "</li>"); i += 1
            out.append("</ul>"); continue
        if _re.match(r"\s*\d+\.\s+", ln):
            out.append("<ol>")
            while i < n and _re.match(r"\s*\d+\.\s+", lines[i]):
                out.append("<li>" + inline(_re.sub(r"\s*\d+\.\s+", "", lines[i], count=1)) + "</li>"); i += 1
            out.append("</ol>"); continue
        if ln.strip().startswith("|") and i + 1 < n and _re.match(r"^\s*\|[-:\s|]+\|\s*$", lines[i+1]):
            hdr = [c.strip() for c in ln.strip().strip("|").split("|")]
            out.append("<table><thead><tr>" + "".join("<th>%s</th>" % inline(c) for c in hdr) + "</tr></thead><tbody>")
            i += 2
            while i < n and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                out.append("<tr>" + "".join("<td>%s</td>" % inline(c) for c in cells) + "</tr>"); i += 1
            out.append("</tbody></table>"); continue
        if _re.match(r"^\s*---+\s*$", ln):
            out.append("<hr>"); i += 1; continue
        if ln.strip() == "":
            i += 1; continue
        para = [ln]; i += 1
        while i < n and lines[i].strip() and not _re.match(r"(#{1,6}\s|```|\s*[-*]\s|\s*\d+\.\s|\|)", lines[i]):
            para.append(lines[i]); i += 1
        out.append("<p>" + inline(" ".join(para)) + "</p>")
    return "\n".join(out)


def _manual_page(inner):
    return ("""<!DOCTYPE html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Manual</title><style>
:root{--bg:#0d1117;--sf:#161b22;--bd:#30363d;--tx:#e6edf3;--mut:#8b949e;--ac:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);
font:15px/1.65 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:32px 22px 80px}
.top{position:sticky;top:0;background:rgba(13,17,23,.92);backdrop-filter:blur(6px);
border-bottom:1px solid var(--bd);margin:-32px -22px 24px;padding:12px 22px;display:flex;
align-items:center;gap:12px}
.top a{color:var(--ac);text-decoration:none;font-size:13px}
h1,h2,h3,h4{color:#fff;line-height:1.25;margin:1.5em 0 .5em}
h1{font-size:26px;border-bottom:1px solid var(--bd);padding-bottom:.3em}
h2{font-size:20px;border-bottom:1px solid var(--bd);padding-bottom:.25em}
h3{font-size:16px}a{color:var(--ac)}
code{background:var(--sf);border:1px solid var(--bd);border-radius:4px;padding:1px 5px;
font:13px/1.4 ui-monospace,Menlo,monospace}
pre{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px 16px;
overflow:auto}pre code{background:none;border:0;padding:0}
ul,ol{padding-left:1.4em}li{margin:.25em 0}
table{border-collapse:collapse;width:100%;margin:1em 0;font-size:14px}
th,td{border:1px solid var(--bd);padding:7px 10px;text-align:left}
th{background:var(--sf)}hr{border:0;border-top:1px solid var(--bd);margin:2em 0}
.mut{color:var(--mut)}
</style></head><body><div class=wrap>
<div class=top><a href="/">&larr; Back to app</a><span class=mut>&middot; Manual</span></div>
""" + inner + "\n</div></body></html>")


def _serve_manual(handler):
    import os as _os
    p = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "MANUAL.md")
    try:
        with open(p, encoding="utf-8") as _fh:
            md = _fh.read()
    except OSError:
        md = "# Manual\n\nMANUAL.md not found next to the application."
    body = _manual_page(_md_to_html(md)).encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
# ---- end injected block -----------------------------------------------------

if __name__ == "__main__":
    main()
