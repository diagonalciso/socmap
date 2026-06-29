package eu.cisodiagonal.attackmap

import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

/**
 * Self-contained threat-feed engine. Mirrors the Python `sources.py` + `app.py`:
 * polls the same free public feeds directly from the device, geolocates each new
 * malicious IP via ip-api.com (batch, free, no key), and rate-smooths the bursts
 * into a stream of events handed to the WebView map. No server dependency.
 *
 * @param onEvent invoked (on a worker thread) for each emitted event; the caller
 *                marshals it onto the UI thread and into the WebView.
 * @param onStatus optional human status line for the map's centre overlay.
 */
class FeedEngine(
    private val onEvent: (JSONObject) -> Unit,
    private val onStatus: (String) -> Unit = {},
) {
    companion object {
        private const val UA = "attackmap-android/1.0 (+cisodiagonal)"
        private const val FIRST_BURST = 45
        private const val EMIT_PER_SEC = 6.0
        private const val REPLAY_PER_SEC = 1.6   // baseline trickle from pool so map never flatlines
        private const val POOL_MAX = 6000        // ring of geolocated events available for replay
        private const val DNS_CAP = 0            // host->IP DNS deferred; urlhaus IP rows still used

        private val TYPE_COLOR = mapOf(
            "ddos" to "#ff3860", "ransomware" to "#ff4444", "malware" to "#ff8c00",
            "bruteforce" to "#ffd166", "webattack" to "#06d6a0", "intrusion" to "#bc8cff",
            "recon" to "#58a6ff", "other" to "#8b949e",
        )

        // (name, url, type, weight, intervalMs, parser-kind)
        private data class Feed(
            val name: String, val url: String, val type: String,
            val weight: Double, val intervalMs: Long, val kind: String, val label: String,
        )

        private val FEEDS = listOf(
            Feed("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                "intrusion", 1.0, 30 * 60_000L, "feodo", "botnet C2"),
            Feed("urlhaus", "https://urlhaus.abuse.ch/downloads/csv_online/",
                "malware", 0.9, 5 * 60_000L, "urlhaus", "malware URL"),
            Feed("dshield", "https://isc.sans.edu/api/topips/records/0/120?json",
                "recon", 0.7, 60 * 60_000L, "dshield", "top attacker"),
            Feed("blocklist.de", "https://lists.blocklist.de/lists/all.txt",
                "bruteforce", 0.6, 30 * 60_000L, "text", "reported attacker"),
            Feed("cins", "https://cinsscore.com/list/ci-badguys.txt",
                "malware", 0.7, 60 * 60_000L, "text", "CINS bad actor"),
            // extra blocklists — bigger pool
            Feed("greensnow", "https://blocklist.greensnow.co/greensnow.txt",
                "bruteforce", 0.6, 30 * 60_000L, "text", "GreenSnow attacker"),
            Feed("et-compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "intrusion", 0.7, 60 * 60_000L, "text", "ET compromised host"),
            Feed("blocklist.de-ssh", "https://lists.blocklist.de/lists/ssh.txt",
                "bruteforce", 0.6, 30 * 60_000L, "text", "SSH brute-forcer"),
            // DataPlane.org — real sensor/honeypot-derived attacker IPs (no auth)
            Feed("dataplane-ssh", "https://dataplane.org/sshpwauth.txt",
                "bruteforce", 0.7, 60 * 60_000L, "dataplane", "honeypot SSH auth"),
            Feed("dataplane-telnet", "https://dataplane.org/telnetlogin.txt",
                "bruteforce", 0.7, 60 * 60_000L, "dataplane", "honeypot telnet (IoT)"),
            Feed("dataplane-vnc", "https://dataplane.org/vncrfb.txt",
                "intrusion", 0.7, 60 * 60_000L, "dataplane", "honeypot VNC probe"),
            Feed("dataplane-sip", "https://dataplane.org/sipquery.txt",
                "recon", 0.6, 60 * 60_000L, "dataplane", "honeypot SIP scan"),
        )
    }

    private data class Raw(
        val ip: String, val type: String, val source: String,
        val label: String, val country: String?, val weight: Double,
    )

    private val emitQ = LinkedBlockingQueue<JSONObject>(4000)
    private val geoCache = ConcurrentHashMap<String, DoubleArray>()    // ip -> [lat,lon, synthetic?1:0]
    private val geoCountry = ConcurrentHashMap<String, String>()
    private val pool = ArrayList<JSONObject>()                         // geolocated events for replay trickle
    private val poolLock = Any()
    private val rng = java.util.Random()
    @Volatile private var running = false
    private val ipRegex = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")

    fun start() {
        if (running) return
        running = true
        Thread({ emitter() }, "emitter").apply { isDaemon = true }.start()
        Thread({ replay() }, "replay").apply { isDaemon = true }.start()
        for (f in FEEDS) {
            Thread({ pollLoop(f) }, "poll-${f.name}").apply { isDaemon = true }.start()
        }
        onStatus("starting feeds…")
    }

    fun stop() { running = false }

    // ----- emitter: drain backlog at a steady rate so the map flows ----------
    private fun emitter() {
        val gapMs = (1000.0 / EMIT_PER_SEC).toLong()
        while (running) {
            val ev = try { emitQ.take() } catch (e: InterruptedException) { break }
            onEvent(ev)
            try { Thread.sleep(gapMs) } catch (e: InterruptedException) { break }
        }
    }

    // ----- replay: re-emit known-bad infra from the pool at a steady baseline
    // so the map never goes dead between (slow) feed refreshes. Honest: these
    // are the same real malicious IPs already shown, redrawn.
    private fun replay() {
        val gapMs = (1000.0 / REPLAY_PER_SEC).toLong()
        while (running) {
            sleepMs(gapMs)
            val src = synchronized(poolLock) {
                if (pool.isEmpty()) null else pool[rng.nextInt(pool.size)]
            } ?: continue
            val ev = try { JSONObject(src.toString()) } catch (e: Exception) { continue }
            ev.put("replay", true)
            try { emitQ.offer(ev) } catch (e: Exception) {}
        }
    }

    private fun poolAdd(ev: JSONObject) = synchronized(poolLock) {
        pool.add(ev)
        if (pool.size > POOL_MAX) pool.subList(0, pool.size - POOL_MAX).clear()
    }

    // ----- one feed poller ----------------------------------------------------
    private fun pollLoop(f: Feed) {
        val seen = HashSet<String>()
        var first = true
        while (running) {
            try {
                val raws = fetchFeed(f)
                val fresh = ArrayList<Raw>()
                val cap = if (first) FIRST_BURST else Int.MAX_VALUE
                for (r in raws) {
                    if (r.ip in seen) continue
                    seen.add(r.ip)
                    if (fresh.size < cap) fresh.add(r)
                }
                if (fresh.isNotEmpty()) {
                    geolocateAndEnqueue(fresh)
                }
                if (seen.size > 60000) seen.clear()
            } catch (e: Exception) {
                // dead feed never kills the map
            }
            first = false
            sleepMs(f.intervalMs)
        }
    }

    private fun geolocateAndEnqueue(raws: List<Raw>) {
        // resolve unknown IPs one-by-one via ipwho.is (HTTPS, free, no key), cached
        val unknown = raws.map { it.ip }.filter { !geoCache.containsKey(it) }.distinct()
        for (ip in unknown) {
            ipWhoIs(ip)
            sleepMs(120)    // be polite to the free endpoint
        }
        for (r in raws) {
            val loc = geoCache[r.ip] ?: fallbackLoc(r)
            val ev = JSONObject().apply {
                put("ip", r.ip)
                put("src", JSONObject().put("lat", loc[0]).put("lon", loc[1]))
                put("country", geoCountry[r.ip] ?: r.country ?: "?")
                put("type", r.type)
                put("color", TYPE_COLOR[r.type] ?: TYPE_COLOR["other"])
                put("source", r.source)
                put("label", r.label)
                put("weight", r.weight)
                put("synthetic", loc[2] > 0.5)
            }
            poolAdd(JSONObject(ev.toString()))
            try { emitQ.offer(ev) } catch (e: Exception) {}
        }
    }

    // ----- geolocation (ipwho.is, HTTPS, free, no key) ------------------------
    private fun ipWhoIs(ip: String) {
        if (geoCache.containsKey(ip)) return
        try {
            val o = JSONObject(httpGet("https://ipwho.is/$ip"
                + "?fields=success,latitude,longitude,country,country_code"))
            if (o.optBoolean("success", false)) {
                geoCache[ip] = doubleArrayOf(
                    o.optDouble("latitude"), o.optDouble("longitude"), 0.0)
                o.optString("country").takeIf { it.isNotEmpty() }?.let { geoCountry[ip] = it }
            }
        } catch (e: Exception) {
            // leave unresolved -> fallbackLoc handles it (synthetic, flagged)
        }
    }

    /** Deterministic synthetic land scatter for IPs ip-api couldn't place. */
    private fun fallbackLoc(r: Raw): DoubleArray {
        geoCache[r.ip]?.let { return it }
        var h = 2166136261L.toInt()
        for (c in r.ip) { h = h xor c.code; h *= 16777619 }
        val lat = ((abs(h) % 12000) / 100.0) - 55.0     // -55..65
        val lon = ((abs(h / 13) % 34000) / 100.0) - 170.0  // -170..170
        val loc = doubleArrayOf(max(-78.0, min(78.0, lat)), lon, 1.0)
        geoCache[r.ip] = loc
        return loc
    }

    // ----- feed fetch + parse -------------------------------------------------
    private fun fetchFeed(f: Feed): List<Raw> = when (f.kind) {
        "feodo" -> parseFeodo(httpGet(f.url), f)
        "urlhaus" -> parseUrlhaus(httpGet(f.url), f)
        "dshield" -> parseDshield(httpGet(f.url), f)
        "dataplane" -> parseDataplane(httpGet(f.url), f)
        else -> parseText(httpGet(f.url), f)
    }

    // DataPlane.org feeds: pipe-delimited  ASN | ASname | IP | lastseen | category
    private fun parseDataplane(txt: String, f: Feed): List<Raw> {
        val out = ArrayList<Raw>()
        for (line in txt.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) continue
            val cols = t.split('|')
            if (cols.size < 3) continue
            val ip = cols[2].trim()
            if (!isIp(ip)) continue
            out.add(Raw(ip, f.type, f.name, f.label, null, f.weight))
        }
        return out
    }

    private fun parseFeodo(txt: String, f: Feed): List<Raw> {
        val out = ArrayList<Raw>()
        val arr = JSONArray(txt)
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            val ip = o.optString("ip_address")
            if (!isIp(ip)) continue
            out.add(Raw(ip, f.type, f.name,
                o.optString("malware").ifEmpty { f.label },
                o.optString("country").takeIf { it.isNotEmpty() }, f.weight))
        }
        return out
    }

    private fun parseUrlhaus(txt: String, f: Feed): List<Raw> {
        val out = ArrayList<Raw>()
        for (line in txt.lineSequence()) {
            if (line.isEmpty() || line.startsWith("#")) continue
            // CSV: id,dateadded,url,url_status,last_online,threat,tags,link,reporter
            val cols = splitCsv(line)
            if (cols.size < 6) continue
            val url = cols[2]
            val sep = url.indexOf("://")
            if (sep < 0) continue
            var host = url.substring(sep + 3)
            host = host.substringBefore('/').substringBefore(':')
            if (!isIp(host)) continue   // only IP-host rows (no DNS on device for v1)
            out.add(Raw(host, f.type, f.name,
                cols[5].replace('_', ' ').ifEmpty { f.label }, null, f.weight))
        }
        return out
    }

    private fun parseDshield(txt: String, f: Feed): List<Raw> {
        val out = ArrayList<Raw>()
        val arr = try { JSONArray(txt) } catch (e: Exception) {
            JSONObject(txt).optJSONArray("topips") ?: JSONArray()
        }
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val ip = o.optString("ipaddr", o.optString("source", o.optString("ip")))
            if (!isIp(ip)) continue
            out.add(Raw(ip, f.type, f.name, f.label, null, f.weight))
        }
        return out
    }

    private fun parseText(txt: String, f: Feed): List<Raw> {
        val out = ArrayList<Raw>()
        for (line in txt.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) continue
            val tok = t.split(Regex("\\s+"))[0].substringBefore('/')
            if (isIp(tok)) out.add(Raw(tok, f.type, f.name, f.label, null, f.weight))
        }
        return out
    }

    // ----- helpers ------------------------------------------------------------
    private fun isIp(s: String?) = s != null && ipRegex.matches(s)

    private fun splitCsv(line: String): List<String> {
        val out = ArrayList<String>(); val sb = StringBuilder(); var q = false
        for (c in line) {
            when {
                c == '"' -> q = !q
                c == ',' && !q -> { out.add(sb.toString()); sb.setLength(0) }
                else -> sb.append(c)
            }
        }
        out.add(sb.toString())
        return out
    }

    private fun httpGet(url: String): String {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 15000; readTimeout = 25000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", UA)
            setRequestProperty("Accept", "*/*")
        }
        return readBody(conn)
    }

    private fun readBody(conn: HttpURLConnection): String {
        val stream = if (conn.responseCode in 200..399) conn.inputStream else conn.errorStream
        return BufferedReader(InputStreamReader(stream)).use { it.readText() }
    }

    private fun sleepMs(ms: Long) { try { Thread.sleep(ms) } catch (e: InterruptedException) {} }
}
