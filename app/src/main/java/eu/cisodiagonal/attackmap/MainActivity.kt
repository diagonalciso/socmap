package eu.cisodiagonal.attackmap

import android.annotation.SuppressLint
import android.os.Bundle
import android.view.View
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

/**
 * Single-screen standalone attack map. A fullscreen WebView renders the canvas
 * map (assets/map.html); FeedEngine polls public threat feeds on the device and
 * pushes events into the page via evaluateJavascript. No backend required.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var web: WebView
    private var engine: FeedEngine? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        web = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = true
            settings.mediaPlaybackRequiresUserGesture = false   // let Web Audio start (still gated by the in-page tap)
            setBackgroundColor(0xFF05080F.toInt())
            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    onMapReady()
                }
            }
        }
        setContentView(web)
        hideSystemBars()
        web.loadUrl("file:///android_asset/map.html")
    }

    /** Page loaded: inject the world map, then start the feed engine. */
    private fun onMapReady() {
        // world.geojson is valid JSON => a valid JS expression for setWorld(...)
        val geo = try {
            assets.open("world.geojson").bufferedReader().use { it.readText() }
        } catch (e: Exception) { null }
        if (geo != null) js("window.setWorld($geo);")
        js("window.setHome(52.37, 4.90);")

        if (engine == null) {
            engine = FeedEngine(
                onEvent = { ev: JSONObject ->
                    val s = ev.toString()
                    runOnUiThread { js("window.pushEvent($s);") }
                },
                onStatus = { txt ->
                    val safe = txt.replace("'", " ")
                    runOnUiThread { js("window.setStatus('$safe');") }
                },
            ).also { it.start() }
        }
    }

    private fun js(code: String) {
        web.evaluateJavascript(code, null)
    }

    private fun hideSystemBars() {
        @Suppress("DEPRECATION")
        web.systemUiVisibility = (
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                or View.SYSTEM_UI_FLAG_FULLSCREEN
                or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
            )
    }

    override fun onDestroy() {
        engine?.stop()
        web.destroy()
        super.onDestroy()
    }
}
