# WebView JS bridge methods must survive shrinking (none enabled in release, but keep safe).
-keepclassmembers class eu.cisodiagonal.socmap.** {
    @android.webkit.JavascriptInterface <methods>;
}
