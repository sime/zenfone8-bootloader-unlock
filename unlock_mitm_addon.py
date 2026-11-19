"""
mitmproxy unlock script for ASUS ZenFone 8 (I006D), EU variant.

Run:  mitmproxy -s unlock.py
Then point the phone's Wi-Fi proxy at <mac-ip>:8080 and use the ASUS Unlock app.

NOTE (Nov 2026): ASUS's unlock backend no longer returns a secret token,
so this will almost certainly NOT unlock anything. Kept for a documented attempt.

swVer = "<android>..<fota-version>..<carrier>"
  android     : 13 (or 12 on Android 12)
  fota-version: ro.vendor.build.fota.version  -> WW_I006D-WW_user_33.0210.0210.296-...
  carrier     : ro.vendor.product.carrier      -> EU-ASUS_I006D-WW
"""
from mitmproxy import http

# Build currently flashed on the device (Android 12, 31.1010.0410.61).
SWVER = "12..WW_I006D-WW_user_9999999..999999.1010.0410.61..EU-ASUS_I006D-WW"


def request(flow: http.HTTPFlow) -> None:
    if flow.request.host == "dm.asus.com" and "/unlock/register" in flow.request.url:
        flow.request.urlencoded_form["apkVersion"] = "2.0"
        flow.request.urlencoded_form["swVer"] = SWVER
        flow.request.urlencoded_form["keyIndex"] = "1"
