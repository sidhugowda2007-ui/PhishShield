# PhishGuard for Android

Android version of the PhishGuard Chrome extension. Same heuristic link scoring (ported to Java, verified identical
to `analyzer.js` on 38 test URLs), same dashboard and warning screens, all analysis on-device.

## What it does

| Where the link comes from | How PhishGuard sees it |
|---|---|
| Tapped in any app (SMS, WhatsApp, email, ...) | Choose PhishGuard as a browser app. Safe links are forwarded instantly to your real browser; risky ones show the warning screen first. |
| Shared to PhishGuard (Share > PhishGuard) | Same check. |
| Arrives as a notification, even when the app is closed | **Background scanning**: a notification listener scans link text and raises a "risky link" alert. |

The dashboard (links checked, risks caught, 7-day chart, safety overview, recent activity) is the extension's popup UI.

## Setup on the phone
1. Install the APK and open PhishGuard.
2. **Background link scanning > Turn on**: enable PhishGuard under Notification access. Allow notifications when asked.
3. **Check links tapped in other apps > Set up**: Default apps > Browser app > PhishGuard.
4. **Safe links open in**: pick the real browser to forward to (Chrome is auto-picked if present).
5. Samsung/Xiaomi/OnePlus etc.: set PhishGuard's battery usage to "Unrestricted" so the system doesn't stop background scanning.

## Getting an APK
- **GitHub (no installs):** push this folder to a GitHub repo. The *Build APK* workflow runs automatically; download
  `PhishGuard-debug-apk` from the run's Artifacts, copy it to your phone, and install (allow "install unknown apps").
- **Android Studio:** File > Open this folder, then Build > Build APK(s).
- **Command line:** with JDK 17, Android SDK and Gradle 8.7: `gradle assembleDebug`
  (output: `app/build/outputs/apk/debug/app-debug.apk`).

The debug APK is fine for personal use. For Play Store distribution you need a release signing key.

## What is different from the extension
- No page-level signals (password-form checks): a phone app can't see inside other apps' pages.
- History stores only `scheme://host` of each link (never paths or query strings, which can carry tokens), and is capped at 2,000 entries.
- Android cannot watch links inside other apps in the background. "Background" here means notification scanning plus the link handler, which are the supported, permission-based ways to do it.
- Heuristic scores are warning signals, not proof of safety or danger (same caveat as the extension).

## Layout
`app/src/main/java/com/phishguard/app/`: `Analyzer` (scoring), `LinkCheckActivity` (link handler + warning),
`LinkWatchService` (background notification scanning), `MainActivity` (dashboard + setup), `ScanStore`, `BrowserForwarder`, `UrlExtractor`.
`app/src/main/assets/web/`: dashboard and warning UI reused from the extension.
