package com.phishguard.app;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Hands a checked link to a real browser (never back to PhishGuard, so it cannot loop). */
public final class BrowserForwarder {
    private static final String PREF_KEY = "browser_pkg";
    private static final List<String> PREFERRED = Arrays.asList("com.android.chrome", "org.mozilla.firefox", "com.brave.browser",
            "com.microsoft.emmx", "com.sec.android.app.sbrowser", "com.opera.browser", "com.duckduckgo.mobile.android");

    private BrowserForwarder() {}

    /** package name -> label, excluding this app. */
    public static Map<String, String> installedBrowsers(Context c) {
        PackageManager pm = c.getPackageManager();
        Intent probe = new Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).addCategory(Intent.CATEGORY_BROWSABLE);
        Map<String, String> out = new LinkedHashMap<>();
        for (ResolveInfo ri : pm.queryIntentActivities(probe, PackageManager.MATCH_ALL)) {
            String pkg = ri.activityInfo.packageName;
            if (pkg.equals(c.getPackageName())) continue;
            out.put(pkg, String.valueOf(ri.loadLabel(pm)));
        }
        return out;
    }

    public static String chosenBrowser(Context c) {
        Map<String, String> browsers = installedBrowsers(c);
        String saved = ScanStore.prefs(c).getString(PREF_KEY, null);
        if (saved != null && browsers.containsKey(saved)) return saved;
        for (String p : PREFERRED) if (browsers.containsKey(p)) return p;
        return browsers.isEmpty() ? null : new ArrayList<>(browsers.keySet()).get(0);
    }

    public static void setChosenBrowser(Context c, String pkg) { ScanStore.prefs(c).edit().putString(PREF_KEY, pkg).apply(); }

    /** @return false if no other browser is installed. */
    public static boolean open(Context c, String url) {
        String pkg = chosenBrowser(c);
        if (pkg == null) return false;
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE).setPackage(pkg).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try { c.startActivity(i); return true; } catch (Exception e) { return false; }
    }
}
