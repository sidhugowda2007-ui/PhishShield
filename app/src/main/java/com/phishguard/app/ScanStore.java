package com.phishguard.app;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URI;

/** Local scan history (same record shape as the extension's chrome.storage "scans"). */
public final class ScanStore {
    private static final String PREFS = "phishguard";
    private static final String KEY = "scans";
    private static final int MAX = 2000;
    private static final Object LOCK = new Object();

    private ScanStore() {}

    static SharedPreferences prefs(Context c) { return c.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE); }

    /** Stores only scheme://host (never paths or query strings, which can carry tokens). */
    public static void add(Context c, String url, Analyzer.Verdict v, String source) {
        String stored = url;
        try { URI u = new URI(url); if (u.getScheme() != null && u.getHost() != null) stored = u.getScheme() + "://" + u.getHost(); } catch (Exception ignored) { }
        synchronized (LOCK) {
            try {
                JSONArray old = new JSONArray(prefs(c).getString(KEY, "[]"));
                JSONArray next = new JSONArray();
                JSONObject rec = new JSONObject();
                rec.put("url", stored); rec.put("host", v.host); rec.put("time", System.currentTimeMillis());
                rec.put("score", v.score); rec.put("level", v.level); rec.put("source", source);
                next.put(rec);
                for (int i = 0; i < old.length() && next.length() < MAX; i++) next.put(old.get(i));
                prefs(c).edit().putString(KEY, next.toString()).apply();
            } catch (JSONException ignored) { }
        }
    }

    public static String json(Context c) { synchronized (LOCK) { return prefs(c).getString(KEY, "[]"); } }
    public static void clear(Context c) { synchronized (LOCK) { prefs(c).edit().putString(KEY, "[]").apply(); } }
}
