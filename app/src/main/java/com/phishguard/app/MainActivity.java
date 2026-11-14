package com.phishguard.app;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Intent;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Dashboard (the extension's popup, in a WebView) plus a small setup panel for the Android-specific switches. */
public class MainActivity extends Activity {
    private WebView web;
    private TextView notifStatus, browserStatus;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#F5F7FB"));

        LinearLayout setup = new LinearLayout(this);
        setup.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        setup.setPadding(pad, dp(12), pad, dp(8));
        setup.setBackgroundColor(Color.WHITE);
        notifStatus = row(setup, getString(R.string.setup_notifications), getString(R.string.setup_notifications_btn), v -> startActivity(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)));
        row(setup, getString(R.string.setup_default), getString(R.string.setup_default_btn), v -> {
            try { startActivity(new Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)); }
            catch (Exception e) { startActivity(new Intent(Settings.ACTION_SETTINGS)); }
        });
        browserStatus = row(setup, "", getString(R.string.setup_browser_btn), v -> chooseBrowser());
        root.addView(setup, new LinearLayout.LayoutParams(-1, -2));

        web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#F5F7FB"));
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setAllowFileAccess(false);        // does not affect file:///android_asset
        s.setAllowContentAccess(false);
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView v, android.webkit.WebResourceRequest r) { return true; }
        });
        web.addJavascriptInterface(new Object() {
            @JavascriptInterface public String getScans() { return ScanStore.json(MainActivity.this); }
            @JavascriptInterface public void clearScans() { ScanStore.clear(MainActivity.this); }
        }, "PG");
        root.addView(web, new LinearLayout.LayoutParams(-1, 0, 1f));
        setContentView(root);
        web.loadUrl("file:///android_asset/web/popup.html");
    }

    @Override protected void onResume() {
        super.onResume();
        notifStatus.setText(getString(isListenerEnabled() ? R.string.status_on : R.string.status_off));
        notifStatus.setTextColor(Color.parseColor(isListenerEnabled() ? "#299775" : "#D76350"));
        String pkg = BrowserForwarder.chosenBrowser(this);
        Map<String, String> b = BrowserForwarder.installedBrowsers(this);
        browserStatus.setText(getString(R.string.setup_browser, pkg == null ? getString(R.string.none) : b.get(pkg)));
        web.evaluateJavascript("if(window.refresh)window.refresh()", null);
    }

    private boolean isListenerEnabled() {
        String flat = Settings.Secure.getString(getContentResolver(), "enabled_notification_listeners");
        if (flat == null) return false;
        String mine = new ComponentName(this, LinkWatchService.class).flattenToString();
        for (String part : flat.split(":")) if (part.equals(mine)) return true;
        return false;
    }

    private void chooseBrowser() {
        final Map<String, String> browsers = BrowserForwarder.installedBrowsers(this);
        if (browsers.isEmpty()) { new AlertDialog.Builder(this).setMessage(R.string.no_browser).setPositiveButton(android.R.string.ok, null).show(); return; }
        final List<String> pkgs = new ArrayList<>(browsers.keySet());
        String[] labels = new String[pkgs.size()];
        for (int i = 0; i < labels.length; i++) labels[i] = browsers.get(pkgs.get(i));
        new AlertDialog.Builder(this).setTitle(R.string.choose_browser)
                .setItems(labels, (d, which) -> { BrowserForwarder.setChosenBrowser(this, pkgs.get(which)); onResume(); }).show();
    }

    /** One setup row: a status/description line and a button. Returns the text view so callers can update it. */
    private TextView row(LinearLayout parent, String text, String button, View.OnClickListener click) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setGravity(Gravity.CENTER_VERTICAL);
        TextView t = new TextView(this);
        t.setText(text); t.setTextSize(13); t.setTextColor(Color.parseColor("#17253C"));
        r.addView(t, new LinearLayout.LayoutParams(0, -2, 1f));
        Button b = new Button(this);
        b.setText(button); b.setAllCaps(false); b.setTextSize(12); b.setOnClickListener(click);
        r.addView(b, new LinearLayout.LayoutParams(-2, -2));
        parent.addView(r, new LinearLayout.LayoutParams(-1, -2));
        return t;
    }

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density); }
}
