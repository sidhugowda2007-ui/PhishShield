package com.phishguard.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Background protection. Once the user grants "Notification access", Android keeps this service alive on its own
 * (no foreground notification needed). It scans link text in incoming notifications (SMS, WhatsApp, email...) and
 * raises a PhishGuard alert for risky ones. All analysis is on-device.
 */
public class LinkWatchService extends NotificationListenerService {
    private static final String CHANNEL = "phishguard_alerts";
    private final Map<String, Long> recent = new HashMap<>();
    private int alertId = 1000;

    @Override public void onListenerDisconnected() {
        // Ask the system to reconnect us if it dropped the binding (some OEMs do this under memory pressure).
        try { NotificationListenerService.requestRebind(new ComponentName(this, LinkWatchService.class)); } catch (Exception ignored) { }
    }

    @Override public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null || getPackageName().equals(sbn.getPackageName())) return;
        Notification n = sbn.getNotification();
        if (n == null || n.extras == null) return;
        if ((n.flags & Notification.FLAG_GROUP_SUMMARY) != 0) return;

        StringBuilder text = new StringBuilder();
        Bundle x = n.extras;
        for (String key : new String[]{Notification.EXTRA_TITLE, Notification.EXTRA_TEXT, Notification.EXTRA_BIG_TEXT, Notification.EXTRA_SUB_TEXT}) {
            CharSequence cs = x.getCharSequence(key);
            if (cs != null) text.append(cs).append('\n');
        }
        CharSequence[] lines = x.getCharSequenceArray(Notification.EXTRA_TEXT_LINES);
        if (lines != null) for (CharSequence l : lines) text.append(l).append('\n');

        List<String> urls = UrlExtractor.extract(text, 5);
        if (urls.isEmpty()) return;
        long now = System.currentTimeMillis();
        for (String url : urls) {
            Long seen = recent.get(url);
            if (seen != null && now - seen < 60_000) continue;     // same link re-posted/updated
            recent.put(url, now);
            if (recent.size() > 200) recent.entrySet().removeIf(e -> now - e.getValue() > 60_000);
            Analyzer.Verdict v = Analyzer.analyzeUrl(url);
            ScanStore.add(this, url, v, "notification");
            if (!"low".equals(v.level)) alert(sbn.getPackageName(), v);
        }
    }

    private void alert(String fromPackage, Analyzer.Verdict v) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, getString(R.string.alert_channel), NotificationManager.IMPORTANCE_HIGH));
        String app = fromPackage;
        try { app = String.valueOf(getPackageManager().getApplicationLabel(getPackageManager().getApplicationInfo(fromPackage, 0))); }
        catch (PackageManager.NameNotFoundException ignored) { }
        String title = ("high".equals(v.level) ? getString(R.string.alert_high) : getString(R.string.alert_medium)) + " · " + app;
        String body = getString(R.string.alert_body, v.host, v.score);
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification.Builder b = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_shield).setContentTitle(title).setContentText(body)
                .setStyle(new Notification.BigTextStyle().bigText(body + "\n" + v.explanation))
                .setContentIntent(open).setAutoCancel(true);
        nm.notify(alertId++, b.build());   // silently dropped if POST_NOTIFICATIONS was not granted
    }
}
