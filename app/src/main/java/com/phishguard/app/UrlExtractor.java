package com.phishguard.app;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Pulls http(s) links out of free text (notification bodies, shared text). Pure Java. */
public final class UrlExtractor {
    private static final Pattern URL = Pattern.compile("https?://[^\\s<>\"'\\u201c\\u201d\\u2018\\u2019]+", Pattern.CASE_INSENSITIVE);
    private UrlExtractor() {}

    public static List<String> extract(CharSequence text, int max) {
        LinkedHashSet<String> found = new LinkedHashSet<>();
        if (text == null) return new ArrayList<>();
        Matcher m = URL.matcher(text);
        while (m.find() && found.size() < max) {
            String url = m.group();
            // trim trailing punctuation that is almost never part of the link
            while (!url.isEmpty() && ".,;:!?)]}".indexOf(url.charAt(url.length() - 1)) >= 0) url = url.substring(0, url.length() - 1);
            if (url.length() > 8) found.add(url);
        }
        return new ArrayList<>(found);
    }
}
