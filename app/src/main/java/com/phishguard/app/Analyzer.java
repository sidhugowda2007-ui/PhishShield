package com.phishguard.app;

import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Java port of extension/detection/analyzer.js. Same indicators, same points, same thresholds.
 * Pure Java (no Android classes) so it can be unit-tested on a plain JVM.
 */
public final class Analyzer {

    public static final class Indicator {
        public final String id, label;
        public final int points;
        Indicator(String id, String label, int points) { this.id = id; this.label = label; this.points = points; }
    }

    public static final class Verdict {
        public final int score;
        public final String level, host, explanation;
        public final List<Indicator> indicators;
        Verdict(int score, String level, String host, List<Indicator> ind, String explanation) {
            this.score = score; this.level = level; this.host = host; this.indicators = ind; this.explanation = explanation;
        }
    }

    private static final Set<String> SHORTENERS = new HashSet<>(Arrays.asList("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"));
    private static final Pattern SENSITIVE = Pattern.compile("(?:login|log-in|signin|sign-in|verify|account|password|wallet|banking|authenticate)", Pattern.CASE_INSENSITIVE);
    private static final Set<String> REDIRECT_KEYS = new HashSet<>(Arrays.asList("url", "redirect", "redirect_uri", "return", "returnto", "next", "continue", "dest", "destination"));
    private static final Set<String> UNUSUAL_TLDS = new HashSet<>(Arrays.asList("zip", "mov", "click", "top", "work", "gq", "tk", "country", "stream"));
    private static final String[] BRANDS = {"amazon", "apple", "bankofamerica", "binance", "chase", "coinbase", "discord", "facebook", "google", "instagram", "microsoft", "netflix", "paypal", "steam"};
    private static final Pattern IPV4 = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern PRIVATE_V6 = Pattern.compile("^(?:fc|fd|fe[89ab])", Pattern.CASE_INSENSITIVE);
    private static final Pattern ENC_REPEAT = Pattern.compile("%(?:25)+[0-9a-f]{2}", Pattern.CASE_INSENSITIVE);
    private static final Pattern ENC_STRUCT = Pattern.compile("%(?:2f|5c|40|3a)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ESCAPE = Pattern.compile("%[0-9a-f]{2}", Pattern.CASE_INSENSITIVE);

    private Analyzer() {}

    // ---- Minimal WHATWG-style URL parse (just what the heuristics need) ----
    private static final class ParsedUrl {
        String scheme, username = "", password = "", host = "", port = "", path = "", query = "";
        String href;
    }

    private static boolean forbiddenHostChar(char c) {
        return c <= 0x20 || "#%/:<>?@[\\]^|".indexOf(c) >= 0 || c == 0x7f;
    }

    private static String pctEncode(String s, String extra) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (cp > 0x7e || cp <= 0x20 || extra.indexOf(cp) >= 0) {
                for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) sb.append(String.format("%%%02X", b & 0xff));
            } else sb.append((char) cp);
        }
        return sb.toString();
    }

    private static ParsedUrl parse(String input) {
        String s = input.replaceAll("^[\\x00-\\x20]+|[\\x00-\\x20]+$", "").replaceAll("[\\t\\n\\r]", "");
        int colon = s.indexOf(':');
        if (colon <= 0 || !s.substring(0, colon).matches("[A-Za-z][A-Za-z0-9+.\\-]*")) return null;
        ParsedUrl u = new ParsedUrl();
        u.scheme = s.substring(0, colon).toLowerCase(Locale.ROOT);
        String rest = s.substring(colon + 1);
        boolean special = u.scheme.equals("http") || u.scheme.equals("https");
        if (!special) { u.href = s; return u; }
        rest = rest.replace('\\', '/');
        int hash = rest.indexOf('#');
        if (hash >= 0) rest = rest.substring(0, hash);
        rest = rest.replaceAll("^/*", "");
        int end = rest.length();
        for (int i = 0; i < rest.length(); i++) { char c = rest.charAt(i); if (c == '/' || c == '?') { end = i; break; } }
        String authority = rest.substring(0, end), tail = rest.substring(end);
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            String cred = authority.substring(0, at);
            authority = authority.substring(at + 1);
            int c = cred.indexOf(':');
            u.username = c >= 0 ? cred.substring(0, c) : cred;
            u.password = c >= 0 ? cred.substring(c + 1) : "";
        }
        String hostPart = authority;
        int pc = authority.startsWith("[") ? authority.indexOf(':', authority.indexOf(']') + 1) : authority.lastIndexOf(':');
        if (pc >= 0) {
            hostPart = authority.substring(0, pc);
            String port = authority.substring(pc + 1);
            if (!port.isEmpty()) {
                if (!port.matches("\\d{1,5}") || Integer.parseInt(port) > 65535) return null;
                boolean dflt = (u.scheme.equals("http") && port.equals("80")) || (u.scheme.equals("https") && port.equals("443"));
                u.port = dflt ? "" : String.valueOf(Integer.parseInt(port));
            }
        }
        if (hostPart.isEmpty()) return null;
        String host;
        if (hostPart.startsWith("[") && hostPart.endsWith("]")) {
            host = hostPart.toLowerCase(Locale.ROOT);
        } else {
            try { host = java.net.URLDecoder.decode(hostPart.replace("+", "%2B"), "UTF-8"); } catch (Exception e) { return null; }
            host = host.toLowerCase(Locale.ROOT);
            try { host = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT); } catch (Exception e) { return null; }
            for (char c : host.toCharArray()) if (forbiddenHostChar(c)) return null;
            if (host.matches("\\d+") && host.length() <= 10 && Long.parseLong(host) <= 0xFFFFFFFFL) {
                long n = Long.parseLong(host);
                host = ((n >> 24) & 255) + "." + ((n >> 16) & 255) + "." + ((n >> 8) & 255) + "." + (n & 255);
            }
        }
        if (host.isEmpty()) return null;
        u.host = host;
        int q = tail.indexOf('?');
        String path = q >= 0 ? tail.substring(0, q) : tail;
        u.query = q >= 0 ? tail.substring(q + 1) : "";
        u.path = path.isEmpty() ? "/" : pctEncode(path, "\"<>`{}");
        u.query = pctEncode(u.query, "\"<>'");
        String userinfo = u.username.isEmpty() && u.password.isEmpty() ? "" : u.username + (u.password.isEmpty() ? "" : ":" + u.password) + "@";
        u.href = u.scheme + "://" + userinfo + u.host + (u.port.isEmpty() ? "" : ":" + u.port) + u.path + (q >= 0 ? "?" + u.query : "");
        return u;
    }

    private static List<String> queryKeys(String query) {
        List<String> keys = new ArrayList<>();
        if (query.isEmpty()) return keys;
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            String k = pair.contains("=") ? pair.substring(0, pair.indexOf('=')) : pair;
            try { k = java.net.URLDecoder.decode(k, "UTF-8"); } catch (Exception ignored) { }
            keys.add(k);
        }
        return keys;
    }

    // ---- Scoring ----
    private static int editDistance(String left, String right) {
        int[] row = new int[right.length() + 1];
        for (int i = 0; i < row.length; i++) row[i] = i;
        for (int i = 1; i <= left.length(); i++) {
            int diagonal = row[0];
            row[0] = i;
            for (int j = 1; j <= right.length(); j++) {
                int previous = row[j];
                row[j] = Math.min(Math.min(row[j] + 1, row[j - 1] + 1), diagonal + (left.charAt(i - 1) == right.charAt(j - 1) ? 0 : 1));
                diagonal = previous;
            }
        }
        return row[right.length()];
    }

    private static void add(List<Indicator> list, String id, String label, int points) { list.add(new Indicator(id, label, points)); }

    private static Verdict result(String host, List<Indicator> indicators) {
        int score = 0;
        for (Indicator i : indicators) score += i.points;
        score = Math.min(100, score);
        String level = score >= 45 ? "high" : score >= 20 ? "medium" : "low";
        String explanation;
        if (indicators.isEmpty()) explanation = "No listed URL warning indicators were detected. A low score is not a guarantee of safety.";
        else {
            StringBuilder sb = new StringBuilder();
            for (Indicator i : indicators) { if (sb.length() > 0) sb.append("; "); sb.append(i.label).append(" (+").append(i.points).append(")"); }
            explanation = sb.toString();
        }
        return new Verdict(score, level, host, indicators, explanation);
    }

    public static Verdict analyzeUrl(String input) {
        List<Indicator> ind = new ArrayList<>();
        boolean containsUnicode = input != null && input.chars().anyMatch(c -> c > 0x7f);
        ParsedUrl url = input == null ? null : parse(input);
        if (url == null) { add(ind, "malformed", "Malformed URL", 70); return result("Unknown", ind); }
        if (!url.scheme.equals("http") && !url.scheme.equals("https")) {
            return new Verdict(0, "low", url.host, new ArrayList<>(), "Unsupported URL scheme; no HTTP(S) risk assessment was made.");
        }
        String host = url.host;
        String[] labels = Arrays.stream(host.split("\\.")).filter(x -> !x.isEmpty()).toArray(String[]::new);
        String address = host.replaceAll("^\\[|\\]$", "").replaceAll("\\.$", "").toLowerCase(Locale.ROOT);
        String kind; boolean skipDomain = true;
        if (address.equals("localhost") || address.endsWith(".localhost")) kind = "loopback-name";
        else if (IPV4.matcher(address).matches()) {
            String[] p = address.split("\\.");
            int[] o = new int[4];
            for (int i = 0; i < 4; i++) o[i] = Integer.parseInt(p[i]);
            if (Arrays.stream(o).anyMatch(x -> x > 255)) kind = "invalid-ip";
            else if (o[0] == 127) kind = "loopback-ipv4";
            else if (o[0] == 10 || (o[0] == 172 && o[1] >= 16 && o[1] <= 31) || (o[0] == 192 && o[1] == 168)) kind = "private-ipv4";
            else kind = "public-ipv4";
        } else if (address.contains(":")) {
            if (address.equals("::1")) kind = "loopback-ipv6";
            else if (PRIVATE_V6.matcher(address).find()) kind = "private-ipv6";
            else kind = "public-ipv6";
        } else { kind = "domain"; skipDomain = false; }

        if (kind.startsWith("loopback")) add(ind, "loopback-host", "Loopback development address; not treated as a public destination", 0);
        else if (kind.startsWith("private")) add(ind, "private-host", "Private network address; not treated as a public destination", 0);
        else if (kind.startsWith("public")) add(ind, "ip-host", "Public IP destination is less typical and is a contextual warning signal", 10);

        if (host.contains("xn--")) add(ind, "punycode", "Domain contains a punycode label", 18);
        if (!skipDomain && labels.length >= 5) add(ind, "deep-subdomains", "Domain has " + (labels.length - 2) + " subdomain labels", 22);
        else if (!skipDomain && labels.length == 4) add(ind, "many-subdomains", "Domain has multiple subdomain labels", 10);

        if (!skipDomain && labels.length >= 2) {
            String registered = labels[labels.length - 2];
            String domainCore = registered.replaceAll("[-_]", "");
            StringBuilder cc = new StringBuilder();
            for (char c : domainCore.toCharArray()) {
                switch (c) { case '0': cc.append('o'); break; case '1': cc.append('l'); break; case '3': cc.append('e'); break;
                    case '4': cc.append('a'); break; case '5': cc.append('s'); break; case '7': cc.append('t'); break; default: cc.append(c); }
            }
            String confusable = cc.toString();
            for (String b : BRANDS) {
                if (!domainCore.equals(b) && confusable.length() >= b.length() - 1 && confusable.length() <= b.length() + 1 && editDistance(confusable, b) <= 1) {
                    add(ind, "lookalike-brand", "Registered domain closely resembles the " + b + " brand", 28); break;
                }
            }
            for (String b : BRANDS) {
                if (host.contains(b + ".") && !host.endsWith(b + ".com")) { add(ind, "brand-in-wrong-domain", "The " + b + " brand appears outside its official .com domain", 24); break; }
            }
            for (String b : BRANDS) {
                if (Arrays.asList(registered.split("[-_]")).contains(b)) {
                    if (!host.endsWith(b + ".com")) add(ind, "brand-token-domain", "Domain uses the " + b + " brand in a different registered domain", 18);
                    break;
                }
            }
        }
        if (!url.username.isEmpty() || !url.password.isEmpty()) add(ind, "embedded-credentials", "URL embeds credentials before the host", 28);

        String pathQuery = url.path + (url.query.isEmpty() ? "" : "?" + url.query);
        if (SHORTENERS.contains(host)) add(ind, "shortener", "Destination is hidden behind a URL shortener", 12);
        if (SENSITIVE.matcher(pathQuery).find()) add(ind, "sensitive-keyword", "Path or query contains an account-sensitive keyword (weak signal)", 7);
        if (SENSITIVE.matcher(host).find()) add(ind, "sensitive-host-keyword", "Hostname contains an account-sensitive keyword", 8);
        boolean http = url.scheme.equals("http");
        if (http) add(ind, "no-https", "Connection does not use HTTPS (not proof of phishing)", 8);
        boolean sensitiveSignal = SENSITIVE.matcher(pathQuery + host).find();
        if (http && sensitiveSignal) add(ind, "http-sensitive-destination", "Sensitive destination terms combined with an unencrypted connection", 6);
        if (url.href.length() > 180) add(ind, "long-url", "URL is unusually long", 8);
        if (ENC_REPEAT.matcher(url.href).find() || ENC_STRUCT.matcher(url.href).find()) add(ind, "encoded-structure", "URL contains encoded separators or repeated encoding", 16);
        int escapes = 0;
        java.util.regex.Matcher m = ESCAPE.matcher(url.href);
        while (m.find()) escapes++;
        if (escapes >= 6) add(ind, "many-escapes", "URL contains " + escapes + " percent-encoded bytes", 12);
        for (String key : queryKeys(url.query)) {
            if (REDIRECT_KEYS.contains(key.toLowerCase(Locale.ROOT))) { add(ind, "redirect-parameter", "Query contains a redirect-style parameter", 12); break; }
        }
        if (labels.length >= 2 && UNUSUAL_TLDS.contains(labels[labels.length - 1])) add(ind, "unusual-tld", "Domain uses the less common ." + labels[labels.length - 1] + " suffix", 10);
        if (containsUnicode) add(ind, "unicode", "URL contains non-ASCII characters", 10);
        if (host.length() > 35) add(ind, "long-host", "Hostname is unusually long", 8);
        return result(host, ind);
    }
}
