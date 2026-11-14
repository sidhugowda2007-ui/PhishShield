import com.phishguard.app.Analyzer;
import java.nio.file.*; import java.util.*;
public class Parity { public static void main(String[] a) throws Exception {
  for (String u : Files.readAllLines(Path.of("urls.txt"))) { if (u.isEmpty()) continue;
    Analyzer.Verdict v = Analyzer.analyzeUrl(u);
    StringBuilder ids = new StringBuilder();
    for (Analyzer.Indicator i : v.indicators) { if (ids.length()>0) ids.append(","); ids.append("\"").append(i.id).append("\""); }
    System.out.println("{\"u\":" + js(u) + ",\"score\":" + v.score + ",\"level\":\"" + v.level + "\",\"ids\":[" + ids + "]}");
  } }
  static String js(String s){ return "\"" + s.replace("\\","\\\\").replace("\"","\\\"") + "\""; }
}
