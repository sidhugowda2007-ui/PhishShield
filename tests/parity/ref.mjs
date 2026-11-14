import { analyzeUrl } from './extension/detection/analyzer.js';
import fs from 'fs';
for (const u of fs.readFileSync('urls.txt','utf8').split('\n').filter(Boolean)) {
  const r = analyzeUrl(u);
  console.log(JSON.stringify({ u, score: r.score, level: r.level, ids: r.indicators.map(i => i.id) }));
}
