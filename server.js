import express from 'express';
import dns from 'node:dns/promises';
import net from 'node:net';
import { URL } from 'node:url';

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public', { extensions: ['html'] }));

function isPrivateIp(ip) {
  if (!net.isIP(ip)) return true;
  if (ip === '::1' || ip === '0.0.0.0') return true;
  if (ip.includes(':')) {
    const s = ip.toLowerCase();
    return s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80:') || s === '::';
  }
  const [a,b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

async function validatePublicUrl(input) {
  let url;
  try { url = new URL(input); } catch { throw new Error('Некорректная ссылка'); }
  if (!['http:','https:'].includes(url.protocol)) throw new Error('Разрешены только http/https ссылки');
  if (url.username || url.password) throw new Error('Ссылки с логином/паролем не поддерживаются');
  const hostname = url.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname.endsWith('.local')) throw new Error('Локальные адреса запрещены');
  const resolved = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!resolved.length || resolved.some(x => isPrivateIp(x.address))) throw new Error('Локальные/служебные IP запрещены');
  return url;
}

function textBetween(html, tag) {
  const m = html.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  return m ? m[1].replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().slice(0,300) : '';
}
function meta(html, name) {
  const patterns = [
    new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']*)["'][^>]*>`, 'i'),
    new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+name=["']${name}["'][^>]*>`, 'i')
  ];
  for (const p of patterns) { const m = html.match(p); if (m) return m[1].slice(0,500); }
  return '';
}

async function fetchPreview(startUrl) {
  let current = startUrl;
  for (let i=0; i<4; i++) {
    await validatePublicUrl(current.href);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);
    let res;
    try {
      res = await fetch(current, {
        redirect: 'manual', signal: controller.signal,
        headers: { 'User-Agent': 'SiteGuard/1.0 (+safe metadata checker)', 'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1' }
      });
    } finally { clearTimeout(timer); }
    if ([301,302,303,307,308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) break;
      current = new URL(loc, current);
      continue;
    }
    const ct = res.headers.get('content-type') || '';
    const len = Number(res.headers.get('content-length') || 0);
    const info = { status: res.status, finalUrl: current.href, contentType: ct, contentLength: len || null };
    if (!ct.toLowerCase().includes('text/html')) return { ...info, title:'', description:'' };
    if (len > 1_000_000) return { ...info, title:'', description:'Страница слишком большая для безопасного предпросмотра.' };
    const reader = res.body.getReader();
    let chunks = [], total = 0;
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      total += value.length;
      if (total > 500_000) { await reader.cancel(); break; }
      chunks.push(value);
    }
    const html = new TextDecoder('utf-8', {fatal:false}).decode(Buffer.concat(chunks.map(x=>Buffer.from(x))));
    return { ...info, title: textBetween(html,'title'), description: meta(html,'description') };
  }
  throw new Error('Слишком много перенаправлений');
}

function localHeuristics(url) {
  const h = url.hostname.toLowerCase();
  const href = url.href.toLowerCase();
  const issues = [];
  if (url.protocol !== 'https:') issues.push({level:'warn', text:'Нет HTTPS'});
  if (h.startsWith('xn--') || h.includes('.xn--')) issues.push({level:'warn', text:'Домен использует Punycode — проверьте, не маскируется ли он под известный бренд'});
  if (h.split('.').length > 5) issues.push({level:'warn', text:'Очень много поддоменов'});
  if ((href.match(/%/g)||[]).length > 8) issues.push({level:'warn', text:'Ссылка сильно закодирована'});
  if (/[0-9]{1,3}(\.[0-9]{1,3}){3}/.test(h)) issues.push({level:'warn', text:'Используется IP вместо домена'});
  if (url.username || url.password) issues.push({level:'danger', text:'Ссылка содержит данные авторизации'});
  const suspicious = ['login','verify','wallet','claim','gift','bonus','free','secure-update','account-check'];
  const hits = suspicious.filter(w => href.includes(w));
  if (hits.length >= 2) issues.push({level:'warn', text:'В URL несколько слов, часто встречающихся в фишинговых ссылках'});
  return issues;
}

async function googleSafeBrowsing(url) {
  const key = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!key) return { enabled:false, matches:[] };
  const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
    method:'POST', headers:{'content-type':'application/json'},
    body:JSON.stringify({client:{clientId:'siteguard-checker',clientVersion:'1.0'},threatInfo:{threatTypes:['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],platformTypes:['ANY_PLATFORM'],threatEntryTypes:['URL'],threatEntries:[{url:url.href}]}})
  });
  if (!res.ok) return {enabled:true, error:`Google Safe Browsing: HTTP ${res.status}`, matches:[]};
  const data = await res.json();
  return {enabled:true, matches:data.matches || []};
}

app.post('/api/check', async (req,res) => {
  try {
    const url = await validatePublicUrl(String(req.body?.url || '').trim());
    const [preview, gsb] = await Promise.all([
      fetchPreview(url).catch(e => ({error:e.message})),
      googleSafeBrowsing(url).catch(e => ({enabled:true,error:e.message,matches:[]}))
    ]);
    const issues = localHeuristics(url);
    if (gsb.matches?.length) issues.unshift({level:'danger', text:'Google Safe Browsing пометил адрес как потенциально опасный'});
    const danger = issues.some(x=>x.level==='danger');
    const warn = issues.some(x=>x.level==='warn');
    res.json({
      ok:true,
      url:{href:url.href, protocol:url.protocol, hostname:url.hostname, port:url.port || null, path:url.pathname, query:url.search || null},
      verdict: danger ? 'danger' : warn ? 'caution' : 'no-obvious-signs',
      issues, preview, googleSafeBrowsing:gsb
    });
  } catch (e) { res.status(400).json({ok:false,error:e.message || 'Ошибка проверки'}); }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`SiteGuard: http://localhost:${port}`));
