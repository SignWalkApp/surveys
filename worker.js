export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const slug = url.pathname.replace(/^\/+|\/+$/g, '');
    const cors = { 'Access-Control-Allow-Origin': '*',
                   'Access-Control-Allow-Methods': 'GET, HEAD, PUT, OPTIONS',
                   'Access-Control-Allow-Headers': 'Content-Type, X-Publish-Key' };
    const say = (text, status, extra) => new Response(text, { status, headers: { ...cors, ...(extra || {}) } });
    if (req.method === 'OPTIONS') return say(null, 204);
    // the master opens every slug; HMAC-SHA256(master, slug), 16 bytes, base64url, opens that slug only
    const b64u = a => btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const derive = async s => {
      const te = new TextEncoder();
      const k = await crypto.subtle.importKey('raw', te.encode(env.PUBLISH_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      return b64u(new Uint8Array(await crypto.subtle.sign('HMAC', k, te.encode(s))).slice(0, 16));
    };
    const given = req.headers.get('X-Publish-Key') || '';
    const keyOK = async () => !!env.PUBLISH_KEY && (given === env.PUBLISH_KEY || (slug !== '' && given === await derive(slug)));
    // r10c — Send to device: a one-time 6-character code that carries one survey's working link
    // from one device to another. PUT /~pair with {link} and that survey's key → {code}; GET
    // /~pair/<code> → {link} once, within 10 minutes, then it is gone.
    if (slug === '~pair' || slug.startsWith('~pair/')) {
      if (!env.SURVEYS) return say('The publisher has no storage attached.', 500);
      const TTL = 10 * 60 * 1000, ABC = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
      const json = (o, st) => say(JSON.stringify(o), st || 200, { 'Content-Type': 'application/json' });
      if (slug === '~pair' && req.method === 'PUT') {
        let body; try { body = await req.json(); } catch (_) { return say('Bad request.', 400); }
        let lk; try { lk = new URL(String(body.link || '')); } catch (_) { return say('Bad link.', 400); }
        const s2 = lk.pathname.replace(/^\/+|\/+$/g, '');
        if (lk.origin !== url.origin || !/^[a-z0-9][a-z0-9-]{2,63}$/.test(s2) || !/^#k=[\w-]{22}/.test(lk.hash))
          return say('That is not a working link on this publisher.', 400);
        if (!env.PUBLISH_KEY || !(given === env.PUBLISH_KEY || given === await derive(s2))) return say('Wrong publish key.', 401);
        let code = '';
        for (let t = 0; t < 5 && !code; t++) {
          const r = crypto.getRandomValues(new Uint8Array(6)); let c = '';
          r.forEach(b => { c += ABC[b % ABC.length]; });
          if (!(await env.SURVEYS.head('~pair-' + c))) code = c;
        }
        if (!code) return say('Try again.', 503);
        await env.SURVEYS.put('~pair-' + code, JSON.stringify({ link: lk.href, job: String(body.job || '').slice(0, 120) }),
          { httpMetadata: { contentType: 'application/json' } });
        return json({ code: code, minutes: 10 });
      }
      if (req.method === 'GET') {
        const code = slug.slice(6).toUpperCase().replace(/[^A-Z0-9]/g, '');
        const gone = 'That code has expired or was already used. Make a new one: Share → Send to device.';
        if (code.length !== 6) return say('A code is 6 characters.', 400);
        const obj = await env.SURVEYS.get('~pair-' + code);
        if (!obj) return say(gone, 404);
        const txt = await obj.text();                      // read before the delete
        await env.SURVEYS.delete('~pair-' + code);
        if (Date.now() - obj.uploaded.getTime() > TTL) return say(gone, 404);
        return json(JSON.parse(txt));
      }
      return say('Method not allowed.', 405);
    }
    if (slug === '') {                                   // the app's Check talks to the root
      if (req.method === 'PUT') return (await keyOK()) ? say(null, 204) : say('Wrong publish key.', 401);
      return say(JSON.stringify({ publisher: 'SurveyWalk', storage: !!env.SURVEYS, password: !!env.PUBLISH_KEY }),
                 200, { 'Content-Type': 'application/json' });
    }
    if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(slug)) return say('No survey at this address.', 404);
    // the app itself: /start (staff) and /admin (the office) are app.html from this repository,
    // so every push updates them; no survey can take either address
    const APP = slug === 'start' || slug === 'admin';
    if (APP && env.ASSETS && (req.method === 'GET' || req.method === 'HEAD')) {
      const a = await env.ASSETS.fetch(new Request(url.origin + '/app.html'));
      if (a.status === 200) return say(req.method === 'HEAD' ? null : a.body, 200,
        { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Robots-Tag': 'noindex' });
    }
    if (APP && req.method === 'PUT' && env.ASSETS) return say('That address is the app, not a survey.', 409);
    if (req.method === 'PUT') {
      // the staff key, HMAC(master, '~staff'), makes a NEW address only, and is answered with that
      // address's own key; it never overwrites a survey that is already there
      let staff = false;
      if (!(await keyOK())) {
        if (!(env.PUBLISH_KEY && given !== '' && given === await derive('~staff'))) return say('Wrong publish key.', 401);
        if (!env.SURVEYS) return say('The publisher has no storage attached — open the setup screen for what to check.', 500);
        if (await env.SURVEYS.head(slug)) return say('This survey was published from another device, so this one cannot change it. Ask the shop.', 409);
        staff = true;
      }
      if (!env.SURVEYS) return say('The publisher has no storage attached — open the setup screen for what to check.', 500);
      if (Number(req.headers.get('Content-Length') || 0) > 64 * 1024 * 1024) return say('Too big for one survey.', 413);
      try { await env.SURVEYS.put(slug, req.body, { httpMetadata: { contentType: 'text/html; charset=utf-8' } }); }
      catch (e) { return say('Storage refused the survey: ' + e.message + ' — check R2 in Cloudflare.', 507); }
      const out = { url: url.origin + '/' + slug };
      if (staff) out.key = await derive(slug);
      return say(JSON.stringify(out), 200, { 'Content-Type': 'application/json' });
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      const page = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Robots-Tag': 'noindex' };
      if (!env.SURVEYS) return say('No survey at this address.', 404);
      const obj = req.method === 'HEAD' ? await env.SURVEYS.head(slug) : await env.SURVEYS.get(slug);
      if (!obj) return say('No survey at this address.', 404);
      const lm = { ...page, 'Last-Modified': obj.uploaded.toUTCString() };
      if (req.method === 'HEAD') return say(null, 200, lm);
      // r10d — every survey link opens in the NEWEST SurveyWalk. A saved survey carries the app it
      // was saved with; here its data is lifted out and put into today's app (public/app.html),
      // exactly as the app's own buildHTML() does. Anything unexpected → the page as stored.
      const stored = new Uint8Array(await obj.arrayBuffer());
      let out = null;
      try { out = env.ASSETS ? await upgrade(stored, env, url) : null; } catch (_) { out = null; }
      return say(out || stored, 200, lm);
    }
    return say('Method not allowed.', 405);
  }
};

// ---- r10d: put a stored survey's data into the current app -------------------------------------
// Works on BYTES: a survey is megabytes of base64 photos, and decoding that text costs more CPU
// than the free plan allows per request. Every marker searched for is ASCII, and in UTF-8 every
// byte of a multi-byte character is >= 0x80, so byte positions are exact. The survey data is
// never decoded — it is sliced out of the stored bytes and handed to the response as is.
const te = new TextEncoder(), td = new TextDecoder();
const B = s => te.encode(s);
function find(h, pat, from) {                       // pat: Uint8Array, h: Uint8Array
  let i = from || 0; const f = pat[0], n = pat.length;
  for (;;) {
    i = h.indexOf(f, i); if (i < 0 || i + n > h.length) return -1;
    let k = 1; while (k < n && h[i + k] === pat[k]) k++;
    if (k === n) return i; i++;
  }
}
function after(h, key, from) {                      // position of the '{' right after key
  // search for the rare part ('DOC={', 'BRAND={'), then check the 'const '/'let ' before it
  const sp = key.lastIndexOf(' '), pre = B(key.slice(0, sp + 1)), word = B(key.slice(sp + 1) + '{');
  let i = from || 0;
  for (;;) {
    i = find(h, word, i); if (i < 0) return -1;
    let ok = i >= pre.length;
    for (let k = 0; ok && k < pre.length; k++) if (h[i - pre.length + k] !== pre[k]) ok = false;
    if (ok) return i + word.length - 1;
    i++;
  }
}
function braceEnd(h, start) {                       // strings skipped with native indexOf
  let depth = 0, i = start;
  while (i < h.length) {
    const c = h[i];
    if (c === 34) {
      let j = i + 1;
      for (;;) {
        j = h.indexOf(34, j); if (j < 0) return -1;
        let k = j - 1, bs = 0; while (h[k] === 92) { bs++; k--; }
        if (bs % 2 === 0) break; j++;
      }
      i = j + 1; continue;
    }
    if (c === 123) depth++;
    else if (c === 125) { if (--depth === 0) return i + 1; }
    i++;
  }
  return -1;
}
const he = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
// The current app's shell, cut into pieces around its markers — once per app version per isolate.
let SHELLC = null;
async function shellParts(env, url) {
  const a = await env.ASSETS.fetch(new Request(url.origin + '/app.html'));
  if (a.status !== 200) return null;
  const tag = a.headers.get('ETag') || a.headers.get('Last-Modified') || a.headers.get('Content-Length') || '';
  if (SHELLC && tag && SHELLC.tag === tag) { try { a.body && a.body.cancel(); } catch (_) {} return SHELLC; }
  const app = await a.text();
  const OPEN = '<script id="shellsrc" type="text/plain">';
  const s0 = app.indexOf(OPEN); if (s0 < 0) return null;
  const s1 = app.indexOf('</script>', s0 + OPEN.length); if (s1 < 0) return null;
  const raw = app.slice(s0 + OPEN.length, s1);                   // the shell, escaped as stored
  const shell = raw.split('<\\/script').join('</scr' + 'ipt');
  const bits = shell.split(/@@(DATA|BRAND|VIEW|INST|NAME|PUBLINK|SHELL)@@/);   // text, name, text, …
  const need = ['DATA', 'BRAND', 'VIEW', 'INST', 'SHELL'];
  if (!need.every(m => bits.filter((x, i) => i % 2 && x === m).length === 1)) return null;
  SHELLC = { tag: tag, raw: B(raw), parts: bits.map((x, i) => i % 2 ? x : B(x)) };
  return SHELLC;
}
async function upgrade(stored, env, url) {
  const S = await shellParts(env, url); if (!S) return null;
  const d0 = after(stored, 'const DOC='); if (d0 < 0) return null;
  const d1 = braceEnd(stored, d0); if (d1 < 0 || td.decode(stored.subarray(d1, d1 + 7)) !== ', MISS=') return null;
  let b0 = after(stored, 'let BRAND=', d1); if (b0 < 0) b0 = after(stored, 'const BRAND=', d1); if (b0 < 0) return null;
  const b1 = braceEnd(stored, b0); if (b1 < 0) return null;
  const brandRaw = td.decode(stored.subarray(b0, b1)), brand = JSON.parse(brandRaw);
  const fi = find(stored, B('VIEWONLY='), d1);
  const f = fi < 0 ? null : /^VIEWONLY=(true|false), INSTALL=(true|false)/.exec(td.decode(stored.subarray(fi, fi + 40)));
  const view = f ? f[1] : 'false', inst = f ? f[2] : 'false';
  const P = brand.pub || {};
  const link = view === 'true' ? (P.url || '') : inst === 'true' ? (P.iurl || '') : (P.wurl || P.url || '');
  const pub = link ? '<a class="go" href="' + he(link) + '">Open the survey ›</a><p>The link opens on any phone or computer. Nothing to download.</p>'
    : '<p class="ask">This copy has no web link yet. Ask whoever sent it for the survey’s link, or open the file on a computer.</p>';
  const fill = { DATA: stored.subarray(d0, d1), BRAND: B(brandRaw), VIEW: B(view), INST: B(inst),
                 NAME: B(he(brand.job || 'Site Survey')), PUBLINK: B(pub), SHELL: S.raw };
  return new Blob(S.parts.map((x, i) => i % 2 ? fill[x] : x));
}
