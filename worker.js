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
      return say(req.method === 'HEAD' ? null : obj.body, 200, { ...page, 'Last-Modified': obj.uploaded.toUTCString() });
    }
    return say('Method not allowed.', 405);
  }
};
