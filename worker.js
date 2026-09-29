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
    if (slug === '') {                                   // the app's Check talks to the root
      if (req.method === 'PUT') return (await keyOK()) ? say(null, 204) : say('Wrong publish key.', 401);
      return say(JSON.stringify({ publisher: 'SurveyWalk', storage: !!env.SURVEYS, password: !!env.PUBLISH_KEY }),
                 200, { 'Content-Type': 'application/json' });
    }
    if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(slug)) return say('No survey at this address.', 404);
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
