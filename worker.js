export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const slug = url.pathname.replace(/^\/+|\/+$/g, '');
    const cors = { 'Access-Control-Allow-Origin': '*',
                   'Access-Control-Allow-Methods': 'GET, HEAD, PUT, OPTIONS',
                   'Access-Control-Allow-Headers': 'Content-Type, X-Publish-Key' };
    const say = (text, status, extra) => new Response(text, { status, headers: { ...cors, ...(extra || {}) } });
    if (req.method === 'OPTIONS') return say(null, 204);
    const keyOK = req.headers.get('X-Publish-Key') === env.PUBLISH_KEY;
    if (slug === '') {                                   // the app's Check talks to the root
      if (req.method === 'PUT') return say(keyOK ? 'Password accepted.' : 'Wrong publish key.', keyOK ? 204 : 401);
      return say(JSON.stringify({ publisher: 'SurveyWalk', storage: !!env.SURVEYS, password: !!env.PUBLISH_KEY }),
                 200, { 'Content-Type': 'application/json' });
    }
    if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(slug)) return say('No survey at this address.', 404);
    if (req.method === 'PUT') {
      if (!keyOK) return say('Wrong publish key.', 401);
      if (!env.SURVEYS) return say('The publisher has no storage attached — open the setup screen for what to check.', 500);
      if (Number(req.headers.get('Content-Length') || 0) > 64 * 1024 * 1024) return say('Too big for one survey.', 413);
      try { await env.SURVEYS.put(slug, req.body, { httpMetadata: { contentType: 'text/html; charset=utf-8' } }); }
      catch (e) { return say('Storage refused the survey: ' + e.message + ' — check R2 in Cloudflare.', 507); }
      return say(JSON.stringify({ url: url.origin + '/' + slug }), 200, { 'Content-Type': 'application/json' });
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      const page = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Robots-Tag': 'noindex' };
      if (!env.SURVEYS) return say('No survey at this address.', 404);
      if (req.method === 'HEAD') return say(null, (await env.SURVEYS.head(slug)) ? 200 : 404, page);
      const obj = await env.SURVEYS.get(slug);
      if (!obj) return say('No survey at this address.', 404);
      return say(obj.body, 200, page);
    }
    return say('Method not allowed.', 405);
  }
};
