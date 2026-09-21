// Boss Moms WordPress relay — a tiny forwarder on Render (off William's box, free).
// WHY: SiteGround's Anti-Bot AI Challenge blocks the Cloudflare Worker's egress IP, so the
// dashboard's page editor could not reach register.solve-now.com from Cloudflare. This relay
// runs on a clean (non-Cloudflare) IP that SiteGround does not challenge, so the Worker calls
// here and we forward the WordPress REST request, returning the response verbatim.
//
// Contract (matches siteFetch() in the dashboard _worker.js):
//   POST /  with header  X-Proxy-Key: <RELAY_KEY>
//   body JSON: { url, method, headers:{}, body_b64 }   (body_b64 = base64 of the request body bytes)
//   -> 200 JSON: { status, body_b64 }                  (body_b64 = base64 of the response body bytes)
//
// Security: every request must carry the shared key, and the target url MUST start with
// ALLOW_ORIGIN, so this can never be abused as an open proxy.
//
// Env (set on the Render service):
//   RELAY_KEY     shared secret the Worker presents (X-Proxy-Key)
//   ALLOW_ORIGIN  the only origin we will forward to, e.g. https://register.solve-now.com
const http = require('http');

const PORT = process.env.PORT || 10000;
const KEY = process.env.RELAY_KEY || '';
const ALLOW = (process.env.ALLOW_ORIGIN || '').replace(/\/+$/, '');

function send(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(obj));
}
// Max request body we accept. The worker sends the WP payload as base64 (video uploads too),
// and base64 inflates the raw bytes ~33%, so this must comfortably clear a real hero video.
// 80 MB request ≈ 58 MB of raw video; safely within Render's 512 MB RAM for one upload at a time.
const MAX_BODY = 80 * 1024 * 1024;
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0; let over = false;
    req.on('data', c => {
      if (over) return;
      size += c.length; chunks.push(c);
      if (size > MAX_BODY) { over = true; reject(new Error('too_large')); req.destroy(); }
    });
    req.on('end', () => { if (!over) resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', () => { if (!over) reject(new Error('read_error')); });
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/health') return send(res, 200, { ok: true, relay: 'bossmoms-wp', allow: ALLOW, keyed: !!KEY });
  if (req.method !== 'POST') return send(res, 405, { error: 'POST only' });
  if (!KEY || req.headers['x-proxy-key'] !== KEY) return send(res, 403, { error: 'bad key' });

  let payload;
  try { payload = JSON.parse(await readBody(req)); }
  catch (e) {
    if (e && e.message === 'too_large') return send(res, 413, { error: 'too_large', detail: 'File is too big to upload. Please use a smaller video.' });
    return send(res, 400, { error: 'bad json' });
  }
  const { url, method = 'GET', headers = {}, body_b64 = null } = payload || {};
  if (!url || (ALLOW && !String(url).startsWith(ALLOW))) return send(res, 400, { error: 'url not allowed' });

  // strip hop-by-hop headers we should not forward
  const fwd = {}; for (const [k, v] of Object.entries(headers)) {
    if (!/^(host|content-length|connection)$/i.test(k)) fwd[k] = v;
  }
  const body = body_b64 != null ? Buffer.from(body_b64, 'base64') : undefined;

  try {
    const r = await fetch(url, { method, headers: fwd, body, redirect: 'manual' });
    const buf = Buffer.from(await r.arrayBuffer());
    // Return response headers too so the box can manage the WP login cookie jar + rest-nonce
    // across relay hops (cookie login, not Basic Auth). set_cookie is the raw Set-Cookie list.
    const hdrs = {}; r.headers.forEach((v, k) => { hdrs[k] = v; });
    const set_cookie = (typeof r.headers.getSetCookie === 'function') ? r.headers.getSetCookie() : [];
    return send(res, 200, { status: r.status, headers: hdrs, set_cookie, body_b64: buf.toString('base64') });
  } catch (e) {
    return send(res, 502, { error: 'fetch failed', detail: String(e && e.message || e) });
  }
});

server.listen(PORT, () => console.log(`bossmoms-wp relay up on :${PORT}, allow=${ALLOW}`));
