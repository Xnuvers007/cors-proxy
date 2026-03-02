const CONFIG = {
  RATE_LIMIT_MAX: 60, // requests per window
  RATE_LIMIT_WINDOW_SEC: 60, // window duration
  RATE_LIMIT_COOLDOWN_SEC: 120, // cooldown if exceeded (2 min)
  DAILY_BUDGET_PER_IP: 2000, // max requests per IP per day
  GLOBAL_DAILY_CAP: 80000, // global daily cap (all IPs combined) — protects 100K free tier
  MAX_URL_LENGTH: 3076,
  MAX_RESPONSE_SIZE: 500 * 1024 * 1024, // 500 MB (streaming enforced)
  MAX_REQUEST_BODY_SIZE: 500 * 1024 * 1024, // 500 MB max upload
  REQUEST_TIMEOUT_MS: 30000, // 30s
  MAX_REDIRECTS: 5,
  BLOCKED_HOSTS: [
    /^localhost$/i,
    /^127\./,                          // 127.0.0.0/8 loopback
    /^10\./,                           // 10.0.0.0/8 private
    /^172\.(1[6-9]|2\d|3[01])\./,      // 172.16.0.0/12 private
    /^192\.168\./,                     // 192.168.0.0/16 private
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 CGNAT
    /^169\.254\./,                     // 169.254.0.0/16 link-local
    /^192\.0\.0\./,                    // 192.0.0.0/24 IETF protocol
    /^192\.0\.2\./,                    // 192.0.2.0/24 TEST-NET-1
    /^198\.51\.100\./,                 // 198.51.100.0/24 TEST-NET-2
    /^203\.0\.113\./,                  // 203.0.113.0/24 TEST-NET-3
    /^198\.1[89]\./,                   // 198.18.0.0/15 benchmark
    /^24[0-9]\./,                      // 240.0.0.0/4 Class E reserved
    /^255\.255\.255\.255$/,            // broadcast
    /^0\./,                            // 0.0.0.0/8
    /^0+$/,                            // "0" in various forms
    /^::1$/,                           // IPv6 loopback
    /^::$/,                            // IPv6 all-zeros (= 0.0.0.0)
    /^::ffff:/i,                       // ALL IPv4-mapped IPv6 (validated separately)
    /^::(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.)/i, // IPv4-compatible IPv6 with private
    /^fd[0-9a-f]{2}:/i,               // IPv6 ULA fd00::/8
    /^fc[0-9a-f]{2}:/i,               // IPv6 ULA fc00::/8
    /^fe80:/i,                         // IPv6 link-local
    /^metadata\.google\.internal$/i,
    /^metadata\.google$/i,
    /^metadata$/i,
    /^169\.254\.169\.254$/,            // AWS/GCP/Azure metadata (also caught by 169.254.)
    /\.internal$/i,
    /\.local$/i,
    /^kubernetes\.default/i,
    /^.*\.svc\.cluster\.local$/i,
    /^consul\./i,                      // Consul service mesh
    /^vault\./i,                       // HashiCorp Vault
  ],
  BLOCKED_PORTS: [
    22, 23, 25, 53, 110, 143, 445, 587, 993, 995,  // common dangerous
    2379, 2380,                                      // etcd
    3306, 5432, 6379, 11211, 27017,                  // databases
    6443,                                             // Kubernetes API
    9200, 9300,                                       // Elasticsearch
    8500, 8600,                                       // Consul
    8200,                                             // Vault
  ],

  ALLOWED_SCHEMES: ["http:", "https:"],
  ALLOWED_METHODS: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  STRIPPED_REQUEST_HEADERS: [
    "cookie",
    "set-cookie",
    "cf-connecting-ip",
    "x-forwarded-for",
    "x-real-ip",
  ],
  STRIPPED_RESPONSE_HEADERS: ["set-cookie", "set-cookie2"],
};
const rateLimitMap = new Map();
const dailyBudgetMap = new Map();
let globalDailyCounter = { count: 0, dayStart: Date.now() };

function cleanupMaps() {
  const now = Date.now();
  const maxAge =
    (CONFIG.RATE_LIMIT_COOLDOWN_SEC + CONFIG.RATE_LIMIT_WINDOW_SEC) * 1000;
  if (rateLimitMap.size > 10000) {
    for (const [key, val] of rateLimitMap) {
      if (now - val.windowStart > maxAge) rateLimitMap.delete(key);
    }
  }
  if (dailyBudgetMap.size > 50000) {
    for (const [key, val] of dailyBudgetMap) {
      if (now - val.dayStart > 86400000) dailyBudgetMap.delete(key);
    }
  }
}

function getRateLimitInfo(ip) {
  const now = Date.now();
  cleanupMaps();
  let entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > CONFIG.RATE_LIMIT_WINDOW_SEC * 1000) {
    entry = { count: 0, windowStart: now, blocked: false, blockedUntil: 0 };
    rateLimitMap.set(ip, entry);
  }
  return entry;
}

function checkDailyBudget(ip) {
  const now = Date.now();
  let entry = dailyBudgetMap.get(ip);
  if (!entry || now - entry.dayStart > 86400000) {
    entry = { count: 0, dayStart: now };
    dailyBudgetMap.set(ip, entry);
  }
  entry.count++;
  return {
    allowed: entry.count <= CONFIG.DAILY_BUDGET_PER_IP,
    used: entry.count,
    limit: CONFIG.DAILY_BUDGET_PER_IP,
    remaining: Math.max(0, CONFIG.DAILY_BUDGET_PER_IP - entry.count),
  };
}

function checkGlobalDailyCap() {
  const now = Date.now();
  if (now - globalDailyCounter.dayStart > 86400000) {
    globalDailyCounter = { count: 0, dayStart: now };
  }
  globalDailyCounter.count++;
  return {
    allowed: globalDailyCounter.count <= CONFIG.GLOBAL_DAILY_CAP,
    used: globalDailyCounter.count,
    limit: CONFIG.GLOBAL_DAILY_CAP,
    remaining: Math.max(0, CONFIG.GLOBAL_DAILY_CAP - globalDailyCounter.count),
  };
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = getRateLimitInfo(ip);
  if (entry.blocked && now < entry.blockedUntil) {
    const retryAfter = Math.ceil((entry.blockedUntil - now) / 1000);
    return {
      allowed: false,
      retryAfter,
      remaining: 0,
      limit: CONFIG.RATE_LIMIT_MAX,
    };
  }
  if (entry.blocked && now >= entry.blockedUntil) {
    entry.blocked = false;
    entry.count = 0;
    entry.windowStart = now;
  }
  entry.count++;
  if (entry.count > CONFIG.RATE_LIMIT_MAX) {
    entry.blocked = true;
    entry.blockedUntil = now + CONFIG.RATE_LIMIT_COOLDOWN_SEC * 1000;
    return {
      allowed: false,
      retryAfter: CONFIG.RATE_LIMIT_COOLDOWN_SEC,
      remaining: 0,
      limit: CONFIG.RATE_LIMIT_MAX,
    };
  }
  return {
    allowed: true,
    retryAfter: 0,
    remaining: CONFIG.RATE_LIMIT_MAX - entry.count,
    limit: CONFIG.RATE_LIMIT_MAX,
  };
}
function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": CONFIG.ALLOWED_METHODS.join(", "),
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Requested-With, Accept, Origin",
    "Access-Control-Expose-Headers":
      "Content-Length, Content-Type, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Daily-Remaining, X-Request-Count",
    "Access-Control-Max-Age": "86400",
  };
}
function securityHeaders() {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Proxy-By": "Xnuvers007 (github.com/Xnuvers007)",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Resource-Policy": "cross-origin",
    "X-Download-Options": "noopen",
  };
}
function validateUrl(raw) {
  if (!raw)
    return {
      ok: false,
      error: "Parameter 'url' wajib diisi. Contoh: ?url=https://example.com",
    };
  if (raw.length > CONFIG.MAX_URL_LENGTH)
    return {
      ok: false,
      error: `URL terlalu panjang (max ${CONFIG.MAX_URL_LENGTH} karakter)`,
    };

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return {
      ok: false,
      error: "URL tidak valid. Pastikan diawali http:// atau https://",
    };
  }

  if (!CONFIG.ALLOWED_SCHEMES.includes(parsed.protocol)) {
    return {
      ok: false,
      error: `Scheme '${parsed.protocol}' tidak diizinkan. Gunakan http atau https.`,
    };
  }
  if (parsed.username || parsed.password) {
    return {
      ok: false,
      error: "URL dengan credentials (user:pass@) tidak diizinkan.",
    };
  }
  if (parsed.port && CONFIG.BLOCKED_PORTS.includes(parseInt(parsed.port, 10))) {
    return {
      ok: false,
      error: "Port tersebut tidak diizinkan untuk keamanan.",
    };
  }
  const hostname = parsed.hostname.toLowerCase();
  if (/^\d+$/.test(hostname)) {
    return { ok: false, error: "Akses via decimal IP tidak diizinkan." };
  }
  if (/^0\d+\./.test(hostname)) {
    return { ok: false, error: "Akses via octal IP tidak diizinkan." };
  }
  if (/^0x[0-9a-f]+/i.test(hostname)) {
    return { ok: false, error: "Akses via hex IP tidak diizinkan." };
  }
  const ffmpMatch = hostname.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (ffmpMatch) {
    const embeddedIPv4 = ffmpMatch[1];
    for (const pattern of CONFIG.BLOCKED_HOSTS) {
      if (pattern.test(embeddedIPv4)) {
        return { ok: false, error: "Akses ke alamat internal/private (IPv4-mapped IPv6) tidak diizinkan." };
      }
    }
  }
  const compatMatch = hostname.match(/^::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (compatMatch) {
    const embeddedIPv4 = compatMatch[1];
    for (const pattern of CONFIG.BLOCKED_HOSTS) {
      if (pattern.test(embeddedIPv4)) {
        return { ok: false, error: "Akses ke alamat internal/private (IPv4-compatible IPv6) tidak diizinkan." };
      }
    }
  }

  for (const pattern of CONFIG.BLOCKED_HOSTS) {
    if (pattern.test(hostname)) {
      return {
        ok: false,
        error: "Akses ke alamat internal/private tidak diizinkan.",
      };
    }
  }

  return { ok: true, url: parsed };
}
function createSizeLimitedStream(readable, maxBytes) {
  let totalBytes = 0;
  const transform = new TransformStream({
    transform(chunk, controller) {
      totalBytes += chunk.byteLength;
      if (totalBytes > maxBytes) {
        const overshoot = totalBytes - maxBytes;
        const keep = chunk.byteLength - overshoot;
        if (keep > 0) {
          controller.enqueue(chunk.slice(0, keep));
        }
        controller.terminate();
        return;
      }
      controller.enqueue(chunk);
    },
  });
  return readable.pipeThrough(transform);
}
function jsonError(message, status, extra = {}) {
  const body = JSON.stringify(
    { success: false, error: message, status, ...extra },
    null,
    2,
  );
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(),
      ...securityHeaders(),
    },
  });
}
function sanitizeError(err) {
  const msg = err.message || "Unknown error";
  return msg
    .replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, "[REDACTED_IP]")
    .replace(/\/[\w/.-]+/g, "[REDACTED_PATH]")
    .substring(0, 200);
}
function landingPage(requestUrl) {
  const rawOrigin = new URL(requestUrl).origin;
  const baseUrl = rawOrigin.replace(/[<>"'&]/g, (c) => `&#${c.charCodeAt(0)};`);
  return `<!DOCTYPE html>
<html lang="id" prefix="og: https://ogp.me/ns#">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CORS Proxy Gratis - Free, Secure &amp; Fast CORS Proxy API | Xnuvers007</title>
<meta name="description" content="CORS Proxy gratis dan aman. Bypass CORS error untuk fetch/XHR JavaScript. Mendukung semua HTTP method, rate-limited, SSRF protection, dan streaming 500MB. Ditenagai Cloudflare Workers.">
<meta name="keywords" content="cors proxy, free cors proxy, cors bypass, cors anywhere, cors error fix, proxy api, fetch cors, javascript cors, cors proxy online, cloudflare cors proxy, secure cors proxy, bypass cors, access-control-allow-origin, cors header, api proxy gratis, cors proxy indonesia">
<meta name="author" content="Xnuvers007">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1">
<meta name="googlebot" content="index, follow">
<meta name="bingbot" content="index, follow">
<meta name="revisit-after" content="7 days">
<meta name="language" content="Indonesian">
<meta name="rating" content="general">
<meta name="category" content="Technology, Developer Tools">
<meta name="google-site-verification" content="5fXy6ddYnEo0LHvXabZMvqyitQGFS9p6uVlMF-2qzzg" />
<meta name="theme-color" content="#0f0f1a">
<meta name="color-scheme" content="dark">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="CORS Proxy">
<link rel="canonical" href="${rawOrigin}/">
<!-- Open Graph / Facebook / WhatsApp -->
<meta property="og:type" content="website">
<meta property="og:url" content="${rawOrigin}/">
<meta property="og:title" content="CORS Proxy Gratis - Free, Secure &amp; Fast CORS Proxy API">
<meta property="og:description" content="Bypass CORS error secara gratis. Proxy API aman dengan rate-limiting, SSRF protection, dan mendukung semua HTTP methods (GET/POST/PUT/DELETE). Ditenagai Cloudflare Workers.">
<meta property="og:site_name" content="CORS Proxy by Xnuvers007">
<meta property="og:locale" content="id_ID">
<meta property="og:locale:alternate" content="en_US">
<!-- Twitter Card -->
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="CORS Proxy Gratis - Free, Secure &amp; Fast CORS Proxy API">
<meta name="twitter:description" content="Bypass CORS error secara gratis. Proxy API aman dengan rate-limiting, SSRF protection, dan streaming 500MB.">
<meta name="twitter:creator" content="@Xnuvers007">
<meta name="twitter:site" content="@Xnuvers007">
<!-- JSON-LD Structured Data (WebApplication + BreadcrumbList) -->
<script type="application/ld+json">
[
  {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    "name": "CORS Proxy by Xnuvers007",
    "url": "${rawOrigin}/",
    "description": "Free and secure CORS proxy built on Cloudflare Workers. Bypass CORS errors for JavaScript fetch/XHR API requests. Supports GET, POST, PUT, PATCH, DELETE methods with rate-limiting and SSRF protection.",
    "applicationCategory": "DeveloperApplication",
    "applicationSubCategory": "WebProxy",
    "operatingSystem": "Any",
    "browserRequirements": "Requires JavaScript",
    "inLanguage": ["id", "en"],
    "isAccessibleForFree": true,
    "keywords": "cors proxy, free cors proxy, bypass cors, cors anywhere, cors error, api proxy",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    },
    "featureList": "Rate limiting per IP, Daily budget per IP, SSRF protection, Streaming 500MB, Request timeout 30s, Port scan blocking, Redirect validation, Header sanitization, CORS all origins, Cloudflare Workers",
    "author": {
      "@type": "Person",
      "name": "Xnuvers007",
      "url": "https://github.com/Xnuvers007"
    },
    "provider": {
      "@type": "Person",
      "name": "Xnuvers007",
      "url": "https://github.com/Xnuvers007"
    }
  },
  {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    "mainEntity": [
      {
        "@type": "Question",
        "name": "Apa itu CORS Proxy?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "CORS Proxy adalah layanan yang memungkinkan browser mengakses API atau resource dari domain lain yang tidak mengizinkan CORS. Proxy ini menambahkan header Access-Control-Allow-Origin ke setiap response."
        }
      },
      {
        "@type": "Question",
        "name": "Bagaimana cara menggunakan CORS Proxy ini?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Tambahkan URL target sebagai parameter: ${rawOrigin}/?url=https://api.example.com/data. Proxy mendukung semua HTTP method: GET, POST, PUT, PATCH, DELETE."
        }
      },
      {
        "@type": "Question",
        "name": "Apakah CORS Proxy ini gratis?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Ya, sepenuhnya gratis dengan limit 60 request per menit dan 2000 request per hari per IP. Ditenagai Cloudflare Workers."
        }
      },
      {
        "@type": "Question",
        "name": "Apakah CORS Proxy ini aman?",
        "acceptedAnswer": {
          "@type": "Answer",
          "text": "Ya. Proxy ini dilengkapi SSRF protection, port scan blocking, header sanitization, rate limiting, dan validasi redirect. IP internal/private diblokir sepenuhnya."
        }
      }
    ]
  }
]
</script>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data: blob:; media-src blob:; connect-src 'self'; base-uri 'none'; form-action 'none';">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  :root{
    --bg:#0a0a14;--surface:rgba(26,26,46,.85);--surface2:#16213e;--primary:#00d2ff;
    --primary2:#7b2ff7;--primary3:#a855f7;--accent:#ff6b6b;--text:#f0f0f5;--text2:#8892b0;
    --green:#00e676;--border:rgba(255,255,255,.08);--glow:0 0 30px rgba(0,210,255,.12);
    --radius:16px;--card-blur:blur(12px);
  }
  html{scroll-behavior:smooth;-webkit-text-size-adjust:100%;text-size-adjust:100%}
  body{font-family:'Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,'Helvetica Neue',Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;overflow-x:hidden;line-height:1.6;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;position:relative}
  body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% -20%,rgba(0,210,255,.08),transparent 70%),radial-gradient(ellipse 60% 50% at 80% 110%,rgba(123,47,247,.06),transparent 60%);pointer-events:none;z-index:0}
  .wrapper{width:100%;max-width:820px;padding:2.5rem 1.5rem;position:relative;z-index:1}
  .header{text-align:center;margin-bottom:2.5rem;animation:fadeInDown .6s ease-out}
  .logo{font-size:3.5rem;margin-bottom:.6rem;filter:drop-shadow(0 0 20px rgba(0,210,255,.5));animation:float 3s ease-in-out infinite}
  .header h1{font-size:clamp(1.4rem,5vw,2rem);background:linear-gradient(135deg,var(--primary),var(--primary2),var(--primary3));background-size:200% 200%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem;font-weight:800;letter-spacing:-.5px;animation:gradientMove 4s ease infinite}
  .header p{color:var(--text2);font-size:clamp(.82rem,2.5vw,.95rem);line-height:1.7;max-width:600px;margin:0 auto}
  .header p a{color:var(--primary);text-decoration:none;font-weight:600;transition:opacity .2s}
  .header p a:hover{opacity:.8}
  .card{background:var(--surface);backdrop-filter:var(--card-blur);-webkit-backdrop-filter:var(--card-blur);border:1px solid var(--border);border-radius:var(--radius);padding:clamp(1.2rem,4vw,2rem);margin-bottom:1.2rem;box-shadow:var(--glow);transition:box-shadow .3s,transform .3s,border-color .3s;position:relative;overflow:hidden}
  .card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(0,210,255,.3),transparent);opacity:0;transition:opacity .3s}
  .card:hover{box-shadow:0 8px 40px rgba(0,210,255,.18),0 0 0 1px rgba(0,210,255,.1);transform:translateY(-2px)}
  .card:hover::before{opacity:1}
  .card h2{font-size:clamp(1rem,3vw,1.15rem);color:var(--primary);margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;font-weight:700}
  .card h2 span{font-size:1.2rem}
  .try-form{display:flex;gap:.6rem;margin-bottom:1rem}
  .try-form input{flex:1;padding:.8rem 1rem;border-radius:12px;border:1px solid var(--border);background:rgba(10,10,20,.6);color:var(--text);font-size:clamp(.85rem,2.5vw,.95rem);outline:none;transition:border-color .2s,box-shadow .2s;min-width:0}
  .try-form input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(0,210,255,.15)}
  .try-form input::placeholder{color:var(--text2)}
  .try-form button{padding:.8rem 1.6rem;border-radius:12px;border:none;background:linear-gradient(135deg,var(--primary),var(--primary2));color:#fff;font-weight:700;cursor:pointer;font-size:clamp(.85rem,2.5vw,.95rem);white-space:nowrap;transition:transform .15s,box-shadow .2s;position:relative;overflow:hidden}
  .try-form button::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent,rgba(255,255,255,.1),transparent);opacity:0;transition:opacity .2s}
  .try-form button:hover{transform:translateY(-2px);box-shadow:0 6px 24px rgba(0,210,255,.35)}
  .try-form button:hover::after{opacity:1}
  .try-form button:active{transform:scale(.97)}
  .try-form button:disabled{opacity:.6;cursor:not-allowed;transform:none}
  .result{background:rgba(10,10,20,.6);border:1px solid var(--border);border-radius:12px;padding:1rem;font-size:clamp(.75rem,2vw,.85rem);color:var(--text2);min-height:60px;max-height:50vh;overflow:auto;white-space:pre-wrap;word-break:break-all;display:none;scrollbar-width:thin;scrollbar-color:var(--primary2) transparent}
  .result::-webkit-scrollbar{width:6px}
  .result::-webkit-scrollbar-track{background:transparent}
  .result::-webkit-scrollbar-thumb{background:var(--primary2);border-radius:3px}
  .result.show{display:block;animation:fadeIn .3s ease}
  .result.error{border-color:var(--accent);color:var(--accent)}
  .result.success{border-color:var(--green);color:var(--green)}
  .result img{max-width:100%;max-height:350px;border-radius:8px;margin-top:.5rem;display:block}
  .result video{max-width:100%;max-height:350px;border-radius:8px;margin-top:.5rem;display:block}
  .result audio{width:100%;margin-top:.5rem}
  pre{background:rgba(10,10,20,.6);border:1px solid var(--border);border-radius:12px;padding:1rem;padding-right:4rem;overflow-x:auto;font-size:clamp(.75rem,2vw,.85rem);line-height:1.7;color:var(--text2);position:relative;scrollbar-width:thin;scrollbar-color:var(--primary2) transparent}
  pre::-webkit-scrollbar{height:4px}
  pre::-webkit-scrollbar-thumb{background:var(--primary2);border-radius:2px}
  pre code{font-family:'Cascadia Code','Fira Code','JetBrains Mono','SF Mono',Consolas,monospace;font-size:inherit}
  .copy-btn{position:absolute;top:.6rem;right:.6rem;padding:.35rem .8rem;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text2);font-size:.72rem;cursor:pointer;transition:all .2s;backdrop-filter:blur(8px);z-index:1}
  .copy-btn:hover{background:var(--primary);color:#fff;border-color:var(--primary);transform:scale(1.05)}
  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:clamp(.5rem,2vw,.8rem);margin-bottom:1.5rem}
  .stat{background:var(--surface);backdrop-filter:var(--card-blur);-webkit-backdrop-filter:var(--card-blur);border:1px solid var(--border);border-radius:14px;padding:clamp(.8rem,3vw,1.2rem);text-align:center;transition:transform .2s,box-shadow .2s}
  .stat:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(0,210,255,.12)}
  .stat .num{font-size:clamp(1rem,3.5vw,1.4rem);font-weight:800;background:linear-gradient(135deg,var(--primary),var(--primary2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;line-height:1.2}
  .stat .label{font-size:clamp(.6rem,1.8vw,.75rem);color:var(--text2);margin-top:.25rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .features{display:grid;grid-template-columns:1fr 1fr;gap:.6rem}
  .feat{display:flex;align-items:center;gap:.5rem;font-size:clamp(.78rem,2.2vw,.88rem);color:var(--text2);padding:.6rem .8rem;border-radius:10px;background:rgba(0,210,255,.04);border:1px solid transparent;transition:all .2s}
  .feat:hover{background:rgba(0,210,255,.08);border-color:rgba(0,210,255,.15);transform:translateX(4px)}
  .feat span:first-child{font-size:1.1rem;flex-shrink:0}
  details{color:var(--text2);font-size:clamp(.82rem,2.2vw,.9rem);border:1px solid var(--border);border-radius:10px;padding:.8rem 1rem;transition:all .2s;background:rgba(0,210,255,.02)}
  details:hover{border-color:rgba(0,210,255,.2);background:rgba(0,210,255,.04)}
  details[open]{background:rgba(0,210,255,.05)}
  details summary{cursor:pointer;color:var(--text);font-weight:600;padding:.1rem 0;user-select:none;-webkit-user-select:none;list-style:none}
  details summary::-webkit-details-marker{display:none}
  details summary::before{content:'\u25B6';display:inline-block;margin-right:.5rem;font-size:.7rem;transition:transform .2s;color:var(--primary)}
  details[open] summary::before{transform:rotate(90deg)}
  details p{margin-top:.6rem;line-height:1.7}
  details code{background:rgba(0,210,255,.1);padding:.15rem .4rem;border-radius:4px;font-size:.82em;color:var(--primary)}
  .faq-list{display:flex;flex-direction:column;gap:.7rem}
  .footer{text-align:center;color:var(--text2);font-size:clamp(.68rem,2vw,.78rem);margin-top:2rem;padding:1.5rem 0;opacity:.7;line-height:1.8}
  .footer a{color:var(--primary);text-decoration:none;font-weight:600;transition:opacity .2s}
  .footer a:hover{opacity:.7}
  @keyframes fadeInDown{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
  @keyframes fadeIn{from{opacity:0}to{opacity:1}}
  @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
  @keyframes gradientMove{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
  .card{animation:fadeIn .5s ease-out both}
  .card:nth-child(1){animation-delay:.1s}
  .card:nth-child(2){animation-delay:.15s}
  .card:nth-child(3){animation-delay:.2s}
  .card:nth-child(4){animation-delay:.25s}
  .card:nth-child(5){animation-delay:.3s}
  .card:nth-child(6){animation-delay:.35s}
  .spinner{display:inline-block;width:16px;height:16px;border:2px solid var(--border);border-top-color:var(--primary);border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}
  /* === RESPONSIVE: Extra small (< 360px) — small phones === */
  @media(max-width:359px){
    .wrapper{padding:1rem .8rem}
    .stats{grid-template-columns:repeat(2,1fr);gap:.4rem}
    .features{grid-template-columns:1fr}
    .try-form{flex-direction:column}
    .try-form button{width:100%}
    .header h1{font-size:1.2rem}
    .logo{font-size:2.5rem}
    .card{padding:1rem;border-radius:12px;margin-bottom:1rem}
    pre{padding:.7rem;padding-right:3.5rem}
    .stat{padding:.7rem .4rem}
  }
  /* === RESPONSIVE: Small phones (360-480px) === */
  @media(min-width:360px) and (max-width:480px){
    .wrapper{padding:1.2rem 1rem}
    .stats{grid-template-columns:repeat(2,1fr);gap:.5rem}
    .features{grid-template-columns:1fr}
    .try-form{flex-direction:column}
    .try-form button{width:100%}
    .card{padding:1.2rem;margin-bottom:1rem}
  }
  /* === RESPONSIVE: Large phones (481-600px) === */
  @media(min-width:481px) and (max-width:600px){
    .wrapper{padding:1.5rem 1.2rem}
    .stats{grid-template-columns:repeat(2,1fr)}
    .try-form{flex-direction:column}
    .try-form button{width:100%}
    .features{grid-template-columns:1fr}
  }
  /* === RESPONSIVE: Small tablets (601-768px) === */
  @media(min-width:601px) and (max-width:768px){
    .wrapper{padding:2rem 1.5rem}
    .stats{grid-template-columns:repeat(4,1fr)}
    .features{grid-template-columns:1fr 1fr}
  }
  /* === RESPONSIVE: Tablets & small laptops (769-1024px) === */
  @media(min-width:769px) and (max-width:1024px){
    .wrapper{max-width:860px;padding:2.5rem 2rem}
  }
  /* === RESPONSIVE: Desktops (1025-1440px) === */
  @media(min-width:1025px) and (max-width:1440px){
    .wrapper{max-width:880px}
  }
  /* === RESPONSIVE: Large/Ultra-wide (1441px+) === */
  @media(min-width:1441px){
    .wrapper{max-width:920px;padding:3rem 2rem}
    .card{padding:2.2rem}
    .header{margin-bottom:3rem}
  }
  /* === Touch device optimizations === */
  @media(hover:none) and (pointer:coarse){
    .try-form input,.try-form button{padding:.9rem 1rem;font-size:1rem}
    .try-form button{min-height:48px}
    .copy-btn{padding:.45rem 1rem;font-size:.8rem;min-height:36px}
    .feat{padding:.7rem .8rem;min-height:44px}
    details summary{padding:.3rem 0;min-height:44px;display:flex;align-items:center}
    .card:hover{transform:none}
    .stat:hover{transform:none}
    .feat:hover{transform:none}
  }
  /* === Landscape phones === */
  @media(max-height:500px) and (orientation:landscape){
    body{align-items:flex-start}
    .wrapper{padding:1rem 2rem}
    .header{margin-bottom:1.5rem}
    .result{max-height:35vh}
  }
  /* === Reduce motion === */
  @media(prefers-reduced-motion:reduce){
    *{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}
  }
  /* === High contrast === */
  @media(prefers-contrast:high){
    :root{--border:rgba(255,255,255,.2);--text:#fff;--text2:#c0c0c0}
    .card{border-width:2px}
  }
  /* === Print === */
  @media print{
    body{background:#fff;color:#000}
    body::before{display:none}
    .card{box-shadow:none;border:1px solid #ccc;background:#fff}
    .try-form button,.copy-btn{display:none}
  }
</style>
</head>
<body>
<div class="wrapper">
  <header class="header">
    <div class="logo" role="img" aria-label="Shield">🛡️</div>
    <h1>CORS Proxy Gratis — Secure &amp; Fast</h1>
    <p>Bypass CORS Error • Rate-Limited • 500MB Streaming • SSRF Protected — Gratis, ditenagai <strong>Cloudflare Workers</strong> oleh <a href="https://github.com/Xnuvers007" target="_blank" rel="noopener noreferrer" style="color:var(--primary);text-decoration:none">Xnuvers007</a></p>
  </header>
  <div class="stats">
    <div class="stat"><div class="num">${CONFIG.RATE_LIMIT_MAX}</div><div class="label">Req / Menit</div></div>
    <div class="stat"><div class="num">${CONFIG.RATE_LIMIT_COOLDOWN_SEC}s</div><div class="label">Cooldown</div></div>
    <div class="stat"><div class="num">${CONFIG.MAX_RESPONSE_SIZE / 1024 / 1024}MB</div><div class="label">Max Response</div></div>
    <div class="stat"><div class="num">${CONFIG.DAILY_BUDGET_PER_IP}</div><div class="label">Daily / IP</div></div>
  </div>
  <div class="card">
    <h2><span>�</span> Visitor Stats</h2>
    <div id="visitorStats" class="stats" style="margin-bottom:0">
      <div class="stat"><div class="num">-</div><div class="label">Loading...</div></div>
      <div class="stat"><div class="num">-</div><div class="label">Loading...</div></div>
      <div class="stat"><div class="num">-</div><div class="label">Loading...</div></div>
      <div class="stat"><div class="num">-</div><div class="label">Loading...</div></div>
    </div>
  </div>
  <div class="card">
    <h2><span>�🚀</span> Coba Sekarang</h2>
    <div class="try-form">
      <input id="urlInput" type="url" placeholder="https://api.example.com/data" />
      <button id="fetchBtn">Fetch</button>
    </div>
    <div id="result" class="result"></div>
  </div>
  <div class="card">
    <h2><span>📖</span> Cara Pakai</h2>
    <pre><code>// GET request
fetch("${baseUrl}/?url=https://api.example.com/data")
  .then(r =&gt; r.json())
  .then(data =&gt; console.log(data));</code><button class="copy-btn" onclick="copyCode(this)">Copy</button></pre>
    <br>
    <pre><code>// POST request
fetch("${baseUrl}/?url=https://api.example.com/submit", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "test" })
});</code><button class="copy-btn" onclick="copyCode(this)">Copy</button></pre>
  </div>
  <div class="card">
    <h2><span>🔗</span> Endpoint</h2>
    <pre><code>${baseUrl}/?url={TARGET_URL}</code><button class="copy-btn" onclick="copyCode(this)">Copy</button></pre>
  </div>
  <section class="card" aria-label="Fitur Keamanan">
    <h2><span>✨</span> Fitur Keamanan</h2>
    <div class="features">
      <div class="feat"><span>🛡️</span> Rate-limit per IP</div>
      <div class="feat"><span>📅</span> Daily budget per IP</div>
      <div class="feat"><span>🔒</span> SSRF protection</div>
      <div class="feat"><span>📏</span> Streaming 500MB</div>
      <div class="feat"><span>⏱️</span> Request timeout 30s</div>
      <div class="feat"><span>🚫</span> Port scan blocking</div>
      <div class="feat"><span>🔗</span> Redirect validation</div>
      <div class="feat"><span>🧹</span> Header sanitization</div>
      <div class="feat"><span>🌐</span> CORS all origins</div>
      <div class="feat"><span>🔄</span> Cooldown otomatis</div>
    </div>
  </section>
  <section class="card" aria-label="FAQ">
    <h2><span>❓</span> FAQ — Pertanyaan Umum</h2>
    <div class="faq-list">
      <details>
        <summary>Apa itu CORS Proxy?</summary>
        <p>CORS Proxy adalah layanan yang memungkinkan browser mengakses API dari domain lain yang tidak mengizinkan CORS. Proxy menambahkan header <code>Access-Control-Allow-Origin: *</code> ke setiap response.</p>
      </details>
      <details>
        <summary>Bagaimana cara menggunakannya?</summary>
        <p>Tambahkan URL target sebagai parameter: <code>${baseUrl}/?url=https://api.example.com</code>. Mendukung semua HTTP method: GET, POST, PUT, PATCH, DELETE.</p>
      </details>
      <details>
        <summary>Apakah gratis?</summary>
        <p>Ya, sepenuhnya gratis. Limit: 60 request/menit dan 2000 request/hari per IP. Ditenagai Cloudflare Workers.</p>
      </details>
      <details>
        <summary>Apakah aman digunakan?</summary>
        <p>Ya. Dilengkapi SSRF protection, port scan blocking, header sanitization, rate limiting, validasi redirect, dan blokir IP internal/private sepenuhnya.</p>
      </details>
    </div>
  </section>
  <footer class="footer" itemscope itemtype="https://schema.org/WPFooter">
    <p>CORS Proxy &bull; Free CORS Proxy API &bull; Bypass CORS Error &bull; CORS Anywhere Alternative</p>
    <p>Cloudflare Workers &bull; Hardened Security &bull; Open Source</p>
    <p style="margin-top:.4rem">Created by <a href="https://github.com/Xnuvers007" target="_blank" rel="noopener noreferrer" style="color:var(--primary);text-decoration:none" itemprop="author">Xnuvers007</a></p>
  </footer>
</div>
<script>
document.getElementById('fetchBtn').addEventListener('click', doFetch);
document.getElementById('urlInput').addEventListener('keydown',function(e){if(e.key==='Enter')doFetch()});
var IMAGE_TYPES=['image/png','image/jpeg','image/jpg','image/gif','image/webp','image/svg+xml','image/bmp','image/x-icon','image/avif'];
var VIDEO_TYPES=['video/mp4','video/webm','video/ogg'];
var AUDIO_TYPES=['audio/mpeg','audio/ogg','audio/wav','audio/webm','audio/aac','audio/flac'];
function getMimeBase(ct){return (ct||'').split(';')[0].trim().toLowerCase()}
async function doFetch(){
  var input=document.getElementById('urlInput');
  var result=document.getElementById('result');
  var btn=document.getElementById('fetchBtn');
  var url=input.value.trim();
  if(!url){input.focus();return}
  result.className='result show';result.innerHTML='';result.textContent='Fetching...';
  btn.disabled=true;btn.textContent='Loading...';
  try{
    var start=performance.now();
    var r=await fetch(location.origin+'/?url='+encodeURIComponent(url));
    var elapsed=Math.round(performance.now()-start);
    var limit=r.headers.get('X-RateLimit-Limit')||'-';
    var remaining=r.headers.get('X-RateLimit-Remaining')||'-';
    var daily=r.headers.get('X-Daily-Remaining')||'-';
    var ct=r.headers.get('content-type')||'';
    var mime=getMimeBase(ct);
    var reqCount=r.headers.get('X-Request-Count')||'-';
    var info='HTTP '+r.status+' | '+elapsed+'ms | Rate: '+remaining+'/'+limit+' | Daily: '+daily+' | Total: '+reqCount;
    result.className='result show '+(r.ok?'success':'error');
    if(IMAGE_TYPES.indexOf(mime)!==-1||mime.startsWith('image/')){
      var blob=await r.blob();
      var blobUrl=URL.createObjectURL(blob);
      result.innerHTML=esc(info)+'\\n\\n<img src="'+blobUrl+'" alt="Preview" onload="this.style.opacity=1" style="opacity:0;transition:opacity .3s" />';
    }
    else if(VIDEO_TYPES.indexOf(mime)!==-1||mime.startsWith('video/')){
      var blob=await r.blob();
      var blobUrl=URL.createObjectURL(blob);
      result.innerHTML=esc(info)+'\\n\\n<video controls src="'+blobUrl+'"></video>';
    }
    else if(AUDIO_TYPES.indexOf(mime)!==-1||mime.startsWith('audio/')){
      var blob=await r.blob();
      var blobUrl=URL.createObjectURL(blob);
      result.innerHTML=esc(info)+'\\n\\n<audio controls src="'+blobUrl+'"></audio>';
    }
    else if(ct.includes('json')){
      var body;
      try{body=JSON.stringify(await r.json(),null,2)}catch(e){body=await r.text()}
      result.textContent=info+'\\n\\n'+body;
    }
    else if(mime==='application/pdf'){
      var blob=await r.blob();
      var blobUrl=URL.createObjectURL(blob);
      result.innerHTML=esc(info)+'\\n\\n📄 <a href="'+blobUrl+'" target="_blank" style="color:var(--primary)">Open PDF</a>';
    }
    else{
      var body=await r.text();
      if(body.length>102400)body=body.substring(0,102400)+'\\n\\n... (truncated at 100KB)';
      result.textContent=info+'\\n\\n'+body;
    }
  }catch(e){
    result.className='result show error';result.textContent='Network error: '+e.message;
  }finally{btn.disabled=false;btn.textContent='Fetch'}
}
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
(function(){fetch(location.origin+'/rate-limit').then(function(r){return r.json()}).then(function(d){var el=document.getElementById('visitorStats');if(!el)return;el.innerHTML='<div class="stat"><div class="num">'+esc(d.ip||'-')+'</div><div class="label">Your IP</div></div>'+'<div class="stat"><div class="num">'+(d.dailyBudget?d.dailyBudget.used:0)+'</div><div class="label">Requests Today</div></div>'+'<div class="stat"><div class="num">'+(d.dailyBudget?d.dailyBudget.remaining:'-')+'</div><div class="label">Daily Remaining</div></div>'+'<div class="stat"><div class="num">'+(d.rateLimit&&d.rateLimit.blocked?'\u26d4 Blocked':'\u2705 Active')+'</div><div class="label">Status</div></div>';}).catch(function(){});})();
function copyCode(btn){
  var code=btn.parentElement.querySelector('code').textContent;
  navigator.clipboard.writeText(code).then(function(){btn.textContent='Copied!';setTimeout(function(){btn.textContent='Copy'},1500)});
}
</script>
</body></html>`;
}
export default {
  async fetch(request) {
    try {
    const url = new URL(request.url);
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    if (url.pathname === "/favicon.ico") {
      return new Response(null, { status: 204 });
    }

    if (url.pathname === "/health") {
      if (!["GET", "HEAD"].includes(request.method)) {
        return jsonError("Method not allowed.", 405);
      }
      return new Response(
        JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }),
        {
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders(),
            ...securityHeaders(),
          },
        },
      );
    }

    if (url.pathname === '/sitemap.xml') {
      return new Response(generateSitemap(), {
        headers: {
          'Content-Type': 'application/xml',
        },
      });
    }

    if (url.pathname === "/rate-limit") {
      if (!["GET", "HEAD"].includes(request.method)) {
        return jsonError("Method not allowed.", 405);
      }
      const entry = rateLimitMap.get(clientIP);
      const dailyEntry = dailyBudgetMap.get(clientIP);
      return new Response(
        JSON.stringify(
          {
            ip: clientIP.length > 6 ? clientIP.substring(0, 6) + "***" : "***",
            rateLimit: {
              limit: CONFIG.RATE_LIMIT_MAX,
              remaining: entry
                ? Math.max(0, CONFIG.RATE_LIMIT_MAX - entry.count)
                : CONFIG.RATE_LIMIT_MAX,
              blocked: entry ? entry.blocked : false,
            },
            dailyBudget: {
              limit: CONFIG.DAILY_BUDGET_PER_IP,
              used: dailyEntry ? dailyEntry.count : 0,
              remaining: dailyEntry
                ? Math.max(0, CONFIG.DAILY_BUDGET_PER_IP - dailyEntry.count)
                : CONFIG.DAILY_BUDGET_PER_IP,
            },
          },
          null,
          2,
        ),
        {
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders(),
            ...securityHeaders(),
          },
        },
      );
    }
    if (url.pathname !== "/") {
      return jsonError("Endpoint tidak ditemukan. Gunakan /?url=https://...", 404);
    }

    const targetRaw = url.searchParams.get("url");
    if (!targetRaw) {
      return new Response(landingPage(request.url), {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "public, max-age=3600",
          "X-Frame-Options": "DENY",
          "X-Content-Type-Options": "nosniff",
          "Referrer-Policy": "no-referrer",
        },
      });
    }
    if (request.method === "OPTIONS") {
      const reqHeaders = (request.headers.get("Access-Control-Request-Headers") || "").substring(0, 500);
      return new Response(null, {
        status: 204,
        headers: {
          ...corsHeaders(),
          ...securityHeaders(),
          "Access-Control-Allow-Headers":
            reqHeaders || "Content-Type, Authorization, X-Requested-With, Accept, Origin",
        },
      });
    }
    if (!CONFIG.ALLOWED_METHODS.includes(request.method)) {
      return jsonError(`Method '${request.method}' tidak diizinkan.`, 405);
    }
    const rateLimit = checkRateLimit(clientIP);
    if (!rateLimit.allowed) {
      const retryHeaders = {
        ...corsHeaders(),
        ...securityHeaders(),
        "Content-Type": "application/json; charset=utf-8",
        "Retry-After": String(rateLimit.retryAfter),
        "X-RateLimit-Limit": String(rateLimit.limit),
        "X-RateLimit-Remaining": "0",
      };
      return new Response(
        JSON.stringify({
          success: false,
          error: `Rate limit tercapai. Coba lagi dalam ${rateLimit.retryAfter} detik.`,
          status: 429,
          retryAfter: rateLimit.retryAfter,
        }, null, 2),
        { status: 429, headers: retryHeaders },
      );
    }
    const dailyBudget = checkDailyBudget(clientIP);
    if (!dailyBudget.allowed) {
      const retryHeaders = {
        ...corsHeaders(),
        ...securityHeaders(),
        "Content-Type": "application/json; charset=utf-8",
        "Retry-After": "3600",
      };
      return new Response(
        JSON.stringify({
          success: false,
          error: `Budget harian tercapai (${CONFIG.DAILY_BUDGET_PER_IP} request/hari). Coba lagi besok.`,
          status: 429,
          dailyUsed: dailyBudget.used,
          dailyLimit: dailyBudget.limit,
        }, null, 2),
        { status: 429, headers: retryHeaders },
      );
    }
    const globalCap = checkGlobalDailyCap();
    if (!globalCap.allowed) {
      return jsonError(
        "Service mencapai batas harian global. Coba lagi besok.",
        503,
        { globalUsed: globalCap.used, globalLimit: globalCap.limit },
      );
    }
    const validation = validateUrl(targetRaw);
    if (!validation.ok) {
      return jsonError(validation.error, 400);
    }
    const selfHost = url.hostname.toLowerCase();
    if (validation.url.hostname.toLowerCase() === selfHost) {
      return jsonError(
        "Tidak bisa proxy ke diri sendiri (loop prevention).",
        403,
      );
    }
    if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method) && request.headers.get("Content-Length")) {
      const reqContentLength = parseInt(
        request.headers.get("Content-Length") || "0",
        10,
      );
      if (reqContentLength > CONFIG.MAX_REQUEST_BODY_SIZE) {
        return jsonError(
          `Request body terlalu besar (${Math.round(reqContentLength / 1024 / 1024)}MB). Max: ${CONFIG.MAX_REQUEST_BODY_SIZE / 1024 / 1024}MB.`,
          413,
        );
      }
    }
    try {
      const proxyHeaders = new Headers();
      const forwardHeaders = [
        "Content-Type",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
      ];
      for (const h of forwardHeaders) {
        const val = request.headers.get(h);
        if (val) proxyHeaders.set(h, val);
      }
      if (
        validation.url.protocol === "https:" &&
        request.headers.get("Authorization")
      ) {
        proxyHeaders.set("Authorization", request.headers.get("Authorization"));
      }
      for (const h of CONFIG.STRIPPED_REQUEST_HEADERS) {
        proxyHeaders.delete(h);
      }
      proxyHeaders.set(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      );

      const fetchOptions = {
        method: request.method,
        headers: proxyHeaders,
        redirect: "manual", // Handle redirects manually for security
      };
      let requestBody = null;
      if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method) && request.body) {
        try {
          requestBody = await request.arrayBuffer();
        } catch {
          requestBody = null;
        }
        if (requestBody && requestBody.byteLength > CONFIG.MAX_REQUEST_BODY_SIZE) {
          return jsonError(
            `Request body terlalu besar (${Math.round(requestBody.byteLength / 1024 / 1024)}MB). Max: ${CONFIG.MAX_REQUEST_BODY_SIZE / 1024 / 1024}MB.`,
            413,
          );
        }
        if (requestBody && requestBody.byteLength > 0) {
          fetchOptions.body = requestBody;
        }
      }
      let response;
      let currentUrl = validation.url.href;
      let redirectCount = 0;

      while (true) {
        const controller = new AbortController();
        const hopTimeout = setTimeout(
          () => controller.abort(),
          CONFIG.REQUEST_TIMEOUT_MS,
        );
        fetchOptions.signal = controller.signal;

        try {
          response = await fetch(currentUrl, fetchOptions);
        } finally {
          clearTimeout(hopTimeout);
        }

        if ([301, 302, 303, 307, 308].includes(response.status)) {
          redirectCount++;
          if (redirectCount > CONFIG.MAX_REDIRECTS) {
            return jsonError(
              `Terlalu banyak redirect (max ${CONFIG.MAX_REDIRECTS}).`,
              502,
            );
          }

          const location = response.headers.get("Location");
          if (!location) {
            return jsonError("Redirect tanpa Location header.", 502);
          }
          let redirectUrl;
          try {
            redirectUrl = new URL(location, currentUrl);
          } catch {
            return jsonError("Redirect URL tidak valid.", 502);
          }
          const redirectValidation = validateUrl(redirectUrl.href);
          if (!redirectValidation.ok) {
            return jsonError(
              `Redirect diblokir: ${redirectValidation.error}`,
              403,
            );
          }
          if (redirectUrl.hostname.toLowerCase() === selfHost) {
            return jsonError(
              "Redirect ke proxy sendiri diblokir (loop prevention).",
              403,
            );
          }
          const prevOrigin = new URL(currentUrl);
          if (redirectUrl.origin !== prevOrigin.origin || (prevOrigin.protocol === "https:" && redirectUrl.protocol === "http:")) {
            proxyHeaders.delete("Authorization");
          }

          currentUrl = redirectUrl.href;
          if (response.status === 303) {
            fetchOptions.method = "GET";
            delete fetchOptions.body;
          } else if (
            [301, 302].includes(response.status) &&
            fetchOptions.method === "POST"
          ) {
            fetchOptions.method = "GET";
            delete fetchOptions.body;
          } else if ([307, 308].includes(response.status) && requestBody) {
            fetchOptions.body = requestBody;
          }

          continue;
        }

        break;
      }
      const contentLength = parseInt(
        response.headers.get("Content-Length") || "0",
        10,
      );
      if (contentLength > CONFIG.MAX_RESPONSE_SIZE) {
        return jsonError(
          `Response terlalu besar (${Math.round(contentLength / 1024 / 1024)}MB). Max: ${CONFIG.MAX_RESPONSE_SIZE / 1024 / 1024}MB.`,
          413,
        );
      }
      const responseHeaders = new Headers();
      for (const [key, value] of response.headers.entries()) {
        const lower = key.toLowerCase();
        if (CONFIG.STRIPPED_RESPONSE_HEADERS.includes(lower)) continue;
        if (lower === "content-security-policy") continue;
        if (lower === "content-security-policy-report-only") continue;
        if (lower === "x-frame-options") continue;
        if (lower === "strict-transport-security") continue;
        responseHeaders.set(key, value);
      }
      const cors = corsHeaders();
      for (const [key, value] of Object.entries(cors)) {
        responseHeaders.set(key, value);
      }
      const secHeaders = securityHeaders();
      for (const [key, value] of Object.entries(secHeaders)) {
        responseHeaders.set(key, value);
      }
      responseHeaders.set("X-RateLimit-Limit", String(rateLimit.limit));
      responseHeaders.set("X-RateLimit-Remaining", String(rateLimit.remaining));
      responseHeaders.set("X-Daily-Remaining", String(dailyBudget.remaining));
      responseHeaders.set("X-Request-Count", String(dailyBudget.used));
      responseHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate");
      responseHeaders.set("Vary", "Origin");
      responseHeaders.set("Content-Security-Policy", "sandbox");
      let body = response.body;
      if (body) {
        body = createSizeLimitedStream(body, CONFIG.MAX_RESPONSE_SIZE);
      }

      return new Response(body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      if (err.name === "AbortError") {
        return jsonError(
          `Request timeout setelah ${CONFIG.REQUEST_TIMEOUT_MS / 1000} detik.`,
          504,
        );
      }
      return jsonError(`Gagal fetch: ${sanitizeError(err)}`, 502);
    }
    } catch (fatalErr) {
      return new Response(
        JSON.stringify({ success: false, error: "Internal proxy error.", status: 500 }, null, 2),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            ...corsHeaders(),
            ...securityHeaders(),
          },
        },
      );
    }
  },
};

function generateSitemap() {
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://my-cors-proxy.zenth.workers.dev/</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <priority>1.0</priority>
  </url>
</urlset>`;

  return sitemap.trim();
}
