const PASSWORD_KEY = "password";
const SECRET_KEY = "session-secret";
const DATA_KEY = "store";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MIN_PASSWORD_LENGTH = 6;
const FORBIDDEN_PASSWORDS = new Set(["8888"]);

function defaultData() {
  return {
    classes: [],
    sessions: [],
    redeemed: {},
    prizes: [
      { n: 5, title: "\u80fd\u91cf\u65b0\u661f", gift: "10 \u679a\u534e\u7279\u5e01" },
      { n: 10, title: "\u661f\u9645\u63a2\u7d22\u5bb6", gift: "20 \u679a\u534e\u7279\u5e01" },
      { n: 15, title: "\u94f6\u6cb3\u5c0f\u52c7\u58eb", gift: "30 \u679a\u534e\u7279\u5e01" },
    ],
  };
}

function allowedOrigin(request) {
  const origin = request.headers.get("Origin");
  if (origin == null) return null;
  if (origin === "null") return "null";
  const selfOrigin = new URL(request.url).origin;
  if (origin === selfOrigin) return origin;
  if (origin === "https://summerguo21.github.io") return origin;
  try {
    const url = new URL(origin);
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1")
    ) {
      return origin;
    }
  } catch {
    return null;
  }
  return null;
}

function corsHeaders(request) {
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
  const allow = allowedOrigin(request);
  if (allow) headers["Access-Control-Allow-Origin"] = allow;
  return headers;
}

function json(request, body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(request),
    },
  });
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBytes(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replaceAll("-", "+").replaceAll("_", "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function timingSafeEqual(a, b) {
  const max = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < max; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    key,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

async function getSigningSecret(env) {
  const existing = await env.ATTENDANCE_KV.get(SECRET_KEY);
  if (existing) return existing;
  const secret = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  await env.ATTENDANCE_KV.put(SECRET_KEY, secret);
  return secret;
}

async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToBase64Url(new Uint8Array(sig));
}

async function issueToken(env) {
  const secret = await getSigningSecret(env);
  const now = Date.now();
  const payload = bytesToBase64Url(
    new TextEncoder().encode(JSON.stringify({ v: 1, iat: now, exp: now + SESSION_TTL_MS }))
  );
  const sig = await hmacSign(secret, payload);
  return `${payload}.${sig}`;
}

async function verifyToken(env, token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return false;
  const secret = await getSigningSecret(env);
  const idx = token.lastIndexOf(".");
  const payload = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = await hmacSign(secret, payload);
  if (!timingSafeEqual(base64UrlToBytes(sig), base64UrlToBytes(expected))) return false;
  try {
    const data = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payload)));
    return !!(data && data.v === 1 && typeof data.exp === "number" && data.exp > Date.now());
  } catch {
    return false;
  }
}

function bearerToken(request) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

function validateNewPassword(password) {
  if (typeof password !== "string") return "\u8bf7\u8bbe\u7f6e\u8001\u5e08\u5bc6\u7801";
  const value = password.trim();
  if (!value) return "\u8bf7\u8bbe\u7f6e\u8001\u5e08\u5bc6\u7801";
  if (value.length < MIN_PASSWORD_LENGTH) return "\u5bc6\u7801\u81f3\u5c11\u9700\u8981 6 \u4e2a\u5b57\u7b26";
  if (FORBIDDEN_PASSWORDS.has(value)) return "\u8bf7\u8bbe\u7f6e\u65b0\u7684\u8001\u5e08\u5bc6\u7801\uff0c\u4e0d\u80fd\u4f7f\u7528\u9ed8\u8ba4\u5bc6\u7801";
  return null;
}

async function readStore(env) {
  const raw = await env.ATTENDANCE_KV.get(DATA_KEY, "json");
  if (!raw || typeof raw !== "object") {
    return { data: defaultData(), revision: 0 };
  }
  const revision = Number.isInteger(raw.revision) ? raw.revision : 0;
  const data = raw.data && typeof raw.data === "object" ? raw.data : defaultData();
  return { data, revision };
}

async function handleAuth(request, env, body) {
  const op = body?.op || body?.action;
  if (op === "status") {
    const password = await env.ATTENDANCE_KV.get(PASSWORD_KEY);
    return json(request, { ok: true, mustSetup: !password });
  }
  if (op === "logout") {
    return json(request, { ok: true });
  }
  if (op === "setup") {
    const existing = await env.ATTENDANCE_KV.get(PASSWORD_KEY);
    if (existing) {
      return json(request, { ok: false, error: "\u5bc6\u7801\u5df2\u8bbe\u7f6e\uff0c\u8bf7\u76f4\u63a5\u767b\u5f55" }, 409);
    }
    const error = validateNewPassword(body?.password);
    if (error) return json(request, { ok: false, error }, 400);
    const salt = crypto.randomUUID();
    const hash = await hashPassword(body.password, salt);
    await env.ATTENDANCE_KV.put(PASSWORD_KEY, JSON.stringify({ salt, hash }));
    const token = await issueToken(env);
    return json(request, { ok: true, token });
  }
  if (op === "login") {
    const recorded = await env.ATTENDANCE_KV.get(PASSWORD_KEY, "json");
    if (!recorded || !recorded.salt || !recorded.hash) {
      return json(
        request,
        { ok: false, mustSetup: true, error: "\u8bf7\u5148\u8bbe\u7f6e\u8001\u5e08\u5bc6\u7801" },
        403
      );
    }
    const password = typeof body?.password === "string" ? body.password : "";
    const hash = await hashPassword(password, recorded.salt);
    if (!timingSafeEqual(new TextEncoder().encode(hash), new TextEncoder().encode(recorded.hash))) {
      return json(request, { ok: false, error: "\u5bc6\u7801\u4e0d\u6b63\u786e\uff0c\u8bf7\u91cd\u65b0\u8f93\u5165" }, 401);
    }
    const token = await issueToken(env);
    return json(request, { ok: true, token });
  }
  return json(request, { ok: false, error: "\u4e0d\u652f\u6301\u7684\u64cd\u4f5c" }, 400);
}

async function handleGetData(request, env) {
  const store = await readStore(env);
  return json(request, store);
}

async function handlePostData(request, env, body) {
  if (!(await verifyToken(env, bearerToken(request)))) {
    return json(request, { ok: false, error: "\u8bf7\u5148\u767b\u5f55\u8001\u5e08\u540e\u53f0" }, 401);
  }
  if (!body || typeof body !== "object" || !body.data || typeof body.data !== "object") {
    return json(request, { ok: false, error: "\u6570\u636e\u683c\u5f0f\u4e0d\u6b63\u786e" }, 400);
  }
  const expected =
    body.revision !== undefined ? body.revision : body.expectedRevision;
  if (!Number.isInteger(expected) || expected < 0) {
    return json(request, { ok: false, error: "\u7248\u672c\u53f7\u4e0d\u6b63\u786e" }, 400);
  }
  const current = await readStore(env);
  if (expected !== current.revision) {
    return json(request, { data: current.data, revision: current.revision, error: "\u6570\u636e\u5df2\u5728\u5176\u4ed6\u8bbe\u5907\u66f4\u65b0" }, 409);
  }
  const next = { data: body.data, revision: current.revision + 1 };
  await env.ATTENDANCE_KV.put(DATA_KEY, JSON.stringify(next));
  return json(request, next);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    let body = null;
    if (request.method === "POST") {
      const contentType = request.headers.get("Content-Type") || "";
      if (contentType.includes("application/json")) {
        try {
          body = await request.json();
        } catch {
          return json(request, { ok: false, error: "\u8bf7\u6c42\u683c\u5f0f\u4e0d\u6b63\u786e" }, 400);
        }
      } else {
        try {
          body = await request.json();
        } catch {
          body = null;
        }
      }
    }
    if (path === "/api/auth" && request.method === "POST") {
      return handleAuth(request, env, body || {});
    }
    if (path === "/api/data" && request.method === "GET") {
      return handleGetData(request, env);
    }
    if (path === "/api/data" && request.method === "POST") {
      return handlePostData(request, env, body);
    }
    if (request.method === "GET" || request.method === "HEAD") {
      let html = await env.ATTENDANCE_KV.get("index-html");
      const current = html && html.includes("function htApiBase");
      if (!current) {
        try {
          const upstream = await fetch("https://raw.githubusercontent.com/summerguo21/hua-te-attendance/main/index.html");
          if (upstream.ok) {
            const fresh = await upstream.text();
            if (fresh && fresh.includes("function htApiBase")) {
              html = fresh;
              await env.ATTENDANCE_KV.put("index-html", html);
            }
          }
        } catch {
          /* keep existing html */
        }
      }
      if (html && !html.includes("function htApiBase")) html = null;
      if (html) {
        return new Response(request.method === "HEAD" ? null : html, {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store, max-age=0",
            "X-Content-Type-Options": "nosniff",
          },
        });
      }
    }
    return json(request, { ok: false, error: "不支持的操作" }, 404);
  },
};
