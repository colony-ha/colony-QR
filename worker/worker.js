const ALLOWED_ORIGIN = "https://colony-qr.pages.dev";
const SESSION_DAYS = 7;
const PASSWORD_ITERATIONS = 100000;
const GOOGLE_KEYS_URL = "https://www.googleapis.com/oauth2/v3/certs";

const SUPER_ADMIN_EMAILS = new Set([
  "hanih9823@gmail.com",
  "colonyus666@gmail.com"
]);

const ALLOWED_QR_TYPES = [
  "url", "text", "wifi", "whatsapp", "phone",
  "email", "sms", "contact", "location", "event", "social"
];

const ALLOWED_PLANS = ["free", "pro", "business"];
const ADMIN_PLANS = ["pro", "business"];

// ==========================================
// GENERAL HELPERS
// ==========================================

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isSuperAdminEmail(email) {
  return SUPER_ADMIN_EMAILS.has(normalizeEmail(email));
}

function hex(bytes) {
  return Array.from(bytes, b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

function fromHex(value) {
  const result = new Uint8Array(value.length / 2);

  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(
      value.slice(i * 2, i * 2 + 2),
      16
    );
  }

  return result;
}

function randomHex(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return hex(bytes);
}

function base64UrlToBytes(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    base64 + "=".repeat((4 - base64.length % 4) % 4);

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    c => c.charCodeAt(0)
  );
}

function decodeJwtPart(value) {
  return JSON.parse(
    new TextDecoder().decode(
      base64UrlToBytes(value)
    )
  );
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return hex(new Uint8Array(result));
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: fromHex(salt),
    iterations: PASSWORD_ITERATIONS,
    hash: "SHA-256"
  }, key, 256);

  return hex(new Uint8Array(bits));
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) return false;

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
}

function corsHeaders(origin) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };

  if (origin === ALLOWED_ORIGIN) {
    headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN;
    headers["Access-Control-Allow-Credentials"] = "true";
    headers["Access-Control-Allow-Methods"] =
      "GET, POST, PATCH, DELETE, OPTIONS";
    headers["Access-Control-Allow-Headers"] =
      "Content-Type";
  }

  return headers;
}

function reply(data, status, headers) {
  return new Response(
    JSON.stringify(data),
    { status, headers }
  );
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";

  const item = cookies
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));

  return item
    ? item.slice(name.length + 1)
    : null;
}

function sessionCookie(token, maxAge) {
  return `colony_session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${maxAge}`;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function validUuid(value) {
  return /^[a-f0-9-]{36}$/i.test(String(value || ""));
}

function validDuration(value) {
  if (value === null) return true;

  return (
    Number.isInteger(value) &&
    value >= 1 &&
    value <= 36500
  );
}

function addDays(date, days) {
  return new Date(
    date.getTime() + days * 86400000
  ).toISOString();
}

async function grantSignupTrial(env, userId) {
  const existing = await env.DB.prepare(`
    SELECT trial_granted_at
    FROM users
    WHERE id = ?
    LIMIT 1
  `).bind(userId).first();

  if (!existing || existing.trial_granted_at) return null;

  const now = new Date();
  const startsAt = now.toISOString();
  const endsAt = addDays(now, 3);
  const subscriptionId = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO subscriptions (
      id, user_id, plan_code, source, status,
      starts_at, ends_at, auto_renew, provider,
      provider_subscription_id, granted_by_user_id,
      grant_reason, created_at, updated_at
    )
    VALUES (?, ?, 'pro', 'admin_granted', 'active',
            ?, ?, 0, NULL, NULL, NULL,
            'Automatic 3-day Pro trial', ?, ?)
  `).bind(
    subscriptionId, userId, startsAt, endsAt, startsAt, startsAt
  ).run();

  await env.DB.prepare(`
    UPDATE users
    SET trial_granted_at = ?, updated_at = ?
    WHERE id = ? AND trial_granted_at IS NULL
  `).bind(startsAt, startsAt, userId).run();

  return { id: subscriptionId, starts_at: startsAt, ends_at: endsAt };
}

// ==========================================
// SESSION MANAGEMENT
// ==========================================

async function createSession(env, userId) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const id = crypto.randomUUID();

  const expiresAt = new Date(
    Date.now() + SESSION_DAYS * 86400000
  ).toISOString();

  await env.DB.prepare(`
    INSERT INTO sessions (
      id,
      user_id,
      token_hash,
      expires_at
    )
    VALUES (?, ?, ?, ?)
  `).bind(
    id,
    userId,
    tokenHash,
    expiresAt
  ).run();

  return token;
}

async function currentUser(request, env) {
  const token = getCookie(request, "colony_session");

  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    return null;
  }

  const tokenHash = await sha256(token);

  const user = await env.DB.prepare(`
    SELECT
      users.id,
      users.email,
      users.display_name,
      users.role,
      users.status
    FROM sessions
    JOIN users
      ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
    LIMIT 1
  `).bind(
    tokenHash,
    new Date().toISOString()
  ).first();

  if (!user || user.status !== "active") {
    return null;
  }

  if (isSuperAdminEmail(user.email)) {
    if (user.role !== "super_admin") {
      await env.DB.prepare(`
        UPDATE users
        SET role = 'super_admin'
        WHERE id = ?
      `).bind(user.id).run();

      user.role = "super_admin";
    }
  } else if (user.role === "super_admin") {
    await env.DB.prepare(`
      UPDATE users
      SET role = 'user'
      WHERE id = ?
    `).bind(user.id).run();

    user.role = "user";
  }

  return user;
}

async function requireSuperAdmin(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    return {
      ok: false,
      status: 401,
      error: "Authentication required"
    };
  }

  if (
    !isSuperAdminEmail(user.email) ||
    user.role !== "super_admin"
  ) {
    return {
      ok: false,
      status: 403,
      error: "Super Admin access required"
    };
  }

  return {
    ok: true,
    user
  };
}

// ==========================================
// AUDIT LOGS
// ==========================================

async function writeAudit(
  env,
  actorId,
  targetId,
  action,
  details = {}
) {
  await env.DB.prepare(`
    INSERT INTO audit_logs (
      id,
      actor_user_id,
      target_user_id,
      action,
      details_json,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(),
    actorId,
    targetId || null,
    action,
    JSON.stringify(details),
    new Date().toISOString()
  ).run();
}

// ==========================================
// GOOGLE TOKEN VERIFICATION
// ==========================================

async function verifyGoogleToken(
  token,
  expectedNonce,
  clientId
) {
  if (
    typeof token !== "string" ||
    token.length > 12000
  ) {
    throw new Error("Invalid Google credential");
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid Google token");
  }

  const header = decodeJwtPart(parts[0]);
  const claims = decodeJwtPart(parts[1]);

  if (
    header.alg !== "RS256" ||
    !header.kid
  ) {
    throw new Error("Unsupported Google token");
  }

  const keysResponse = await fetch(GOOGLE_KEYS_URL);

  if (!keysResponse.ok) {
    throw new Error("Google keys unavailable");
  }

  const keySet = await keysResponse.json();

  const jwk = keySet.keys.find(
    key => key.kid === header.kid
  );

  if (!jwk) {
    throw new Error("Google signing key not found");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(
    parts[0] + "." + parts[1]
  );

  const signature = base64UrlToBytes(parts[2]);

  const validSignature = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signature,
    signedData
  );

  if (!validSignature) {
    throw new Error("Invalid Google signature");
  }

  const now = Math.floor(Date.now() / 1000);

  const issuerValid = [
    "https://accounts.google.com",
    "accounts.google.com"
  ].includes(claims.iss);

  if (!issuerValid) {
    throw new Error("Invalid issuer");
  }

  if (claims.aud !== clientId) {
    throw new Error("Invalid audience");
  }

  if (claims.azp && claims.azp !== clientId) {
    throw new Error("Invalid authorized party");
  }

  if (
    !claims.sub ||
    typeof claims.sub !== "string"
  ) {
    throw new Error("Invalid Google account");
  }

  if (!claims.exp || claims.exp <= now) {
    throw new Error("Expired Google token");
  }

  if (
    !claims.iat ||
    claims.iat > now + 60
  ) {
    throw new Error("Invalid token time");
  }

  if (claims.nonce !== expectedNonce) {
    throw new Error("Invalid nonce");
  }

  if (
    claims.email_verified !== true &&
    claims.email_verified !== "true"
  ) {
    throw new Error("Google email is not verified");
  }

  const email = normalizeEmail(claims.email);

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    email.length > 254
  ) {
    throw new Error("Invalid Google email");
  }

  return {
    sub: claims.sub,
    email,
    name: String(
      claims.name ||
      claims.given_name ||
      "COLONY QR User"
    ).trim().slice(0, 80)
  };
}

// ==========================================
// GOOGLE LOGIN
// ==========================================

async function googleLogin(request, env, headers) {
  if (!env.GOOGLE_CLIENT_ID) {
    return reply({
      success: false,
      error: "Google login is not configured"
    }, 503, headers);
  }

  const body = await readJson(request);

  if (!body) {
    return reply({
      success: false,
      error: "Invalid JSON body"
    }, 400, headers);
  }

  const credential = body.credential;
  const nonce = body.nonce;

  if (
    typeof credential !== "string" ||
    typeof nonce !== "string" ||
    !/^[a-f0-9]{64}$/.test(nonce)
  ) {
    return reply({
      success: false,
      error: "Invalid Google login request"
    }, 400, headers);
  }

  const google = await verifyGoogleToken(
    credential,
    nonce,
    env.GOOGLE_CLIENT_ID
  );

  const nonceHash = await sha256(nonce);

  const consumed = await env.DB.prepare(`
    DELETE FROM oauth_nonces
    WHERE nonce_hash = ?
      AND expires_at > ?
    RETURNING nonce_hash
  `).bind(
    nonceHash,
    new Date().toISOString()
  ).first();

  if (!consumed) {
    return reply({
      success: false,
      error: "Login request expired. Try again."
    }, 401, headers);
  }

  let user = await env.DB.prepare(`
    SELECT
      id,
      email,
      display_name,
      role,
      status,
      google_sub
    FROM users
    WHERE google_sub = ?
    LIMIT 1
  `).bind(google.sub).first();

  if (user) {
    if (user.status !== "active") {
      return reply({
        success: false,
        error: "Account unavailable"
      }, 403, headers);
    }

    const newRole = isSuperAdminEmail(user.email)
      ? "super_admin"
      : (user.role === "super_admin" ? "user" : user.role);

    if (newRole !== user.role) {
      await env.DB.prepare(`
        UPDATE users
        SET role = ?
        WHERE id = ?
      `).bind(newRole, user.id).run();

      user.role = newRole;
    }
  } else {
    const existingEmail = await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE email = ?
      LIMIT 1
    `).bind(google.email).first();

    if (existingEmail) {
      return reply({
        success: false,
        error: "An account with this email already exists. Sign in with your password first."
      }, 409, headers);
    }

    const existingUsername = await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE lower(trim(display_name)) = lower(trim(?))
      LIMIT 1
    `).bind(google.name).first();

    if (existingUsername) {
      return reply({
        success: false,
        error: "Username already taken. Please sign up with email and choose another username."
      }, 409, headers);
    }

    const userId = crypto.randomUUID();
    const salt = randomHex(16);
    const randomPassword = randomHex(64);
    const passwordHash = await hashPassword(
      randomPassword,
      salt
    );

    const role = isSuperAdminEmail(google.email)
      ? "super_admin"
      : "user";

    await env.DB.prepare(`
      INSERT INTO users (
        id,
        email,
        display_name,
        password_hash,
        password_salt,
        password_iterations,
        role,
        status,
        google_sub
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
    `).bind(
      userId,
      google.email,
      google.name,
      passwordHash,
      salt,
      PASSWORD_ITERATIONS,
      role,
      google.sub
    ).run();

    await grantSignupTrial(env, userId);

    user = {
      id: userId,
      email: google.email,
      display_name: google.name,
      role,
      status: "active"
    };
  }

  await env.DB.prepare(`
    UPDATE users
    SET last_login_at = ?
    WHERE id = ?
  `).bind(
    new Date().toISOString(),
    user.id
  ).run();

  const sessionToken = await createSession(
    env,
    user.id
  );

  headers["Set-Cookie"] = sessionCookie(
    sessionToken,
    SESSION_DAYS * 86400
  );

  return reply({
    success: true,
    user: {
      id: user.id,
      email: user.email,
      display_name: user.display_name,
      role: user.role
    }
  }, 200, headers);
}

// ==========================================
// IMAGEKIT + DIGITAL BUSINESS PAGES
// ==========================================

async function requireDigitalAccess(env, userId) {
  const now = new Date().toISOString();
  const subscription = await env.DB.prepare(`
    SELECT id, plan_code, ends_at, source, grant_reason
    FROM subscriptions
    WHERE user_id = ?
      AND status = 'active'
      AND plan_code IN ('pro', 'business')
      AND starts_at <= ?
      AND (ends_at IS NULL OR ends_at > ?)
    ORDER BY
      CASE WHEN plan_code = 'business' THEN 0 ELSE 1 END,
      ends_at DESC
    LIMIT 1
  `).bind(userId, now, now).first();

  return subscription || null;
}

async function imageKitAuth(request, env, headers) {
  const user = await currentUser(request, env);

  if (!user) {
    return reply({ success: false, error: "Authentication required" }, 401, headers);
  }

  const subscription = await requireDigitalAccess(env, user.id);

  if (!subscription) {
    return reply({
      success: false,
      error: "An active Pro or Business subscription is required",
      code: "SUBSCRIPTION_REQUIRED"
    }, 403, headers);
  }

  if (!env.IMAGEKIT_PRIVATE_KEY || !env.IMAGEKIT_PUBLIC_KEY || !env.IMAGEKIT_URL_ENDPOINT) {
    return reply({
      success: false,
      error: "Image storage is not configured"
    }, 503, headers);
  }

  const token = crypto.randomUUID();
  const expire = Math.floor(Date.now() / 1000) + 10 * 60;
  const message = token + expire;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.IMAGEKIT_PRIVATE_KEY),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const signatureBytes = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );

  return reply({
    success: true,
    token,
    expire,
    signature: hex(new Uint8Array(signatureBytes)),
    publicKey: env.IMAGEKIT_PUBLIC_KEY,
    urlEndpoint: env.IMAGEKIT_URL_ENDPOINT
  }, 200, headers);
}

function cleanPageInput(body) {
  const fields = [
    "title", "business_category", "description", "phone",
    "whatsapp", "email", "website", "address", "maps_url",
    "logo_url", "cover_image_url"
  ];
  const result = {};

  for (const field of fields) {
    if (body[field] !== undefined) {
      result[field] = String(body[field] ?? "").trim().slice(0, field === "description" ? 5000 : 1000);
    }
  }

  return result;
}

function makeSlug(value) {
  return String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 70);
}

async function handleDigitalPages(request, env, headers, url) {
  const path = url.pathname;
  const now = new Date().toISOString();

  // Public page lookup by its unique slug.
  const publicMatch = path.match(/^\/api\/public\/digital-pages\/([a-z0-9-]{1,70})$/i);
  if (publicMatch && request.method === "GET") {
    const page = await env.DB.prepare(`
      SELECT p.id, p.title, p.slug, p.business_category, p.description, p.phone,
             p.whatsapp, p.email, p.website, p.address, p.maps_url, p.logo_url,
             p.cover_image_url, p.theme_json, p.social_links_json, p.updated_at
      FROM digital_pages p
      WHERE p.slug = ? AND p.status = 'published'
        AND EXISTS (
          SELECT 1
          FROM users u
          WHERE u.id = p.user_id
            AND u.status = 'active'
        )
        AND EXISTS (
          SELECT 1
          FROM subscriptions s
          WHERE s.user_id = p.user_id
            AND s.status = 'active'
            AND s.plan_code IN ('pro', 'business')
            AND s.starts_at <= ?
            AND (s.ends_at IS NULL OR s.ends_at > ?)
        )
      LIMIT 1
    `).bind(publicMatch[1], now, now).first();

    if (!page) {
      return reply({ success: false, error: "Page not found" }, 404, headers);
    }

    const items = await env.DB.prepare(`
      SELECT id, item_type, category, name, description, price,
             currency, image_url, sort_order
      FROM digital_page_items
      WHERE page_id = ? AND is_active = 1
      ORDER BY sort_order ASC, created_at ASC
    `).bind(page.id).all();

    return reply({ success: true, page, items: items.results || [] }, 200, headers);
  }

  const user = await currentUser(request, env);
  if (!user) {
    return reply({ success: false, error: "Authentication required" }, 401, headers);
  }

  if (path === "/api/digital-pages" && request.method === "GET") {
    const result = await env.DB.prepare(`
      SELECT id, title, slug, business_category, description, phone,
             whatsapp, email, website, address, maps_url, logo_url,
             cover_image_url, theme_json, social_links_json, status,
             created_at, updated_at
      FROM digital_pages
      WHERE user_id = ?
      ORDER BY updated_at DESC
      LIMIT 100
    `).bind(user.id).all();

    return reply({ success: true, pages: result.results || [] }, 200, headers);
  }

  if (path === "/api/digital-pages" && request.method === "POST") {
    const subscription = await requireDigitalAccess(env, user.id);
    if (!subscription) {
      return reply({
        success: false,
        error: "An active Pro or Business subscription is required",
        code: "SUBSCRIPTION_REQUIRED"
      }, 403, headers);
    }

    const body = await readJson(request);
    if (!body || typeof body !== "object") {
      return reply({ success: false, error: "Invalid JSON body" }, 400, headers);
    }

    const fields = cleanPageInput(body);
    if (!fields.title || fields.title.length < 2) {
      return reply({ success: false, error: "Page title must contain at least 2 characters" }, 400, headers);
    }

    let slug = makeSlug(body.slug || fields.title);
    if (!slug) slug = "business-" + randomHex(4);
    const exists = await env.DB.prepare("SELECT id FROM digital_pages WHERE slug = ? LIMIT 1").bind(slug).first();
    if (exists) slug = slug + "-" + randomHex(3);

    const id = crypto.randomUUID();
    await env.DB.prepare(`
      INSERT INTO digital_pages (
        id, user_id, title, slug, business_category, description, phone,
        whatsapp, email, website, address, maps_url, logo_url,
        cover_image_url, theme_json, social_links_json, status,
        created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)
    `).bind(
      id, user.id, fields.title, slug,
      fields.business_category || "", fields.description || "",
      fields.phone || "", fields.whatsapp || "", fields.email || "",
      fields.website || "", fields.address || "", fields.maps_url || "",
      fields.logo_url || "", fields.cover_image_url || "",
      JSON.stringify(body.theme && typeof body.theme === "object" ? body.theme : {}),
      JSON.stringify(body.social_links && typeof body.social_links === "object" ? body.social_links : {}),
      now, now
    ).run();

    return reply({
      success: true,
      message: "Digital page created as draft",
      page: { id, user_id: user.id, title: fields.title, slug, status: "draft", created_at: now, updated_at: now }
    }, 201, headers);
  }

  const pageMatch = path.match(/^\/api\/digital-pages\/([a-f0-9-]{36})$/i);
  if (pageMatch) {
    const pageId = pageMatch[1];
    const page = await env.DB.prepare(`
      SELECT * FROM digital_pages WHERE id = ? AND user_id = ? LIMIT 1
    `).bind(pageId, user.id).first();

    if (!page) {
      return reply({ success: false, error: "Page not found" }, 404, headers);
    }

    if (request.method === "GET") {
      const items = await env.DB.prepare(`
        SELECT * FROM digital_page_items
        WHERE page_id = ?
        ORDER BY sort_order ASC, created_at ASC
      `).bind(pageId).all();

      return reply({ success: true, page, items: items.results || [] }, 200, headers);
    }

    if (request.method === "PATCH") {
      const subscription = await requireDigitalAccess(env, user.id);
      if (!subscription) {
        return reply({
          success: false,
          error: "An active Pro or Business subscription is required",
          code: "SUBSCRIPTION_REQUIRED"
        }, 403, headers);
      }

      const body = await readJson(request);
      if (!body || typeof body !== "object") {
        return reply({ success: false, error: "Invalid JSON body" }, 400, headers);
      }

      const fields = cleanPageInput(body);
      const allowed = ["title", "business_category", "description", "phone", "whatsapp", "email", "website", "address", "maps_url", "logo_url", "cover_image_url"];
      const sets = [];
      const values = [];

      for (const field of allowed) {
        if (fields[field] !== undefined) {
          sets.push(field + " = ?");
          values.push(fields[field]);
        }
      }

      if (body.theme !== undefined) {
        sets.push("theme_json = ?");
        values.push(JSON.stringify(body.theme && typeof body.theme === "object" ? body.theme : {}));
      }

      if (body.social_links !== undefined) {
        sets.push("social_links_json = ?");
        values.push(JSON.stringify(body.social_links && typeof body.social_links === "object" ? body.social_links : {}));
      }

      if (body.status !== undefined) {
        const status = String(body.status);
        if (!["draft", "published"].includes(status)) {
          return reply({ success: false, error: "Status must be draft or published" }, 400, headers);
        }
        sets.push("status = ?");
        values.push(status);
      }

      if (body.slug !== undefined) {
        const slug = makeSlug(body.slug);
        if (!slug) return reply({ success: false, error: "Invalid page URL" }, 400, headers);
        const duplicate = await env.DB.prepare("SELECT id FROM digital_pages WHERE slug = ? AND id <> ? LIMIT 1").bind(slug, pageId).first();
        if (duplicate) return reply({ success: false, error: "This page URL is already used" }, 409, headers);
        sets.push("slug = ?");
        values.push(slug);
      }

      if (!sets.length) {
        return reply({ success: false, error: "No changes supplied" }, 400, headers);
      }

      sets.push("updated_at = ?");
      values.push(now, pageId, user.id);

      await env.DB.prepare(`
        UPDATE digital_pages SET ${sets.join(", ")}
        WHERE id = ? AND user_id = ?
      `).bind(...values).run();

      const updated = await env.DB.prepare("SELECT * FROM digital_pages WHERE id = ? AND user_id = ?").bind(pageId, user.id).first();
      return reply({ success: true, page: updated }, 200, headers);
    }

    if (request.method === "DELETE") {
      // The ownership check above ensures customers can only delete their own page.
      // Delete its products and services first, then remove the page itself.
      await env.DB.prepare("DELETE FROM digital_page_items WHERE page_id = ?").bind(pageId).run();
      await env.DB.prepare("DELETE FROM digital_pages WHERE id = ? AND user_id = ?").bind(pageId, user.id).run();
      return reply({ success: true, message: "Digital page and its items deleted" }, 200, headers);
    }
  }

  const itemsCollection = path.match(/^\/api\/digital-pages\/([a-f0-9-]{36})\/items$/i);
  if (itemsCollection) {
    const pageId = itemsCollection[1];
    const ownedPage = await env.DB.prepare("SELECT id FROM digital_pages WHERE id = ? AND user_id = ?").bind(pageId, user.id).first();
    if (!ownedPage) return reply({ success: false, error: "Page not found" }, 404, headers);

    if (request.method === "GET") {
      const items = await env.DB.prepare("SELECT * FROM digital_page_items WHERE page_id = ? ORDER BY sort_order ASC, created_at ASC").bind(pageId).all();
      return reply({ success: true, items: items.results || [] }, 200, headers);
    }

    if (request.method === "POST") {
      const subscription = await requireDigitalAccess(env, user.id);
      if (!subscription) return reply({ success: false, error: "An active Pro or Business subscription is required", code: "SUBSCRIPTION_REQUIRED" }, 403, headers);

      const body = await readJson(request);
      if (!body) return reply({ success: false, error: "Invalid JSON body" }, 400, headers);

      const name = String(body.name || "").trim().slice(0, 160);
      const itemType = String(body.item_type || "product");
      if (!name || !["product", "service"].includes(itemType)) {
        return reply({ success: false, error: "A name and valid item_type (product or service) are required" }, 400, headers);
      }

      const price = Number(body.price || 0);
      if (!Number.isFinite(price) || price < 0 || price > 100000000000) {
        return reply({ success: false, error: "Invalid price" }, 400, headers);
      }

      const id = crypto.randomUUID();
      await env.DB.prepare(`
        INSERT INTO digital_page_items (
          id, page_id, item_type, category, name, description, price,
          currency, image_url, sort_order, is_active, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
      `).bind(
        id, pageId, itemType,
        String(body.category || "").slice(0, 100),
        name,
        String(body.description || "").slice(0, 2000),
        price,
        String(body.currency || "DZD").slice(0, 8),
        String(body.image_url || "").slice(0, 2000),
        Number.isInteger(body.sort_order) ? body.sort_order : 0,
        now, now
      ).run();

      return reply({ success: true, item: { id, page_id: pageId, item_type: itemType, name, price } }, 201, headers);
    }
  }

  const itemMatch = path.match(/^\/api\/digital-page-items\/([a-f0-9-]{36})$/i);
  if (itemMatch) {
    const itemId = itemMatch[1];
    const item = await env.DB.prepare(`
      SELECT i.* FROM digital_page_items i
      JOIN digital_pages p ON p.id = i.page_id
      WHERE i.id = ? AND p.user_id = ?
      LIMIT 1
    `).bind(itemId, user.id).first();

    if (!item) return reply({ success: false, error: "Item not found" }, 404, headers);

    if (request.method === "PATCH") {
      const subscription = await requireDigitalAccess(env, user.id);
      if (!subscription) return reply({ success: false, error: "An active Pro or Business subscription is required", code: "SUBSCRIPTION_REQUIRED" }, 403, headers);

      const body = await readJson(request);
      if (!body) return reply({ success: false, error: "Invalid JSON body" }, 400, headers);

      const allowed = ["item_type", "category", "name", "description", "price", "currency", "image_url", "sort_order", "is_active"];
      const sets = [];
      const values = [];

      for (const field of allowed) {
        if (body[field] === undefined) continue;
        let value = body[field];
        if (field === "item_type" && !["product", "service"].includes(String(value))) {
          return reply({ success: false, error: "Invalid item type" }, 400, headers);
        }
        if (field === "price") {
          value = Number(value);
          if (!Number.isFinite(value) || value < 0 || value > 100000000000) return reply({ success: false, error: "Invalid price" }, 400, headers);
        }
        if (field === "is_active") value = value ? 1 : 0;
        if (["category", "name", "description", "currency", "image_url"].includes(field)) {
          value = String(value ?? "").slice(0, field === "description" ? 2000 : 2000);
        }
        sets.push(field + " = ?");
        values.push(value);
      }

      if (!sets.length) return reply({ success: false, error: "No changes supplied" }, 400, headers);
      sets.push("updated_at = ?");
      values.push(now, itemId);
      await env.DB.prepare(`UPDATE digital_page_items SET ${sets.join(", ")} WHERE id = ?`).bind(...values).run();
      const updated = await env.DB.prepare("SELECT * FROM digital_page_items WHERE id = ?").bind(itemId).first();
      return reply({ success: true, item: updated }, 200, headers);
    }

    if (request.method === "DELETE") {
      await env.DB.prepare("DELETE FROM digital_page_items WHERE id = ?").bind(itemId).run();
      return reply({ success: true, message: "Item deleted" }, 200, headers);
    }
  }

  return reply({ success: false, error: "Route not found" }, 404, headers);
}

// ==========================================
// QR CODE FUNCTIONS
// ==========================================

async function handleQrRequest(
  request,
  env,
  headers,
  url
) {
  const user = await currentUser(request, env);

  if (!user) {
    return reply({
      success: false,
      error: "Authentication required"
    }, 401, headers);
  }

  if (
    url.pathname === "/api/qr" &&
    request.method === "GET"
  ) {
    const result = await env.DB.prepare(`
      SELECT
        id,
        title,
        qr_type,
        content,
        design_json,
        created_at,
        updated_at
      FROM qr_codes
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 200
    `).bind(user.id).all();

    return reply({
      success: true,
      qr_codes: result.results || []
    }, 200, headers);
  }

  if (
    url.pathname === "/api/qr" &&
    request.method === "POST"
  ) {
    const body = await readJson(request);

    if (!body) {
      return reply({
        success: false,
        error: "Invalid JSON body"
      }, 400, headers);
    }

    const title = String(body.title || "").trim();
    const qrType = String(body.qr_type || "");
    const content = String(body.content || "");

    if (
      title.length < 1 ||
      title.length > 100
    ) {
      return reply({
        success: false,
        error: "Title must be between 1 and 100 characters"
      }, 400, headers);
    }

    if (!ALLOWED_QR_TYPES.includes(qrType)) {
      return reply({
        success: false,
        error: "Invalid QR type"
      }, 400, headers);
    }

    if (
      !content ||
      content.length > 10000
    ) {
      return reply({
        success: false,
        error: "QR content is empty or too long"
      }, 400, headers);
    }

    let design;

    try {
      design =
        body.design &&
        typeof body.design === "object"
          ? JSON.stringify(body.design)
          : "{}";
    } catch {
      return reply({
        success: false,
        error: "Invalid QR design"
      }, 400, headers);
    }

    if (design.length > 50000) {
      return reply({
        success: false,
        error: "QR design is too large"
      }, 400, headers);
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    await env.DB.prepare(`
      INSERT INTO qr_codes (
        id,
        user_id,
        title,
        qr_type,
        content,
        design_json,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      user.id,
      title,
      qrType,
      content,
      design,
      now,
      now
    ).run();

    return reply({
      success: true,
      message: "QR code saved successfully",
      qr_code: {
        id,
        title,
        qr_type: qrType,
        content,
        design_json: design,
        created_at: now,
        updated_at: now
      }
    }, 201, headers);
  }

  const deleteMatch = url.pathname.match(
    /^\/api\/qr\/([a-f0-9-]{36})$/i
  );

  if (
    deleteMatch &&
    request.method === "DELETE"
  ) {
    const qrId = deleteMatch[1];

    const deleted = await env.DB.prepare(`
      DELETE FROM qr_codes
      WHERE id = ?
        AND user_id = ?
      RETURNING id
    `).bind(
      qrId,
      user.id
    ).first();

    if (!deleted) {
      return reply({
        success: false,
        error: "QR code not found"
      }, 404, headers);
    }

    return reply({
      success: true,
      message: "QR code deleted successfully"
    }, 200, headers);
  }

  return reply({
    success: false,
    error: "Method not allowed"
  }, 405, headers);
}

// ==========================================
// ADMIN: OVERVIEW
// ==========================================

async function adminOverview(
  request,
  env,
  headers
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const stats = await env.DB.prepare(`
    SELECT
      (SELECT COUNT(*) FROM users) AS total_users,

      (SELECT COUNT(*)
       FROM users
       WHERE status = 'active') AS active_users,

      (SELECT COUNT(*)
       FROM users
       WHERE status = 'suspended') AS suspended_users,

      (SELECT COUNT(*) FROM qr_codes) AS total_qr_codes,

      (SELECT COUNT(*)
       FROM subscriptions
       WHERE status = 'active'
         AND (ends_at IS NULL OR ends_at > ?)
         AND starts_at <= ?) AS active_subscriptions,

      (SELECT COUNT(*) FROM subscriptions) AS total_subscriptions,

      (SELECT COUNT(*)
       FROM subscriptions
       WHERE source = 'admin_granted') AS free_admin_grants
  `).bind(
    new Date().toISOString(),
    new Date().toISOString()
  ).first();

  return reply({
    success: true,
    overview: stats,
    stats,
    ...stats
  }, 200, headers);
}

// ==========================================
// ADMIN: USERS LIST
// ==========================================

async function adminUsers(
  request,
  env,
  headers,
  url
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const search = String(
    url.searchParams.get("search") || ""
  ).trim().slice(0, 100);

  const limitValue = Number(
    url.searchParams.get("limit") || 100
  );

  const offsetValue = Number(
    url.searchParams.get("offset") || 0
  );

  const limit = Number.isFinite(limitValue)
    ? Math.min(Math.max(Math.floor(limitValue), 1), 200)
    : 100;

  const offset = Number.isFinite(offsetValue)
    ? Math.max(Math.floor(offsetValue), 0)
    : 0;

  let result;
  let countResult;

  if (search) {
    const pattern = search.toLowerCase();

    result = await env.DB.prepare(`
      SELECT
        id,
        email,
        display_name,
        role,
        status,
        created_at,
        last_login_at
      FROM users
      WHERE
        instr(lower(email), ?) > 0
        OR instr(lower(display_name), ?) > 0
      ORDER BY created_at DESC
      LIMIT ?
      OFFSET ?
    `).bind(
      pattern,
      pattern,
      limit,
      offset
    ).all();

    countResult = await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM users
      WHERE
        instr(lower(email), ?) > 0
        OR instr(lower(display_name), ?) > 0
    `).bind(pattern, pattern).first();
  } else {
    result = await env.DB.prepare(`
      SELECT
        id,
        email,
        display_name,
        role,
        status,
        created_at,
        last_login_at
      FROM users
      ORDER BY created_at DESC
      LIMIT ?
      OFFSET ?
    `).bind(limit, offset).all();

    countResult = await env.DB.prepare(`
      SELECT COUNT(*) AS total
      FROM users
    `).first();
  }

  return reply({
    success: true,
    users: result.results || [],
    total: countResult?.total || 0,
    limit,
    offset
  }, 200, headers);
}

// ==========================================
// ADMIN: QR CODES LIST
// ==========================================

async function adminQrCodes(
  request,
  env,
  headers,
  url
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const search = String(
    url.searchParams.get("search") || ""
  ).trim().slice(0, 100).toLowerCase();

  const userId = String(
    url.searchParams.get("user_id") || ""
  ).trim();

  const limitValue = Number(
    url.searchParams.get("limit") || 50
  );

  const offsetValue = Number(
    url.searchParams.get("offset") || 0
  );

  const limit = Number.isFinite(limitValue)
    ? Math.min(Math.max(Math.floor(limitValue), 1), 100)
    : 50;

  const offset = Number.isFinite(offsetValue)
    ? Math.max(Math.floor(offsetValue), 0)
    : 0;

  if (userId && !validUuid(userId)) {
    return reply({
      success: false,
      error: "Invalid user ID"
    }, 400, headers);
  }

  const conditions = [];
  const values = [];

  if (userId) {
    conditions.push("qr_codes.user_id = ?");
    values.push(userId);
  }

  if (search) {
    conditions.push(`
      (
        instr(lower(qr_codes.title), ?) > 0
        OR instr(lower(qr_codes.qr_type), ?) > 0
        OR instr(lower(qr_codes.content), ?) > 0
        OR instr(lower(users.email), ?) > 0
        OR instr(lower(users.display_name), ?) > 0
      )
    `);
    values.push(search, search, search, search, search);
  }

  const where = conditions.length
    ? "WHERE " + conditions.join(" AND ")
    : "";

  const result = await env.DB.prepare(`
    SELECT
      qr_codes.id,
      qr_codes.user_id,
      qr_codes.title,
      qr_codes.qr_type,
      qr_codes.content,
      qr_codes.design_json,
      qr_codes.created_at,
      qr_codes.updated_at,
      users.email AS user_email,
      users.display_name AS user_name
    FROM qr_codes
    JOIN users
      ON users.id = qr_codes.user_id
    ${where}
    ORDER BY qr_codes.created_at DESC
    LIMIT ?
    OFFSET ?
  `).bind(
    ...values,
    limit,
    offset
  ).all();

  const countResult = await env.DB.prepare(`
    SELECT COUNT(*) AS total
    FROM qr_codes
    JOIN users
      ON users.id = qr_codes.user_id
    ${where}
  `).bind(...values).first();

  return reply({
    success: true,
    qr_codes: result.results || [],
    total: countResult?.total || 0,
    limit,
    offset
  }, 200, headers);
}

// ==========================================
// ADMIN: CHANGE USER STATUS
// ==========================================

async function adminChangeUserStatus(
  request,
  env,
  headers,
  userId
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const actor = access.user;
  const body = await readJson(request);

  if (!body) {
    return reply({
      success: false,
      error: "Invalid JSON body"
    }, 400, headers);
  }

  const status = String(body.status || "");

  if (!["active", "suspended"].includes(status)) {
    return reply({
      success: false,
      error: "Status must be active or suspended"
    }, 400, headers);
  }

  const target = await env.DB.prepare(`
    SELECT id, email, display_name, role, status
    FROM users
    WHERE id = ?
    LIMIT 1
  `).bind(userId).first();

  if (!target) {
    return reply({
      success: false,
      error: "User not found"
    }, 404, headers);
  }

  if (
    isSuperAdminEmail(target.email) ||
    target.role === "super_admin"
  ) {
    return reply({
      success: false,
      error: "Super Admin accounts are protected"
    }, 403, headers);
  }

  if (target.id === actor.id) {
    return reply({
      success: false,
      error: "You cannot change your own account status"
    }, 403, headers);
  }

  await env.DB.prepare(`
    UPDATE users
    SET status = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).bind(status, userId).run();

  if (status === "suspended") {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
    `).bind(userId).run();
  }

  await writeAudit(
    env,
    actor.id,
    target.id,
    status === "suspended"
      ? "user_suspended"
      : "user_reactivated",
    {
      email: target.email,
      previous_status: target.status,
      new_status: status
    }
  );

  return reply({
    success: true,
    message: status === "suspended"
      ? "User suspended successfully"
      : "User reactivated successfully",
    user: {
      id: target.id,
      email: target.email,
      status
    }
  }, 200, headers);
}

// ==========================================
// ADMIN: DELETE USER ACCOUNT
// ==========================================

async function adminDeleteUser(
  request,
  env,
  headers,
  userId
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const actor = access.user;

  const target = await env.DB.prepare(`
    SELECT id, email, display_name, role
    FROM users
    WHERE id = ?
    LIMIT 1
  `).bind(userId).first();

  if (!target) {
    return reply({
      success: false,
      error: "User not found"
    }, 404, headers);
  }

  if (
    isSuperAdminEmail(target.email) ||
    target.role === "super_admin"
  ) {
    return reply({
      success: false,
      error: "Super Admin accounts are protected"
    }, 403, headers);
  }

  if (target.id === actor.id) {
    return reply({
      success: false,
      error: "You cannot delete your own account"
    }, 403, headers);
  }

  const now = new Date().toISOString();

  await env.DB.batch([
    env.DB.prepare(`
      DELETE FROM digital_page_items
      WHERE page_id IN (
        SELECT id FROM digital_pages WHERE user_id = ?
      )
    `).bind(userId),
    env.DB.prepare(`
      DELETE FROM digital_pages WHERE user_id = ?
    `).bind(userId),
    env.DB.prepare(`
      DELETE FROM qr_codes WHERE user_id = ?
    `).bind(userId),
    env.DB.prepare(`
      DELETE FROM subscriptions WHERE user_id = ?
    `).bind(userId),
    env.DB.prepare(`
      DELETE FROM subscription_extension_requests WHERE user_id = ?
    `).bind(userId),
    env.DB.prepare(`
      DELETE FROM sessions WHERE user_id = ?
    `).bind(userId),
    env.DB.prepare(`
      DELETE FROM audit_logs
      WHERE actor_user_id = ? OR target_user_id = ?
    `).bind(userId, userId),
    env.DB.prepare(`
      DELETE FROM users WHERE id = ?
    `).bind(userId),
    env.DB.prepare(`
      INSERT INTO audit_logs (
        id, actor_user_id, target_user_id,
        action, details_json, created_at
      )
      VALUES (?, ?, NULL, 'user_deleted', ?, ?)
    `).bind(
      crypto.randomUUID(),
      actor.id,
      JSON.stringify({
        email: target.email,
        display_name: target.display_name,
        deleted_user_id: target.id
      }),
      now
    )
  ]);

  return reply({
    success: true,
    message: "User account and related database records deleted"
  }, 200, headers);
}

// ==========================================
// ADMIN: SUBSCRIPTIONS LIST
// ==========================================

async function adminSubscriptions(
  request,
  env,
  headers,
  url
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const search = String(
    url.searchParams.get("search") || ""
  ).trim().slice(0, 100).toLowerCase();

  const status = String(
    url.searchParams.get("status") || ""
  ).trim().toLowerCase();

  const limitValue = Number(
    url.searchParams.get("limit") || 100
  );

  const offsetValue = Number(
    url.searchParams.get("offset") || 0
  );

  const limit = Number.isFinite(limitValue)
    ? Math.min(Math.max(Math.floor(limitValue), 1), 200)
    : 100;

  const offset = Number.isFinite(offsetValue)
    ? Math.max(Math.floor(offsetValue), 0)
    : 0;

  const conditions = [];
  const values = [];

  if (search) {
    conditions.push(`
      (
        instr(lower(users.email), ?) > 0
        OR instr(lower(users.display_name), ?) > 0
      )
    `);
    values.push(search, search);
  }

  if (
    status &&
    ["active", "cancelled", "expired", "paused"].includes(status)
  ) {
    conditions.push("subscriptions.status = ?");
    values.push(status);
  }

  const where = conditions.length
    ? "WHERE " + conditions.join(" AND ")
    : "";

  const result = await env.DB.prepare(`
    SELECT
      subscriptions.id,
      subscriptions.user_id,
      subscriptions.plan_code,
      subscriptions.source,
      subscriptions.status,
      subscriptions.starts_at,
      subscriptions.ends_at,
      subscriptions.auto_renew,
      subscriptions.provider,
      subscriptions.provider_subscription_id,
      subscriptions.granted_by_user_id,
      subscriptions.grant_reason,
      subscriptions.created_at,
      subscriptions.updated_at,
      users.email AS user_email,
      users.display_name AS user_name,
      grantor.email AS granted_by_email
    FROM subscriptions
    JOIN users
      ON users.id = subscriptions.user_id
    LEFT JOIN users AS grantor
      ON grantor.id = subscriptions.granted_by_user_id
    ${where}
    ORDER BY subscriptions.created_at DESC
    LIMIT ?
    OFFSET ?
  `).bind(
    ...values,
    limit,
    offset
  ).all();

  const countResult = await env.DB.prepare(`
    SELECT COUNT(*) AS total
    FROM subscriptions
    JOIN users
      ON users.id = subscriptions.user_id
    ${where}
  `).bind(...values).first();

  return reply({
    success: true,
    subscriptions: result.results || [],
    total: countResult?.total || 0,
    limit,
    offset
  }, 200, headers);
}

// ==========================================
// DIGITAL PAGE EXTENSION REQUESTS
// ==========================================

async function userExtensionRequests(request, env, headers) {
  const user = await currentUser(request, env);
  if (!user) return reply({ success: false, error: "Authentication required" }, 401, headers);

  if (request.method === "GET") {
    const result = await env.DB.prepare(`
      SELECT id, requested_days, message, status, admin_note, created_at, reviewed_at
      FROM subscription_extension_requests
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 20
    `).bind(user.id).all();
    const activeSubscription = await requireDigitalAccess(env, user.id);
    return reply({
      success: true,
      has_access: Boolean(activeSubscription),
      subscription_ends_at: activeSubscription?.ends_at || null,
      requests: result.results || []
    }, 200, headers);
  }

  if (request.method !== "POST") return reply({ success: false, error: "Method not allowed" }, 405, headers);

  const access = await requireDigitalAccess(env, user.id);
  if (access) return reply({ success: false, error: "Your subscription is already active" }, 409, headers);

  const body = await readJson(request);
  if (!body) return reply({ success: false, error: "Invalid JSON body" }, 400, headers);

  const requestedDays = Number(body.requested_days ?? 7);
  const message = String(body.message || "").trim().slice(0, 1000);
  if (!Number.isInteger(requestedDays) || requestedDays < 1 || requestedDays > 30) {
    return reply({ success: false, error: "Requested days must be between 1 and 30" }, 400, headers);
  }

  const pending = await env.DB.prepare(`
    SELECT id FROM subscription_extension_requests
    WHERE user_id = ? AND status = 'pending'
    LIMIT 1
  `).bind(user.id).first();
  if (pending) return reply({ success: false, error: "You already have a pending request" }, 409, headers);

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO subscription_extension_requests
      (id, user_id, requested_days, message, status, admin_note, created_at, updated_at)
    VALUES (?, ?, ?, ?, 'pending', '', ?, ?)
  `).bind(id, user.id, requestedDays, message, now, now).run();

  return reply({ success: true, request: { id, requested_days: requestedDays, message, status: "pending", created_at: now } }, 201, headers);
}

async function adminExtensionRequests(request, env, headers) {
  const access = await requireSuperAdmin(request, env);
  if (!access.ok) return reply({ success: false, error: access.error }, access.status, headers);

  const result = await env.DB.prepare(`
    SELECT r.id, r.user_id, r.requested_days, r.message, r.status,
           r.admin_note, r.created_at, r.reviewed_at,
           u.email AS user_email, u.display_name AS user_name
    FROM subscription_extension_requests r
    JOIN users u ON u.id = r.user_id
    ORDER BY CASE WHEN r.status = 'pending' THEN 0 ELSE 1 END, r.created_at DESC
    LIMIT 200
  `).all();
  return reply({ success: true, requests: result.results || [] }, 200, headers);
}

async function adminReviewExtensionRequest(request, env, headers, requestId) {
  const access = await requireSuperAdmin(request, env);
  if (!access.ok) return reply({ success: false, error: access.error }, access.status, headers);

  const body = await readJson(request);
  if (!body) return reply({ success: false, error: "Invalid JSON body" }, 400, headers);

  const decision = String(body.decision || "").toLowerCase();
  const adminNote = String(body.admin_note || "").trim().slice(0, 500);
  if (!["approve", "reject"].includes(decision)) {
    return reply({ success: false, error: "Decision must be approve or reject" }, 400, headers);
  }

  const row = await env.DB.prepare(`
    SELECT id, user_id, requested_days, status
    FROM subscription_extension_requests WHERE id = ? LIMIT 1
  `).bind(requestId).first();
  if (!row) return reply({ success: false, error: "Request not found" }, 404, headers);
  if (row.status !== "pending") return reply({ success: false, error: "This request has already been reviewed" }, 409, headers);

  const now = new Date().toISOString();
  const status = decision === "approve" ? "approved" : "rejected";

  if (decision === "approve") {
    const active = await requireDigitalAccess(env, row.user_id);
    if (active) return reply({ success: false, error: "User already has an active Pro or Business subscription" }, 409, headers);

    const subscriptionId = crypto.randomUUID();
    const endsAt = addDays(new Date(now), row.requested_days);
    await env.DB.batch([
      env.DB.prepare(`
        UPDATE subscription_extension_requests
        SET status = 'approved', admin_note = ?, reviewed_by = ?, reviewed_at = ?, updated_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(adminNote, access.user.id, now, now, requestId),
      env.DB.prepare(`
        INSERT INTO subscriptions
          (id, user_id, plan_code, source, status, starts_at, ends_at, auto_renew,
           provider, provider_subscription_id, granted_by_user_id, grant_reason, created_at, updated_at)
        SELECT ?, ?, 'pro', 'admin_granted', 'active', ?, ?, 0, NULL, NULL, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM subscription_extension_requests
          WHERE id = ? AND status = 'approved' AND reviewed_by = ? AND reviewed_at = ?
        )
      `).bind(subscriptionId, row.user_id, now, endsAt, access.user.id,
        "Approved free extension request", now, now, requestId, access.user.id, now)
    ]);
    await writeAudit(env, access.user.id, row.user_id, "digital_page_extension_approved", {
      request_id: requestId, subscription_id: subscriptionId, duration_days: row.requested_days, admin_note: adminNote
    });
  } else {
    const updated = await env.DB.prepare(`
      UPDATE subscription_extension_requests
      SET status = 'rejected', admin_note = ?, reviewed_by = ?, reviewed_at = ?, updated_at = ?
      WHERE id = ? AND status = 'pending'
    `).bind(adminNote, access.user.id, now, now, requestId).run();
    if (!updated.meta?.changes) return reply({ success: false, error: "This request has already been reviewed" }, 409, headers);
    await writeAudit(env, access.user.id, row.user_id, "digital_page_extension_rejected", { request_id: requestId, admin_note: adminNote });
  }

  return reply({ success: true, status }, 200, headers);
}

// ==========================================
// ADMIN: FIND USER
// ==========================================

async function findAdminTarget(env, userId) {
  return await env.DB.prepare(`
    SELECT id, email, display_name, role, status
    FROM users
    WHERE id = ?
    LIMIT 1
  `).bind(userId).first();
}

// ==========================================
// ADMIN: CALCULATE NEXT SUBSCRIPTION START
// ==========================================

async function nextSubscriptionStart(env, userId) {
  const now = new Date();
  const nowIso = now.toISOString();

  const existing = await env.DB.prepare(`
    SELECT id, ends_at, starts_at, status
    FROM subscriptions
    WHERE user_id = ?
      AND status = 'active'
      AND (ends_at IS NULL OR ends_at > ?)
    ORDER BY
      CASE WHEN ends_at IS NULL THEN 1 ELSE 0 END DESC,
      ends_at DESC
  `).bind(
    userId,
    nowIso
  ).all();

  const rows = existing.results || [];

  // An active unlimited subscription already exists.
  if (rows.some(row => row.ends_at === null)) {
    return {
      ok: false,
      error: "This user already has an active unlimited subscription."
    };
  }

  let start = now;

  for (const row of rows) {
    if (row.ends_at) {
      const end = new Date(row.ends_at);

      if (!Number.isNaN(end.getTime()) && end > start) {
        start = end;
      }
    }
  }

  return {
    ok: true,
    startsAt: start.toISOString()
  };
}

// ==========================================
// ADMIN: GRANT FREE SUBSCRIPTION
// ==========================================

async function adminGrantSubscription(
  request,
  env,
  headers
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const actor = access.user;
  const body = await readJson(request);

  if (!body) {
    return reply({
      success: false,
      error: "Invalid JSON body"
    }, 400, headers);
  }

  const userId = String(body.user_id || "");
  const planCode = String(body.plan_code || "").toLowerCase();
  const durationDays = body.duration_days;
  const reason = String(body.reason || "").trim().slice(0, 500);

  if (!validUuid(userId)) {
    return reply({
      success: false,
      error: "Invalid user ID"
    }, 400, headers);
  }

  if (!ADMIN_PLANS.includes(planCode)) {
    return reply({
      success: false,
      error: "Plan must be pro or business"
    }, 400, headers);
  }

  if (!validDuration(durationDays)) {
    return reply({
      success: false,
      error: "Duration must be a number of days or null for unlimited"
    }, 400, headers);
  }

  if (!reason) {
    return reply({
      success: false,
      error: "Please provide a reason for this free grant"
    }, 400, headers);
  }

  const target = await findAdminTarget(env, userId);

  if (!target) {
    return reply({
      success: false,
      error: "User not found"
    }, 404, headers);
  }

  const startResult = await nextSubscriptionStart(env, userId);

  if (!startResult.ok) {
    return reply({
      success: false,
      error: startResult.error
    }, 409, headers);
  }

  const startsAt = startResult.startsAt;
  const endsAt = durationDays === null
    ? null
    : addDays(new Date(startsAt), durationDays);

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(`
    INSERT INTO subscriptions (
      id,
      user_id,
      plan_code,
      source,
      status,
      starts_at,
      ends_at,
      auto_renew,
      provider,
      provider_subscription_id,
      granted_by_user_id,
      grant_reason,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, 'admin_granted', 'active', ?, ?, 0, NULL, NULL, ?, ?, ?, ?)
  `).bind(
    id,
    userId,
    planCode,
    startsAt,
    endsAt,
    actor.id,
    reason,
    now,
    now
  ).run();

  await writeAudit(
    env,
    actor.id,
    userId,
    "subscription_free_granted",
    {
      subscription_id: id,
      plan_code: planCode,
      duration_days: durationDays,
      starts_at: startsAt,
      ends_at: endsAt,
      reason
    }
  );

  return reply({
    success: true,
    message: "Free subscription granted successfully",
    subscription: {
      id,
      user_id: userId,
      user_email: target.email,
      plan_code: planCode,
      source: "admin_granted",
      status: "active",
      starts_at: startsAt,
      ends_at: endsAt,
      auto_renew: 0,
      grant_reason: reason
    }
  }, 201, headers);
}

// ==========================================
// ADMIN: EXTEND SUBSCRIPTION FOR FREE
// ==========================================

async function adminExtendSubscription(
  request,
  env,
  headers,
  subscriptionId
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const actor = access.user;
  const body = await readJson(request);

  if (!body) {
    return reply({
      success: false,
      error: "Invalid JSON body"
    }, 400, headers);
  }

  const durationDays = body.duration_days;
  const reason = String(body.reason || "").trim().slice(0, 500);

  if (!validDuration(durationDays) || durationDays === null) {
    return reply({
      success: false,
      error: "Extension duration must be between 1 and 36500 days"
    }, 400, headers);
  }

  if (!reason) {
    return reply({
      success: false,
      error: "Please provide a reason for this extension"
    }, 400, headers);
  }

  const original = await env.DB.prepare(`
    SELECT
      id,
      user_id,
      plan_code,
      source,
      status,
      starts_at,
      ends_at
    FROM subscriptions
    WHERE id = ?
    LIMIT 1
  `).bind(subscriptionId).first();

  if (!original) {
    return reply({
      success: false,
      error: "Subscription not found"
    }, 404, headers);
  }

  if (!ADMIN_PLANS.includes(original.plan_code)) {
    return reply({
      success: false,
      error: "Only Pro or Business subscriptions can be extended"
    }, 400, headers);
  }

  const target = await findAdminTarget(env, original.user_id);

  if (!target) {
    return reply({
      success: false,
      error: "Subscription user not found"
    }, 404, headers);
  }

  const startResult = await nextSubscriptionStart(
    env,
    original.user_id
  );

  if (!startResult.ok) {
    return reply({
      success: false,
      error: startResult.error
    }, 409, headers);
  }

  const startsAt = startResult.startsAt;
  const endsAt = addDays(
    new Date(startsAt),
    durationDays
  );

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  // A free extension is a separate record.
  // The original paid subscription and its payment history are untouched.
  await env.DB.prepare(`
    INSERT INTO subscriptions (
      id,
      user_id,
      plan_code,
      source,
      status,
      starts_at,
      ends_at,
      auto_renew,
      provider,
      provider_subscription_id,
      granted_by_user_id,
      grant_reason,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, 'admin_granted', 'active', ?, ?, 0, NULL, NULL, ?, ?, ?, ?)
  `).bind(
    id,
    original.user_id,
    original.plan_code,
    startsAt,
    endsAt,
    actor.id,
    reason,
    now,
    now
  ).run();

  await writeAudit(
    env,
    actor.id,
    original.user_id,
    "subscription_free_extension",
    {
      original_subscription_id: original.id,
      extension_subscription_id: id,
      original_source: original.source,
      plan_code: original.plan_code,
      duration_days: durationDays,
      starts_at: startsAt,
      ends_at: endsAt,
      reason
    }
  );

  return reply({
    success: true,
    message: "Free extension added successfully",
    original_subscription_id: original.id,
    extension: {
      id,
      user_id: original.user_id,
      user_email: target.email,
      plan_code: original.plan_code,
      source: "admin_granted",
      status: "active",
      starts_at: startsAt,
      ends_at: endsAt,
      auto_renew: 0,
      grant_reason: reason
    }
  }, 201, headers);
}

// ==========================================
// ADMIN: UPDATE SUBSCRIPTION
// ==========================================

async function adminUpdateSubscription(
  request,
  env,
  headers,
  subscriptionId
) {
  const access = await requireSuperAdmin(request, env);

  if (!access.ok) {
    return reply({
      success: false,
      error: access.error
    }, access.status, headers);
  }

  const actor = access.user;
  const body = await readJson(request);

  if (!body) {
    return reply({
      success: false,
      error: "Invalid JSON body"
    }, 400, headers);
  }

  const action = String(body.action || "").toLowerCase();

  const subscription = await env.DB.prepare(`
    SELECT
      id,
      user_id,
      plan_code,
      source,
      status,
      starts_at,
      ends_at,
      auto_renew
    FROM subscriptions
    WHERE id = ?
    LIMIT 1
  `).bind(subscriptionId).first();

  if (!subscription) {
    return reply({
      success: false,
      error: "Subscription not found"
    }, 404, headers);
  }

  const now = new Date().toISOString();
  let message = "";
  let auditAction = "";
  let auditDetails = {};

  if (action === "pause") {
    if (subscription.status !== "active") {
      return reply({
        success: false,
        error: "Only active subscriptions can be paused"
      }, 409, headers);
    }

    await env.DB.prepare(`
      UPDATE subscriptions
      SET status = 'paused',
          updated_at = ?
      WHERE id = ?
    `).bind(now, subscriptionId).run();

    message = "Subscription paused";
    auditAction = "subscription_paused";
  } else if (action === "reactivate") {
    if (subscription.status !== "paused") {
      return reply({
        success: false,
        error: "Only paused subscriptions can be reactivated"
      }, 409, headers);
    }

    if (
      subscription.ends_at &&
      subscription.ends_at <= now
    ) {
      return reply({
        success: false,
        error: "This subscription has expired. Add a free extension instead."
      }, 409, headers);
    }

    await env.DB.prepare(`
      UPDATE subscriptions
      SET status = 'active',
          updated_at = ?
      WHERE id = ?
    `).bind(now, subscriptionId).run();

    message = "Subscription reactivated";
    auditAction = "subscription_reactivated";
  } else if (action === "end_now") {
    if (subscription.status === "expired") {
      return reply({
        success: false,
        error: "Subscription is already ended"
      }, 409, headers);
    }

    await env.DB.prepare(`
      UPDATE subscriptions
      SET status = 'expired',
          ends_at = ?,
          auto_renew = 0,
          updated_at = ?
      WHERE id = ?
    `).bind(
      now,
      now,
      subscriptionId
    ).run();

    message = "Subscription ended immediately";
    auditAction = "subscription_ended";
  } else if (action === "change_plan") {
    const planCode = String(
      body.plan_code || ""
    ).toLowerCase();

    if (!ALLOWED_PLANS.includes(planCode)) {
      return reply({
        success: false,
        error: "Invalid plan"
      }, 400, headers);
    }

    const oldPlan = subscription.plan_code;

    await env.DB.prepare(`
      UPDATE subscriptions
      SET plan_code = ?,
          updated_at = ?
      WHERE id = ?
    `).bind(
      planCode,
      now,
      subscriptionId
    ).run();

    message = "Subscription plan changed";
    auditAction = "subscription_plan_changed";
    auditDetails = {
      old_plan: oldPlan,
      new_plan: planCode
    };
  } else {
    return reply({
      success: false,
      error: "Action must be pause, reactivate, end_now, or change_plan"
    }, 400, headers);
  }

  await writeAudit(
    env,
    actor.id,
    subscription.user_id,
    auditAction,
    {
      subscription_id: subscriptionId,
      previous_status: subscription.status,
      action,
      ...auditDetails
    }
  );

  const updated = await env.DB.prepare(`
    SELECT
      id,
      user_id,
      plan_code,
      source,
      status,
      starts_at,
      ends_at,
      auto_renew,
      grant_reason,
      updated_at
    FROM subscriptions
    WHERE id = ?
    LIMIT 1
  `).bind(subscriptionId).first();

  return reply({
    success: true,
    message,
    subscription: updated
  }, 200, headers);
}

// ==========================================
// MAIN API ROUTER
// ==========================================

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const headers = corsHeaders(origin);
    const url = new URL(request.url);

    if (origin && origin !== ALLOWED_ORIGIN) {
      return reply({
        success: false,
        error: "Origin not allowed"
      }, 403, headers);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers
      });
    }

    if (!env.DB) {
      return reply({
        success: false,
        error: "Database unavailable"
      }, 503, headers);
    }

    try {

      // --------------------------------------
      // API STATUS
      // --------------------------------------

      if (
        url.pathname === "/" &&
        request.method === "GET"
      ) {
        return reply({
          name: "COLONY QR API",
          status: "running"
        }, 200, headers);
      }

      if (
        url.pathname === "/api/health" &&
        request.method === "GET"
      ) {
        await env.DB.prepare("SELECT 1").first();

        return reply({
          success: true,
          api: "online",
          database: "connected"
        }, 200, headers);
      }

      // --------------------------------------
      // GOOGLE LOGIN NONCE
      // --------------------------------------

      if (
        url.pathname === "/api/auth/google/nonce" &&
        request.method === "GET"
      ) {
        const nonce = randomHex(32);
        const nonceHash = await sha256(nonce);

        const expiresAt = new Date(
          Date.now() + 5 * 60 * 1000
        ).toISOString();

        await env.DB.prepare(`
          DELETE FROM oauth_nonces
          WHERE expires_at <= ?
        `).bind(
          new Date().toISOString()
        ).run();

        await env.DB.prepare(`
          INSERT INTO oauth_nonces (
            nonce_hash,
            expires_at
          )
          VALUES (?, ?)
        `).bind(
          nonceHash,
          expiresAt
        ).run();

        return reply({
          success: true,
          nonce,
          expires_in: 300
        }, 200, headers);
      }

      // --------------------------------------
      // GOOGLE LOGIN
      // --------------------------------------

      if (
        url.pathname === "/api/auth/google" &&
        request.method === "POST"
      ) {
        return await googleLogin(request, env, headers);
      }

      // --------------------------------------
      // REGISTER
      // --------------------------------------

      if (
        url.pathname === "/api/auth/register" &&
        request.method === "POST"
      ) {
        const body = await readJson(request);

        if (!body) {
          return reply({
            success: false,
            error: "Invalid JSON body"
          }, 400, headers);
        }

        const email = normalizeEmail(body.email);
        const displayName = String(
          body.display_name || ""
        ).trim();

        const password = String(body.password || "");

        if (
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
          email.length > 254
        ) {
          return reply({
            success: false,
            error: "Invalid email address"
          }, 400, headers);
        }

        if (
          displayName.length < 2 ||
          displayName.length > 80
        ) {
          return reply({
            success: false,
            error: "Name must be 2 to 80 characters"
          }, 400, headers);
        }

        if (
          password.length < 12 ||
          password.length > 128
        ) {
          return reply({
            success: false,
            error: "Password must be 12 to 128 characters"
          }, 400, headers);
        }

        const existing = await env.DB.prepare(`
          SELECT id
          FROM users
          WHERE email = ?
          LIMIT 1
        `).bind(email).first();

        if (existing) {
          return reply({
            success: false,
            error: "An account with this email already exists"
          }, 409, headers);
        }

        const existingUsername = await env.DB.prepare(`
          SELECT id
          FROM users
          WHERE lower(trim(display_name)) = lower(trim(?))
          LIMIT 1
        `).bind(displayName).first();

        if (existingUsername) {
          return reply({
            success: false,
            error: "Username already taken. Please choose another."
          }, 409, headers);
        }

        const userId = crypto.randomUUID();
        const salt = randomHex(16);

        const passwordHash = await hashPassword(
          password,
          salt
        );

        await env.DB.prepare(`
          INSERT INTO users (
            id,
            email,
            display_name,
            password_hash,
            password_salt,
            password_iterations,
            role,
            status
          )
          VALUES (?, ?, ?, ?, ?, ?, 'user', 'active')
        `).bind(
          userId,
          email,
          displayName,
          passwordHash,
          salt,
          PASSWORD_ITERATIONS
        ).run();

        await grantSignupTrial(env, userId);

        const token = await createSession(env, userId);

        headers["Set-Cookie"] = sessionCookie(
          token,
          SESSION_DAYS * 86400
        );

        return reply({
          success: true,
          message: "Account created successfully",
          user: {
            id: userId,
            email,
            display_name: displayName,
            role: "user"
          }
        }, 201, headers);
      }

      // --------------------------------------
      // PASSWORD LOGIN
      // --------------------------------------

      if (
        url.pathname === "/api/auth/login" &&
        request.method === "POST"
      ) {
        const body = await readJson(request);

        if (!body) {
          return reply({
            success: false,
            error: "Invalid JSON body"
          }, 400, headers);
        }

        const email = normalizeEmail(body.email);
        const password = String(body.password || "");

        if (
          password.length > 128 ||
          !email ||
          email.length > 254
        ) {
          return reply({
            success: false,
            error: "Invalid email or password"
          }, 401, headers);
        }

        const user = await env.DB.prepare(`
          SELECT
            id,
            email,
            display_name,
            password_hash,
            password_salt,
            password_iterations,
            role,
            status
          FROM users
          WHERE email = ?
          LIMIT 1
        `).bind(email).first();

        if (!user || user.status !== "active") {
          return reply({
            success: false,
            error: "Invalid email or password"
          }, 401, headers);
        }

        if (
          !Number.isInteger(user.password_iterations) ||
          user.password_iterations < 1 ||
          user.password_iterations > 100000
        ) {
          return reply({
            success: false,
            error: "Account password needs a security update"
          }, 401, headers);
        }

        const key = await crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(password),
          "PBKDF2",
          false,
          ["deriveBits"]
        );

        const bits = await crypto.subtle.deriveBits({
          name: "PBKDF2",
          salt: fromHex(user.password_salt),
          iterations: user.password_iterations,
          hash: "SHA-256"
        }, key, 256);

        const suppliedHash = hex(new Uint8Array(bits));

        if (!safeEqual(suppliedHash, user.password_hash)) {
          return reply({
            success: false,
            error: "Invalid email or password"
          }, 401, headers);
        }

        let role = user.role;

        if (isSuperAdminEmail(user.email)) {
          role = "super_admin";
        } else if (role === "super_admin") {
          role = "user";
        }

        await env.DB.prepare(`
          UPDATE users
          SET role = ?,
              last_login_at = ?
          WHERE id = ?
        `).bind(
          role,
          new Date().toISOString(),
          user.id
        ).run();

        const token = await createSession(env, user.id);

        headers["Set-Cookie"] = sessionCookie(
          token,
          SESSION_DAYS * 86400
        );

        return reply({
          success: true,
          user: {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            role
          }
        }, 200, headers);
      }

      // --------------------------------------
      // CURRENT ACCOUNT
      // --------------------------------------

      if (
        url.pathname === "/api/auth/me" &&
        request.method === "GET"
      ) {
        const user = await currentUser(request, env);

        if (!user) {
          return reply({
            success: false,
            user: null
          }, 401, headers);
        }

        const subscription = await requireDigitalAccess(env, user.id);

        return reply({
          success: true,
          user: {
            ...user,
            subscription
          }
        }, 200, headers);
      }

      // --------------------------------------
      // LOGOUT
      // --------------------------------------

      if (
        url.pathname === "/api/auth/logout" &&
        request.method === "POST"
      ) {
        const token = getCookie(request, "colony_session");

        if (
          token &&
          /^[a-f0-9]{64}$/.test(token)
        ) {
          await env.DB.prepare(`
            DELETE FROM sessions
            WHERE token_hash = ?
          `).bind(await sha256(token)).run();
        }

        headers["Set-Cookie"] = sessionCookie("", 0);

        return reply({
          success: true,
          message: "Logged out"
        }, 200, headers);
      }

      // ======================================
      // DIGITAL PAGE EXTENSION REQUESTS
      // ======================================

      if (
        url.pathname === "/api/digital-page-extension-requests" &&
        ["GET", "POST"].includes(request.method)
      ) {
        return await userExtensionRequests(request, env, headers);
      }

      if (
        url.pathname === "/api/admin/digital-page-extension-requests" &&
        request.method === "GET"
      ) {
        return await adminExtensionRequests(request, env, headers);
      }

      const extensionReviewMatch = url.pathname.match(
        /^\/api\/admin\/digital-page-extension-requests\/([a-f0-9-]{36})\/review$/i
      );
      if (extensionReviewMatch && request.method === "POST") {
        return await adminReviewExtensionRequest(request, env, headers, extensionReviewMatch[1]);
      }

      // ======================================
      // SUPER ADMIN ROUTES
      // ======================================

      if (
        url.pathname === "/api/admin/overview" &&
        request.method === "GET"
      ) {
        return await adminOverview(request, env, headers);
      }

      if (
        url.pathname === "/api/admin/users" &&
        request.method === "GET"
      ) {
        return await adminUsers(request, env, headers, url);
      }

      const adminDeleteMatch = url.pathname.match(
        /^\/api\/admin\/users\/([a-f0-9-]{36})$/i
      );

      if (
        adminDeleteMatch &&
        request.method === "DELETE"
      ) {
        return await adminDeleteUser(
          request,
          env,
          headers,
          adminDeleteMatch[1]
        );
      }

      const adminStatusMatch = url.pathname.match(
        /^\/api\/admin\/users\/([a-f0-9-]{36})\/status$/i
      );

      if (
        adminStatusMatch &&
        request.method === "PATCH"
      ) {
        return await adminChangeUserStatus(
          request,
          env,
          headers,
          adminStatusMatch[1]
        );
      }

      // --------------------------------------
      // ADMIN: QR CODES LIST
      // --------------------------------------

      if (
        url.pathname === "/api/admin/qr-codes" &&
        request.method === "GET"
      ) {
        return await adminQrCodes(
          request,
          env,
          headers,
          url
        );
      }

      // --------------------------------------
      // SUBSCRIPTIONS: LIST
      // --------------------------------------

      if (
        url.pathname === "/api/admin/subscriptions" &&
        request.method === "GET"
      ) {
        return await adminSubscriptions(
          request,
          env,
          headers,
          url
        );
      }

      // --------------------------------------
      // SUBSCRIPTIONS: GRANT FREE
      // --------------------------------------

      if (
        url.pathname === "/api/admin/subscriptions/grant" &&
        request.method === "POST"
      ) {
        return await adminGrantSubscription(
          request,
          env,
          headers
        );
      }

      // --------------------------------------
      // SUBSCRIPTIONS: EXTEND FREE
      // --------------------------------------

      const extendMatch = url.pathname.match(
        /^\/api\/admin\/subscriptions\/([a-f0-9-]{36})\/extend$/i
      );

      if (
        extendMatch &&
        request.method === "POST"
      ) {
        return await adminExtendSubscription(
          request,
          env,
          headers,
          extendMatch[1]
        );
      }

      // --------------------------------------
      // SUBSCRIPTIONS: UPDATE
      // --------------------------------------

      const subscriptionMatch = url.pathname.match(
        /^\/api\/admin\/subscriptions\/([a-f0-9-]{36})$/i
      );

      if (
        subscriptionMatch &&
        request.method === "PATCH"
      ) {
        return await adminUpdateSubscription(
          request,
          env,
          headers,
          subscriptionMatch[1]
        );
      }

      // --------------------------------------
      // IMAGEKIT UPLOAD AUTHENTICATION
      // --------------------------------------

      if (
        url.pathname === "/api/imagekit/auth" &&
        request.method === "GET"
      ) {
        return await imageKitAuth(request, env, headers);
      }

      // --------------------------------------
      // DIGITAL BUSINESS PAGES
      // --------------------------------------

      if (
        url.pathname.startsWith("/api/digital-pages") ||
        url.pathname.startsWith("/api/digital-page-items") ||
        url.pathname.startsWith("/api/public/digital-pages")
      ) {
        return await handleDigitalPages(request, env, headers, url);
      }

      // ======================================
      // SAVED QR CODE ROUTES
      // ======================================

      if (
        url.pathname === "/api/qr" ||
        (
          url.pathname.startsWith("/api/qr/") &&
          request.method === "DELETE"
        )
      ) {
        return await handleQrRequest(
          request,
          env,
          headers,
          url
        );
      }

      return reply({
        success: false,
        error: "Route not found"
      }, 404, headers);

    } catch (error) {
      console.error(
        "COLONY QR API error:",
        error
      );

      return reply({
        success: false,
        error: "Server error. Please try again."
      }, 500, headers);
    }
  }
};