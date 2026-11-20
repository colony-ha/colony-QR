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

        return reply({
          success: true,
          user
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