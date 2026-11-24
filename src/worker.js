// BitBalance Worker — авторизация, персональная история и память ИИ.
// Cloudflare настройки:
//   D1 binding: DB
//   Secret: GEMINI_API_KEY
//
// Важно:
// - Создаются только таблицы bb_*; старые таблицы не удаляются.
// - После публикации проверьте GET /api/health.
// - Для сайта на том же origin cookie будет работать автоматически.
// - Если Pages и Worker находятся на разных доменах, потребуется отдельная
//   настройка CORS/cookie; этот файл намеренно не открывает CORS всем сайтам.

const COOKIE_NAME = "bb_session";
const SESSION_DAYS = 30;
const MAX_QUESTION = 5000;
const MAX_CONTEXT = 30000;
const MAX_MEMORY = 12000;
const MAX_HISTORY = 100;

const SYSTEM_PROMPT =
  "Ты финансовый AI-советник BitBalance. Отвечай на русском языке. " +
  "Проверяй финансовые расчёты. Не выдумывай доходы, расходы, долги и даты. " +
  "Разделяй подтверждённые данные и предположения. Если информации недостаточно, прямо скажи об этом. " +
  "Используй только переданный контекст и персональную память текущего аккаунта. " +
  "Алгоритмы приложения: Баланс = копилка (свободные + накопления) + подушка - долги. " +
  "Подушка: цель = выбранная база (средние траты/рекомендуемые/минимальные) x число месяцев. " +
  "Рекомендация пополнения подушки = остаток до цели / дни периода (месяцы*30). Если подушка >= цели, рекомендация 0. " +
  "Здоровье денег: обязательные расходы не выше needsMax %, остаток не ниже saveMin %, запас не меньше runwayMin дней, долги закрыть за debtMonths месяцев. " +
  "При вопросе о рекомендации подушки объясни: цель, текущий остаток, остаток до цели, число дней периода и рекомендацию в день.";

function responseJson(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    }
  });
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const item of header.split(";")) {
    const index = item.indexOf("=");
    if (index === -1) continue;
    if (item.slice(0, index).trim() === name) {
      return decodeURIComponent(item.slice(index + 1).trim());
    }
  }
  return "";
}

function makeCookie(token) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}

function clearCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomToken(length = 32) {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(length)));
}

async function sha256(value) {
  const result = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(result));
}

async function hashPassword(password, existingSalt) {
  const salt = existingSalt
    ? base64UrlDecode(existingSalt)
    : crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );

  return {
    salt: base64UrlEncode(salt),
    hash: base64UrlEncode(new Uint8Array(bits))
  };
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

async function ensureSchema(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS bb_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS bb_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES bb_users(id) ON DELETE CASCADE
  )`).run();

  await db.prepare("CREATE INDEX IF NOT EXISTS bb_sessions_user_idx ON bb_sessions(user_id)").run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS bb_ai_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES bb_users(id) ON DELETE CASCADE
  )`).run();

  await db.prepare("CREATE INDEX IF NOT EXISTS bb_ai_messages_user_idx ON bb_ai_messages(user_id, id)").run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS bb_ai_memory (
    user_id TEXT PRIMARY KEY,
    content TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES bb_users(id) ON DELETE CASCADE
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS bb_login_attempts (
    attempt_key TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    window_started_at TEXT NOT NULL,
    blocked_until TEXT
  )`).run();

  // Полное финансовое состояние каждого аккаунта хранится отдельно.
  await db.prepare(`CREATE TABLE IF NOT EXISTS bb_user_data (
    user_id TEXT PRIMARY KEY,
    data_json TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES bb_users(id) ON DELETE CASCADE
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS bb_push_subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    keys_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES bb_users(id) ON DELETE CASCADE
  )`).run();
  await db.prepare("CREATE INDEX IF NOT EXISTS bb_push_subscriptions_user_idx ON bb_push_subscriptions(user_id)").run();
  try { await db.prepare("ALTER TABLE bb_users ADD COLUMN telegram_user_id TEXT").run(); } catch (e) {}
}

function originAllowed(request, url) {
  const origin = request.headers.get("Origin");
  // Для браузерных запросов Origin обязателен и должен совпадать с Worker origin.
  // Запросы без Origin оставлены для совместимости с серверными клиентами.
  return !origin || origin === url.origin;
}

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

async function makeAttemptKey(email, ip) {
  return sha256(`${email.toLowerCase()}|${ip}`);
}

async function isLoginBlocked(db, key) {
  const row = await db.prepare(
    "SELECT window_started_at, blocked_until FROM bb_login_attempts WHERE attempt_key = ?"
  ).bind(key).first();

  if (!row) return false;
  const now = Date.now();

  if (row.blocked_until && Date.parse(row.blocked_until) > now) return true;

  const age = now - Date.parse(row.window_started_at);
  if (!Number.isFinite(age) || age > 15 * 60 * 1000) {
    await db.prepare("DELETE FROM bb_login_attempts WHERE attempt_key = ?").bind(key).run();
  }

  return false;
}

async function registerLoginFailure(db, key) {
  const now = new Date();
  const previous = await db.prepare(
    "SELECT failures, window_started_at FROM bb_login_attempts WHERE attempt_key = ?"
  ).bind(key).first();

  let failures = 1;
  let windowStarted = now.toISOString();

  if (previous && now.getTime() - Date.parse(previous.window_started_at) <= 15 * 60 * 1000) {
    failures = Number(previous.failures || 0) + 1;
    windowStarted = previous.window_started_at;
  }

  const blockedUntil = failures >= 8
    ? new Date(now.getTime() + 15 * 60 * 1000).toISOString()
    : null;

  await db.prepare(`INSERT INTO bb_login_attempts
    (attempt_key, failures, window_started_at, blocked_until)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(attempt_key) DO UPDATE SET
      failures = excluded.failures,
      window_started_at = excluded.window_started_at,
      blocked_until = excluded.blocked_until`
  ).bind(key, failures, windowStarted, blockedUntil).run();
}

async function clearLoginFailures(db, key) {
  await db.prepare("DELETE FROM bb_login_attempts WHERE attempt_key = ?").bind(key).run();
}

async function createSession(db, userId) {
  const token = randomToken(32);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_DAYS * 86400000).toISOString();

  await db.prepare(
    "INSERT INTO bb_sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
  ).bind(await sha256(token), userId, expiresAt, now.toISOString()).run();

  return token;
}

async function findAuthenticatedUser(request, db) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return null;

  return db.prepare(`
    SELECT u.id, u.email
    FROM bb_sessions s
    INNER JOIN bb_users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).bind(await sha256(token), new Date().toISOString()).first();
}

async function parseJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function authHandler(request, env, url, pathname, diagnostic) {
  const db = env.DB;
  diagnostic.stage = "auth_handler";

  if (pathname === "/api/auth/me" && request.method === "GET") {
    const user = await findAuthenticatedUser(request, db);
    return responseJson({
      authenticated: Boolean(user),
      user: user ? { id: user.id, email: user.email } : null
    });
  }

  if (pathname === "/api/auth/logout" && request.method === "POST") {
    if (!originAllowed(request, url)) {
      return responseJson({ error: "Недопустимый источник запроса" }, 403);
    }

    const token = getCookie(request, COOKIE_NAME);
    if (token) {
      await db.prepare("DELETE FROM bb_sessions WHERE token_hash = ?")
        .bind(await sha256(token)).run();
    }

    return responseJson({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }

  if (
    (pathname !== "/api/auth/register" && pathname !== "/api/auth/login") ||
    request.method !== "POST"
  ) {
    return responseJson({ error: "Метод не поддерживается" }, 405);
  }

  if (!originAllowed(request, url)) {
    return responseJson({ error: "Недопустимый источник запроса" }, 403);
  }

  diagnostic.stage = "auth_parse_body";
  const body = await parseJson(request);
  if (!body) return responseJson({ error: "Некорректный JSON" }, 400);

  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return responseJson({ error: "Укажи корректный email" }, 400);
  }

  if (password.length < 10 || password.length > 200) {
    return responseJson({ error: "Пароль должен содержать от 10 до 200 символов" }, 400);
  }

  diagnostic.stage = "auth_make_attempt_key";
  const attemptKey = await makeAttemptKey(email, getClientIp(request));
  if (await isLoginBlocked(db, attemptKey)) {
    return responseJson({ error: "Слишком много попыток. Попробуй позже." }, 429);
  }

  if (pathname === "/api/auth/register") {
    diagnostic.stage = "register_check_existing_user";
    const existing = await db.prepare("SELECT id FROM bb_users WHERE email = ?")
      .bind(email).first();

    if (existing) {
      return responseJson({ error: "Аккаунт с таким email уже существует" }, 409);
    }

    const userId = randomToken(18);
    const now = new Date().toISOString();

    diagnostic.stage = "register_hash_password";
    const credentials = await hashPassword(password);

    diagnostic.stage = "register_insert_user";
    try {
      await db.prepare(`INSERT INTO bb_users
        (id, email, password_hash, password_salt, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(userId, email, credentials.hash, credentials.salt, now, now).run();
    } catch (error) {
      return responseJson({
        error: "Не удалось создать аккаунт",
        stage: diagnostic.stage,
        details: String(error?.message || error)
      }, 409);
    }

    diagnostic.stage = "register_create_session";
    const token = await createSession(db, userId);

    diagnostic.stage = "register_clear_login_failures";
    await clearLoginFailures(db, attemptKey);

    return responseJson(
      { ok: true, user: { id: userId, email } },
      201,
      { "Set-Cookie": makeCookie(token) }
    );
  }

  const user = await db.prepare(
    "SELECT id, email, password_hash, password_salt FROM bb_users WHERE email = ?"
  ).bind(email).first();

  if (!user) {
    await registerLoginFailure(db, attemptKey);
    return responseJson({ error: "Неверный email или пароль" }, 401);
  }

  const calculated = await hashPassword(password, user.password_salt);
  if (!timingSafeEqual(calculated.hash, user.password_hash)) {
    await registerLoginFailure(db, attemptKey);
    return responseJson({ error: "Неверный email или пароль" }, 401);
  }

  await clearLoginFailures(db, attemptKey);
  const token = await createSession(db, user.id);

  return responseJson(
    { ok: true, user: { id: user.id, email: user.email } },
    200,
    { "Set-Cookie": makeCookie(token) }
  );
}

async function historyHandler(request, user, db) {
  if (request.method !== "GET") {
    return responseJson({ error: "Method not allowed" }, 405);
  }

  const rawLimit = Number(new URL(request.url).searchParams.get("limit") || 50);
  const limit = Math.max(1, Math.min(MAX_HISTORY, Number.isFinite(rawLimit) ? rawLimit : 50));

  const result = await db.prepare(`
    SELECT id, role, content, created_at
    FROM bb_ai_messages
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT ?
  `).bind(user.id, limit).all();

  return responseJson({ messages: (result.results || []).reverse() });
}

async function memoryHandler(request, user, db) {
  if (request.method === "GET") {
    const row = await db.prepare(
      "SELECT content, updated_at FROM bb_ai_memory WHERE user_id = ?"
    ).bind(user.id).first();

    return responseJson({
      memory: row?.content || "",
      updated_at: row?.updated_at || null
    });
  }

  if (request.method === "PUT") {
    const body = await parseJson(request);
    if (!body || typeof body.content !== "string") {
      return responseJson({ error: "Передай текст памяти в поле content" }, 400);
    }

    const content = body.content.trim();
    if (content.length > MAX_MEMORY) {
      return responseJson({ error: `Память не должна превышать ${MAX_MEMORY} символов` }, 413);
    }

    const updatedAt = new Date().toISOString();
    await db.prepare(`INSERT INTO bb_ai_memory (user_id, content, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        content = excluded.content,
        updated_at = excluded.updated_at`
    ).bind(user.id, content, updatedAt).run();

    return responseJson({ ok: true, memory: content, updated_at: updatedAt });
  }

  if (request.method === "DELETE") {
    await db.prepare("DELETE FROM bb_ai_memory WHERE user_id = ?").bind(user.id).run();
    return responseJson({ ok: true });
  }

  return responseJson({ error: "Method not allowed" }, 405);
}

async function loadPersonalContext(db, userId) {
  const memoryRow = await db.prepare(
    "SELECT content FROM bb_ai_memory WHERE user_id = ?"
  ).bind(userId).first();

  const historyRows = await db.prepare(`
    SELECT role, content
    FROM bb_ai_messages
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 12
  `).bind(userId).all();

  return {
    memory: memoryRow?.content || "",
    recent_history: (historyRows.results || []).reverse().map(row => ({
      role: row.role,
      content: String(row.content).slice(0, 5000)
    }))
  };
}

async function saveAiMessages(db, userId, question, answer) {
  const createdAt = new Date().toISOString();

  await db.batch([
    db.prepare(
      "INSERT INTO bb_ai_messages (user_id, role, content, created_at) VALUES (?, 'user', ?, ?)"
    ).bind(userId, question, createdAt),
    db.prepare(
      "INSERT INTO bb_ai_messages (user_id, role, content, created_at) VALUES (?, 'assistant', ?, ?)"
    ).bind(userId, answer, createdAt)
  ]);
}

async function userDataHandler(request, user, db) {
  if (!user) return responseJson({ error: "Требуется вход в аккаунт" }, 401);

  if (request.method === "GET") {
    const row = await db.prepare(
      "SELECT data_json, version, updated_at FROM bb_user_data WHERE user_id = ?"
    ).bind(user.id).first();

    if (!row) return responseJson({ exists: false, data: null, version: 0 });

    let data;
    try {
      data = JSON.parse(row.data_json);
    } catch {
      return responseJson({ error: "Сохранённые данные повреждены" }, 500);
    }

    return responseJson({
      exists: true,
      data,
      version: row.version,
      updated_at: row.updated_at
    });
  }

  if (request.method !== "PUT") {
    return responseJson({ error: "Метод не поддерживается" }, 405);
  }

  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 1_000_000) {
    return responseJson({ error: "Слишком большой объём данных" }, 413);
  }

  const body = await parseJson(request);
  if (!body || typeof body.data !== "object" || body.data === null || Array.isArray(body.data)) {
    return responseJson({ error: "Некорректные финансовые данные" }, 400);
  }

  const json = JSON.stringify(body.data);
  if (json.length > 900_000) {
    return responseJson({ error: "Данные превышают допустимый размер" }, 413);
  }

  const now = new Date().toISOString();

  // UPSERT выполняется только для user_id из проверенной сессии, а не из тела запроса.
  await db.prepare(`INSERT INTO bb_user_data (user_id, data_json, version, updated_at)
    VALUES (?, ?, 1, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      data_json = excluded.data_json,
      version = bb_user_data.version + 1,
      updated_at = excluded.updated_at`
  ).bind(user.id, json, now).run();

  const row = await db.prepare("SELECT version FROM bb_user_data WHERE user_id = ?")
    .bind(user.id).first();

  return responseJson({
    ok: true,
    version: row?.version || 1,
    updated_at: now
  });
}

async function aiHandler(request, env, user) {
  if (request.method !== "POST") {
    return responseJson({ error: "Method not allowed" }, 405, { Allow: "POST" });
  }

  if (!env.GEMINI_API_KEY) {
    return responseJson({ error: "Не настроен GEMINI_API_KEY" }, 500);
  }

  const body = await parseJson(request);
  if (!body) return responseJson({ error: "Некорректный JSON" }, 400);

  const question = String(body.question || body.message || "").trim();
  const appContext = body.context && typeof body.context === "object" ? body.context : {};
  const contextText = JSON.stringify(appContext);
  const behavior = String(body.behavior || "balanced");

  if (!question) return responseJson({ error: "Пустой вопрос" }, 400);

  if (question.length > MAX_QUESTION || contextText.length > MAX_CONTEXT) {
    return responseJson({ error: "Слишком большой запрос" }, 413);
  }

  const personal = user ? await loadPersonalContext(env.DB, user.id) : null;

  const behaviorHint = behavior === "strict"
    ? "Режим: строгий. Отвечай только фактами, без мотивации и предположений. "
    : behavior === "coach"
    ? "Режим: коуч. Поддерживай, мотивируй, предлагай конкретные шаги. "
    : behavior === "analyst"
    ? "Режим: аналитик. Давай подробный разбор с цифрами и сценариями. "
    : behavior === "choleric"
    ? "Режим: холерик. Будь агрессивным, прямым и жёстким. Матерись только если есть реальный повод (ошибки, бездействие, перерасход). Не матерись без причины. Говори по делу, коротко и резко. "
    : "Режим: сбалансированный. ";
  const input =
    behaviorHint + "ДАННЫЕ ПОЛЬЗОВАТЕЛЯ ИЗ ПРИЛОЖЕНИЯ:\n" + contextText +
    (personal ? "\n\nДОЛГОВРЕМЕННАЯ ПАМЯТЬ ЭТОГО АККАУНТА:\n" + personal.memory : "") +
    (personal ? "\n\nНЕДАВНЯЯ ИСТОРИЯ ЭТОГО АККАУНТА:\n" + JSON.stringify(personal.recent_history) : "") +
    "\n\nВОПРОС:\n" + question;

  // Сохраняем текущую последовательность моделей и endpoint из рабочего Worker.
  const models = ["gemini-3.7-flash", "gemini-3.5-flash-lite"];
  let lastError = "";

  for (const model of models) {
    let response;

    try {
      response = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/interactions",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": env.GEMINI_API_KEY
          },
          body: JSON.stringify({
            model,
            store: false,
            system_instruction: SYSTEM_PROMPT,
            input
          }),
          signal: AbortSignal.timeout(30000)
        }
      );
    } catch (error) {
      lastError = model + ": " + String(error?.message || error);
      continue;
    }

    const raw = await response.text();
    let result;

    try {
      result = JSON.parse(raw);
    } catch {
      result = null;
    }

    if (!response.ok) {
      lastError =
        "Gemini " + model + " HTTP " + response.status + ": " +
        (result?.error?.message || raw.slice(0, 800));

      if ([429, 500, 502, 503, 504].includes(response.status)) continue;

      return responseJson({ error: lastError }, 502);
    }

    const answer = (result?.steps || [])
      .filter(step => step.type === "model_output")
      .flatMap(step => step.content || [])
      .filter(item => item.type === "text")
      .map(item => item.text || "")
      .join("\n")
      .trim();

    if (answer) {
      if (user) {
        try {
          await saveAiMessages(env.DB, user.id, question, answer);
        } catch {
          // Не скрываем ответ ИИ, если сохранение истории временно не удалось.
        }
      }

      return responseJson({
        answer,
        model,
        history_saved: Boolean(user)
      });
    }

    lastError = "Модель " + model + " не вернула текстовый ответ";
  }

  return responseJson({
    error: "Не удалось получить ответ от Gemini. " + lastError
  }, 502);
}


async function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  const pairs = [];
  for (const [k, v] of params.entries()) pairs.push(k + '=' + v);
  pairs.sort();
  const dataCheckString = pairs.join('\n');
  const secretKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('WebAppData'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  // secret key is HMAC(bot_token, "WebAppData") per Telegram spec: secret = HMAC_SHA256(bot_token, "WebAppData")
  const secretBuf = await crypto.subtle.sign('HMAC', secretKey, new TextEncoder().encode(botToken));
  const hmacKey = await crypto.subtle.importKey('raw', secretBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(dataCheckString));
  const sigHex = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2,'0')).join('');
  if (!timingSafeEqual(sigHex, hash)) return null;
  const userStr = params.get('user');
  if (!userStr) return null;
  try { return JSON.parse(userStr); } catch { return null; }
}

async function notifyDebugHandler(user, db, env) {
  if (!user) return responseJson({ error: "Требуется вход в аккаунт" }, 401);
  const row = await db.prepare("SELECT telegram_user_id, data_json FROM bb_users u LEFT JOIN bb_user_data d ON d.user_id = u.id WHERE u.id = ?").bind(user.id).first();
  let state = null;
  try { if (row && row.data_json) state = JSON.parse(row.data_json); } catch {}
  const now = new Date();
  const hour = now.getUTCHours();
  const tzOffset = (state && state.tzOffset != null) ? Number(state.tzOffset) : 0;
  const localHour = (hour + Math.round(tzOffset / 60) + 24) % 24;
  const userTimes = (state && Array.isArray(state.tgNotifyTimes)) ? state.tgNotifyTimes : ["07:00","12:00","19:00"];
  const userHours = userTimes.map(t => parseInt(String(t).split(":")[0], 10)).filter(n => !isNaN(n));
  const timeMatch = userHours.includes(localHour);
  const quietStart = (state && state.aiQuietStart) || "22:00";
  const quietEnd = (state && state.aiQuietEnd) || "08:00";
  const hhmm = String(now.getUTCHours()).padStart(2,'0') + ":" + String(now.getUTCMinutes()).padStart(2,'0');
  let quiet = false;
  if (quietStart > quietEnd) { if (hhmm >= quietStart || hhmm < quietEnd) quiet = true; }
  else { if (hhmm >= quietStart && hhmm < quietEnd) quiet = true; }

  let sent = false;
  let sendError = null;
  if (row && row.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
    try {
      const res = await fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/sendMessage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: row.telegram_user_id, text: "Отладка BitBalance: UTC " + hour + ":00, локально " + localHour + ":00. Времена: " + userTimes.join(", ") })
      });
      const data = await res.json();
      sent = !!(res.ok && data.ok);
      if (!sent) sendError = data.description || ("HTTP " + res.status);
    } catch (e) { sendError = String(e?.message || e); }
  } else {
    sendError = !row?.telegram_user_id ? "Telegram не привязан" : "Бот не настроен";
  }

  return responseJson({
    utcHour: hour,
    tzOffset,
    localHour,
    userTimes,
    userHours,
    timeMatch,
    quiet,
    telegramLinked: Boolean(row && row.telegram_user_id),
    sent,
    sendError
  });
}

async function telegramTestHandler(user, db, env) {
  if (!user) return responseJson({ error: "Требуется вход в аккаунт" }, 401);
  const row = await db.prepare("SELECT telegram_user_id FROM bb_users WHERE id = ?").bind(user.id).first();
  if (!row || !row.telegram_user_id) return responseJson({ error: "Telegram не привязан" }, 400);
  if (!env.TELEGRAM_BOT_TOKEN) return responseJson({ error: "Бот не настроен" }, 500);
  try {
    const res = await fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/sendMessage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: row.telegram_user_id, text: "Тестовое сообщение от BitBalance. Уведомления работают!" })
    });
    const data = await res.json();
    if (!res.ok || !data.ok) return responseJson({ error: data.description || "Ошибка отправки" }, 502);
    return responseJson({ ok: true });
  } catch (e) {
    return responseJson({ error: String(e?.message || e) }, 502);
  }
}

async function telegramLinkHandler(request, user, db, env) {
  if (!user) return responseJson({ error: 'Требуется вход в аккаунт' }, 401);
  if (request.method !== 'POST') return responseJson({ error: 'Method not allowed' }, 405);
  const body = await parseJson(request);
  if (!body || !body.initData) return responseJson({ error: 'Передай initData' }, 400);
  const tgUser = await verifyTelegramInitData(body.initData, env.TELEGRAM_BOT_TOKEN || '');
  if (!tgUser || !tgUser.id) return responseJson({ error: 'Недействительные данные Telegram' }, 403);
  await db.prepare('UPDATE bb_users SET telegram_user_id = ? WHERE id = ?').bind(String(tgUser.id), user.id).run();
  return responseJson({ ok: true, telegram_user_id: tgUser.id });
}

async function pushTestHandler(user, db, env) {
  if (!user) return responseJson({ error: "Требуется вход в аккаунт" }, 401);
  const subs = await db.prepare("SELECT endpoint, keys_json FROM bb_push_subscriptions WHERE user_id = ?").bind(user.id).all();
  const results = [];
  for (const sub of (subs.results || [])) {
    const ok = await sendWebPush(sub.endpoint, env.VAPID_PUBLIC_KEY || "", env.VAPID_PRIVATE_KEY || "");
    results.push({ endpoint: sub.endpoint, ok });
  }
  return responseJson({ ok: true, results });
}

async function pushSubscribeHandler(request, user, db) {
  if (!user) return responseJson({ error: 'Требуется вход в аккаунт' }, 401);
  if (request.method === 'POST') {
    const body = await parseJson(request);
    if (!body || !body.endpoint || !body.keys) return responseJson({ error: 'Некорректная подписка' }, 400);
    const id = randomToken(12);
    await db.prepare('INSERT OR REPLACE INTO bb_push_subscriptions (id, user_id, endpoint, keys_json, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, user.id, body.endpoint, JSON.stringify(body.keys), new Date().toISOString()).run();
    return responseJson({ ok: true });
  }
  if (request.method === 'DELETE') {
    const body = await parseJson(request);
    if (body && body.endpoint) {
      await db.prepare('DELETE FROM bb_push_subscriptions WHERE user_id = ? AND endpoint = ?').bind(user.id, body.endpoint).run();
    }
    return responseJson({ ok: true });
  }
  return responseJson({ error: 'Method not allowed' }, 405);
}


async function telegramWebhookHandler(request, env) {
  if (request.method !== "POST") return responseJson({ ok: true });
  const body = await parseJson(request);
  if (!body) return responseJson({ ok: true });
  const message = body.message;
  if (message && message.chat && message.chat.id) {
    const chatId = message.chat.id;
    const text = message.text || "";
    // Отвечаем на /start и на любое сообщение, чтобы кнопка всегда была доступна
    if (text.startsWith("/start") || text === "" || true) {
    const appUrl = "https://balance-tg.geniy-2012.workers.dev";
    try {
      await fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/sendMessage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          text: "BitBalance — ваш личный финансовый пульт. Нажмите кнопку ниже, чтобы открыть приложение.",
          reply_markup: {
            inline_keyboard: [[{ text: "Открыть BitBalance", web_app: { url: appUrl } }]]
          }
        })
      });
    } catch (e) {}
    }
  }
  return responseJson({ ok: true });
}


function base64UrlToBytes(b64u) {
  const pad = "=".repeat((4 - (b64u.length % 4)) % 4);
  const b64 = (b64u + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

async function sendWebPush(endpoint, vapidPublicKey, vapidPrivateKey) {
  if (!vapidPublicKey || !vapidPrivateKey) return false;
  try {
    const pubBytes = base64UrlToBytes(vapidPublicKey);
    // pubBytes: 04 || x (32) || y (32)
    const x = pubBytes.slice(1, 33);
    const y = pubBytes.slice(33, 65);
    const privBytes = base64UrlToBytes(vapidPrivateKey);
    const jwk = {
      kty: "EC",
      crv: "P-256",
      d: vapidPrivateKey,
      x: btoa(String.fromCharCode(...x)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
      y: btoa(String.fromCharCode(...y)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
    };
    const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const origin = new URL(endpoint).origin;
    const header = { typ: "JWT", alg: "ES256" };
    const payload = { aud: origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "mailto:bitbalance@example.com" };
    const enc = (obj) => btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const unsigned = enc(header) + "." + enc(payload);
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, new TextEncoder().encode(unsigned));
    // convert DER to raw r||s (Web Crypto returns raw for ECDSA? Actually subtle.sign returns raw r||s for ECDSA in Web Crypto)
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const jwt = unsigned + "." + sigB64;

    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Authorization": "vapid t=" + jwt + ", k=" + vapidPublicKey,
        "TTL": "86400"
      }
    });
    return res.ok || res.status === 201;
  } catch (e) {
    console.error("webpush error:", String(e?.message || e));
    return false;
  }
}


function ruDateFull(s) {
  if (!s || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return s || "";
  const months = ["января","февраля","марта","апреля","мая","июня","июля","августа","сентября","октября","ноября","декабря"];
  const p = s.split("-").map(Number);
  return p[2] + " " + months[p[1]-1];
}

function buildSmartMessage(state, hour, now) {
  const today = now.toISOString().slice(0,10);
  const debts = (state && Array.isArray(state.debts)) ? state.debts : [];
  const history = (state && Array.isArray(state.history)) ? state.history : [];
  const debtTotal = debts.reduce((s, d) => d.archived ? s : s + (Number(d.amount) || 0), 0);

  const lines = [];
  if (hour < 11) lines.push("Доброе утро! ☀️");
  else if (hour < 17) lines.push("Дневная сводка 📊");
  else lines.push("Вечерняя сводка 🌙");

  // Статус по умолчанию
  let hasData = false;

  // Долги с приближающимся сроком
  const upcoming = debts.filter(d => {
    if (d.archived) return false;
    if (!d.due) return false;
    const diff = (new Date(d.due) - new Date(today)) / 86400000;
    return diff >= 0 && diff <= (state?.remindDays ?? 2);
  });
  if (upcoming.length) {
    hasData = true;
    lines.push("⚠️ Долги со сроком:");
    upcoming.forEach(d => {
      lines.push("• " + d.name + " — " + d.amount + " ₽ до " + ruDateFull(d.due));
    });
  }

  // Напоминание записать день
  const hasToday = history.some(h => h.type !== "debt" && h.date === today);
  if (!hasToday && hour >= 18) {
    hasData = true;
    lines.push("📝 Сегодня ещё не записан день — не забудьте внести данные.");
  }

  if (!hasData) lines.push("Всё под контролем ✅");
  lines.push("");
  lines.push("Откройте BitBalance, чтобы посмотреть детали.");
  return lines.join("\n");
}

export default {
  async fetch(request, env) {
    const diagnostic = { stage: "request_start" };
    const url = new URL(request.url);
    const pathname = url.pathname;

    try {
      if (!pathname.startsWith("/api/")) {
        return env.ASSETS.fetch(request);
      }

      if (!env.DB) {
        return responseJson({ error: "Не настроена D1 binding DB" }, 500);
      }

      // Инициализация схемы идемпотентна: только CREATE IF NOT EXISTS.
      diagnostic.stage = "ensure_schema";
      await ensureSchema(env.DB);

      if (pathname === "/api/health" && request.method === "GET") {
        return responseJson({
          ok: true,
          database: true,
          account_storage: true,
          gemini_configured: Boolean(env.GEMINI_API_KEY)
        });
      }

      if (pathname.startsWith("/api/auth/")) {
        return await authHandler(request, env, url, pathname, diagnostic);
      }

      if (pathname === "/api/data") {
        const user = await findAuthenticatedUser(request, env.DB);

        if (request.method !== "GET" && !originAllowed(request, url)) {
          return responseJson({ error: "Недопустимый источник запроса" }, 403);
        }

        return await userDataHandler(request, user, env.DB);
      }

      if (pathname === "/api/ai") {
        if (!originAllowed(request, url)) {
          return responseJson({ error: "Недопустимый источник запроса" }, 403);
        }

        const user = await findAuthenticatedUser(request, env.DB);
        return await aiHandler(request, env, user);
      }

      if (pathname === "/api/ai/history" || pathname === "/api/ai/memory") {
        const user = await findAuthenticatedUser(request, env.DB);

        if (!user) {
          return responseJson({ error: "Требуется вход в аккаунт" }, 401);
        }

        if (request.method !== "GET" && !originAllowed(request, url)) {
          return responseJson({ error: "Недопустимый источник запроса" }, 403);
        }

        if (pathname === "/api/ai/history") {
          return await historyHandler(request, user, env.DB);
        }

        return await memoryHandler(request, user, env.DB);
      }


      if (pathname === "/api/telegram/link") {
        const user = await findAuthenticatedUser(request, env.DB);
        return await telegramLinkHandler(request, user, env.DB, env);
      }

      if (pathname === "/api/push/subscribe") {
        const user = await findAuthenticatedUser(request, env.DB);
        return await pushSubscribeHandler(request, user, env.DB);
      }

      if (pathname === "/api/push/vapid-public" && request.method === "GET") {
        return responseJson({ publicKey: env.VAPID_PUBLIC_KEY || "" });
      }

      if (pathname === "/api/telegram/webhook") {
        return await telegramWebhookHandler(request, env);
      }

      if (pathname === "/api/push/test") {
        const user = await findAuthenticatedUser(request, env.DB);
        return await pushTestHandler(user, env.DB, env);
      }

      if (pathname === "/api/telegram/test") {
        const user = await findAuthenticatedUser(request, env.DB);
        return await telegramTestHandler(user, env.DB, env);
      }

      if (pathname === "/api/notify/debug") {
        const user = await findAuthenticatedUser(request, env.DB);
        return await notifyDebugHandler(user, env.DB, env);
      }

      return responseJson({ error: "API endpoint не найден" }, 404);
    } catch (error) {
      console.error("BitBalance Worker error:", {
        stage: diagnostic.stage,
        details: String(error?.stack || error?.message || error)
      });

      return responseJson({
        error: "Ошибка Worker",
        stage: diagnostic.stage,
        details: String(error?.message || error)
      }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    try {
      if (!env.DB) return;
      await ensureSchema(env.DB);
      const now = new Date(event.scheduledTime);
      const hour = now.getUTCHours();
      const users = await env.DB.prepare("SELECT id, telegram_user_id FROM bb_users").all();
      for (const u of (users.results || [])) {
        ctx.waitUntil((async () => {
          try {
            let state = null;
            const row = await env.DB.prepare("SELECT data_json FROM bb_user_data WHERE user_id = ?").bind(u.id).first();
            if (row && row.data_json) { try { state = JSON.parse(row.data_json); } catch {} }
            const remindDays = (state && state.remindDays != null) ? state.remindDays : 2;
            const quietStart = (state && state.aiQuietStart) || "22:00";
            const quietEnd = (state && state.aiQuietEnd) || "08:00";

            const tzOffset = (state && state.tzOffset != null) ? Number(state.tzOffset) : 0;
            const localNow = new Date(now.getTime() + tzOffset * 60000);
            const hhmm = String(localNow.getUTCHours()).padStart(2,'0') + ":" + String(localNow.getUTCMinutes()).padStart(2,'0');
            const localHour = localNow.getUTCHours();
            // Проверка тихого режима
            if (quietStart > quietEnd) {
              if (hhmm >= quietStart || hhmm < quietEnd) return;
            } else {
              if (hhmm >= quietStart && hhmm < quietEnd) return;
            }

            // Долги с приближающимся сроком
            const debts = (state && Array.isArray(state.debts)) ? state.debts : [];
            const today = now.toISOString().slice(0,10);
            // Автоплатежи: выполняем раз в день, если ещё не выполнены
            const autopays = (state && Array.isArray(state.autopay)) ? state.autopay : [];
            const todaysEntries = (state && Array.isArray(state.history)) ? state.history.filter(h => h.type === "day" && h.date === today) : [];
            const doneMk = new Set();
            todaysEntries.forEach(h => (Array.isArray(h.autoMk) ? h.autoMk : []).forEach(m => doneMk.add(String(m))));
            const toFire = autopays.filter(ap => {
              if (!ap || !ap.id) return false;
              if (doneMk.has(String(ap.id))) return false;
              if (ap.mode === "monthly") {
                const day = Math.min(31, Math.max(1, Number(ap.day) || 1));
                if (new Date(today + "T00:00:00").getDate() !== day) return false;
              }
              // Проверяем время выполнения (по местному времени пользователя)
              const apTime = ap.time || "07:00";
              const apHour = parseInt(String(apTime).split(":")[0], 10);
              if (!isNaN(apHour) && apHour !== localNow.getUTCHours()) return false;
              return true;
            });

            let firedText = "";
            if (toFire.length) {
              const expenses = {};
              const autoItems = toFire.map(ap => ({ catId: ap.catId, name: ap.name, amount: ap.amount }));
              const autoMk = toFire.map(ap => ap.id);
              toFire.forEach(ap => {
                const k = String(ap.catId);
                expenses[k] = (expenses[k] || 0) + Number(ap.amount || 0);
              });
              const newEntry = {
                id: "ap_" + today + "_" + Date.now(),
                type: "day",
                date: today,
                income: 0,
                incomeCat: null,
                expenses,
                debtPays: {},
                savings: {},
                savSpend: {},
                cushOut: 0,
                cushIn: 0,
                note: "Автоплатежи",
                autoItems,
                autoMk
              };
              if (!state.history) state.history = [];
              state.history.push(newEntry);
              // Сохраняем состояние
              try {
                await env.DB.prepare("INSERT INTO bb_user_data (user_id, data_json, version, updated_at) VALUES (?, ?, 1, ?) ON CONFLICT(user_id) DO UPDATE SET data_json = excluded.data_json, version = bb_user_data.version + 1, updated_at = excluded.updated_at")
                  .bind(u.id, JSON.stringify(state), new Date().toISOString()).run();
              } catch (e) {}
              firedText = "\nВыполнены автоплатежи: " + toFire.map(ap => ap.name + " " + ap.amount + " ₽").join(", ");
            }
            const upcoming = debts.filter(d => {
              if (d.archived) return false;
              if (!d.due) return false;
              const diff = (new Date(d.due) - new Date(today)) / 86400000;
              return diff >= 0 && diff <= remindDays;
            });

            // Проверяем, совпадает ли текущий час с одним из настроенных времён отправки
            const userTimes = (state && Array.isArray(state.tgNotifyTimes)) ? state.tgNotifyTimes : ["07:00","12:00","19:00"];
            const userHours = userTimes.map(t => parseInt(String(t).split(":")[0], 10)).filter(n => !isNaN(n));
            if (!userHours.includes(localNow.getUTCHours())) return;

            const msgMode = (state && state.tgMessageMode) ? state.tgMessageMode : "smart";
            let text = "";
            if (msgMode === "ai" && env.GEMINI_API_KEY) {
              try {
                const debtRemain = {};
                debts.forEach(d => { debtRemain[d.id] = d.amount; });
                history.forEach(h => {
                  if (h.debtPays) Object.keys(h.debtPays).forEach(k => { if (debtRemain[k] != null) debtRemain[k] = Math.max(0, debtRemain[k] - Number(h.debtPays[k])); });
                });
                const recentHistory = history.slice(-5).map(h => ({ date: h.date, income: h.income, expenses: h.expenses, debtPays: h.debtPays }));
                const ctx = JSON.stringify({ debts: debts.map(d=>({name:d.name, amount:d.amount, remain: Math.max(0, debtRemain[d.id] || 0), due:d.due})), historyCount: history.length, recentHistory });
                const r = await fetch("https://generativelanguage.googleapis.com/v1beta/interactions", {
                  method: "POST",
                  headers: { "Content-Type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY },
                  body: JSON.stringify({ model: "gemini-3.7-flash", store: false, system_instruction: "Ты финансовый помощник BitBalance. Напиши короткое уведомление (3-5 строк) на русском с эмодзи. Упомяни долги со сроком, рост расходов, почти закрытые долги, темпы погашения. Анализируй историю операций: сколько дней прошло, сколько потрачено на долги. Используй полные даты (10 января). Не используй короткие даты.", input: "Данные: " + ctx + "\nВремя: " + hour + ":00" }),
                  signal: AbortSignal.timeout(20000)
                });
                const data = await r.json();
                const ans = (data?.steps || []).filter(st => st.type === "model_output").flatMap(st => st.content || []).filter(c => c.type === "text").map(c => c.text).join("\n").trim();
                if (ans) text = ans;
              } catch (e) {}
            }
            if (!text) text = buildSmartMessage(state, hour, now);
            if (firedText) text += firedText;

            // Telegram
            if (u.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
              await fetch("https://api.telegram.org/bot" + env.TELEGRAM_BOT_TOKEN + "/sendMessage", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ chat_id: u.telegram_user_id, text })
              });
            }

            // Push с VAPID-авторизацией
            const subs = await env.DB.prepare("SELECT endpoint, keys_json FROM bb_push_subscriptions WHERE user_id = ?").bind(u.id).all();
            for (const sub of (subs.results || [])) {
              try {
                await sendWebPush(sub.endpoint, env.VAPID_PUBLIC_KEY || "", env.VAPID_PRIVATE_KEY || "");
              } catch {}
            }
          } catch (e) {
            console.error("BitBalance notify error:", String(e?.message || e));
          }
        })());
      }
      console.log("BitBalance cron tick:", now.toISOString());
    } catch (e) {
      console.error("BitBalance cron error:", String(e?.message || e));
    }
  }
};