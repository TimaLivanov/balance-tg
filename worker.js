// ============================================================
// BitBalance — единый Cloudflare Worker
// D1 binding: DB
// Secret: GEMINI_API_KEY
// Assets binding: ASSETS
// ============================================================

const COOKIE_NAME = "bb_session";
const SESSION_DAYS = 30;

const MAX_DATA_SIZE = 1_500_000;
const MAX_QUESTION_SIZE = 8_000;
const MAX_CONTEXT_SIZE = 45_000;
const MAX_MEMORY_SIZE = 20_000;
const MAX_HISTORY = 100;

const SYSTEM_PROMPT = `
Ты — финансовый ИИ-помощник BitBalance.
Отвечай на русском языке.
Работай внимательно и точно, особенно с арифметикой, датами,
доходами, расходами, долгами и финансовыми прогнозами.

Правила:
- Не придумывай финансовые данные и не подменяй отсутствующие значения.
- Проверяй арифметику и показывай ход расчёта, если это важно.
- Учитывай даты обязательных платежей.
- Разделяй факты, предположения и рекомендации.
- Если данных недостаточно, прямо сообщай об этом.
- Используй историю и память только того аккаунта,
  к которому относится текущий запрос.
- Не раскрывай данные других пользователей.
`;

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers
    }
  });
}

function errorJson(message, status = 400, details = undefined) {
  const result = { error: message };
  if (details) result.details = details;
  return json(result, status);
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const item of header.split(";")) {
    const index = item.indexOf("=");

    if (index < 0) continue;

    if (item.slice(0, index).trim() === name) {
      try {
        return decodeURIComponent(item.slice(index + 1).trim());
      } catch {
        return "";
      }
    }
  }

  return "";
}

function makeCookie(token) {
  return (
    `${COOKIE_NAME}=${encodeURIComponent(token)}; ` +
    `Path=/; HttpOnly; Secure; SameSite=Lax; ` +
    `Max-Age=${SESSION_DAYS * 86400}`
  );
}

function removeCookie() {
  return (
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; ` +
    "SameSite=Lax; Max-Age=0"
  );
}

function originAllowed(request, url) {
  const origin = request.headers.get("Origin");
  return !origin || origin === url.origin;
}

function base64UrlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function randomToken(length = 32) {
  return base64UrlEncode(
    crypto.getRandomValues(new Uint8Array(length))
  );
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return base64UrlEncode(new Uint8Array(result));
}

async function hashPassword(password, existingSalt = null) {
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
    {
      name: "PBKDF2",
      salt,
      iterations: 310000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    salt: base64UrlEncode(salt),
    hash: base64UrlEncode(new Uint8Array(bits))
  };
}

function safeEqual(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    a.length !== b.length
  ) {
    return false;
  }

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
}

// ------------------------------------------------------------
// D1: создание таблиц. Старые таблицы не удаляются.
// ------------------------------------------------------------

async function ensureSchema(db) {
  const statements = [

    `CREATE TABLE IF NOT EXISTS bb_users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`,

    `CREATE TABLE IF NOT EXISTS bb_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES bb_users(id)
    )`,

    `CREATE INDEX IF NOT EXISTS bb_sessions_user_idx
      ON bb_sessions(user_id)`,

    `CREATE TABLE IF NOT EXISTS bb_user_data (
      user_id TEXT PRIMARY KEY,
      data_json TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES bb_users(id)
    )`,

    `CREATE TABLE IF NOT EXISTS bb_ai_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES bb_users(id)
    )`,

    `CREATE INDEX IF NOT EXISTS bb_ai_messages_user_idx
      ON bb_ai_messages(user_id, id)`,

    `CREATE TABLE IF NOT EXISTS bb_ai_memory (
      user_id TEXT PRIMARY KEY,
      content TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES bb_users(id)
    )`,

    `CREATE TABLE IF NOT EXISTS bb_login_attempts (
      attempt_key TEXT PRIMARY KEY,
      failures INTEGER NOT NULL DEFAULT 0,
      window_started_at TEXT NOT NULL,
      blocked_until TEXT
    )`
  ];

  for (const statement of statements) {
    await db.prepare(statement).run();
  }
}

// ------------------------------------------------------------
// Сессии и авторизация
// ------------------------------------------------------------

async function createSession(db, userId) {
  const token = randomToken(32);
  const now = new Date();

  const expiresAt = new Date(
    now.getTime() + SESSION_DAYS * 86400000
  ).toISOString();

  await db.prepare(`
    INSERT INTO bb_sessions
      (token_hash, user_id, expires_at, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(
    await sha256(token),
    userId,
    expiresAt,
    now.toISOString()
  ).run();

  return token;
}

async function getUser(request, db) {
  const token = getCookie(request, COOKIE_NAME);

  if (!token) return null;

  return await db.prepare(`
    SELECT u.id, u.email
    FROM bb_sessions s
    JOIN bb_users u ON u.id = s.user_id
    WHERE s.token_hash = ?
      AND s.expires_at > ?
  `).bind(
    await sha256(token),
    new Date().toISOString()
  ).first();
}

async function authHandler(request, env, url, path) {
  const db = env.DB;

  if (path === "/api/auth/me" && request.method === "GET") {
    const user = await getUser(request, db);

    return json({
      authenticated: Boolean(user),
      user: user
        ? { id: user.id, email: user.email }
        : null
    });
  }

  if (path === "/api/auth/logout" && request.method === "POST") {
    if (!originAllowed(request, url)) {
      return errorJson("Недопустимый источник запроса", 403);
    }

    const token = getCookie(request, COOKIE_NAME);

    if (token) {
      await db.prepare(
        "DELETE FROM bb_sessions WHERE token_hash = ?"
      ).bind(await sha256(token)).run();
    }

    return json(
      { ok: true },
      200,
      { "Set-Cookie": removeCookie() }
    );
  }

  if (
    path !== "/api/auth/register" &&
    path !== "/api/auth/login"
  ) {
    return errorJson("API endpoint не найден", 404);
  }

  if (request.method !== "POST") {
    return errorJson("Метод не поддерживается", 405);
  }

  if (!originAllowed(request, url)) {
    return errorJson("Недопустимый источник запроса", 403);
  }

  const body = await readJson(request);

  if (!body || typeof body !== "object") {
    return errorJson("Некорректный JSON в запросе", 400);
  }

  const email = String(body.email || "")
    .trim()
    .toLowerCase();

  const password = String(body.password || "");

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    email.length > 254
  ) {
    return errorJson("Укажи корректный email", 400);
  }

  // Совпадает с проверкой в index.html: минимум 8 символов.
  if (password.length < 8 || password.length > 200) {
    return errorJson(
      "Пароль должен содержать от 8 до 200 символов",
      400
    );
  }

  if (path === "/api/auth/register") {
    const existing = await db.prepare(
      "SELECT id FROM bb_users WHERE email = ?"
    ).bind(email).first();

    if (existing) {
      return errorJson(
        "Аккаунт с таким email уже существует",
        409
      );
    }

    const userId = randomToken(18);
    const now = new Date().toISOString();
    const credentials = await hashPassword(password);

    try {
      await db.prepare(`
        INSERT INTO bb_users
          (id, email, password_hash, password_salt,
           created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        userId,
        email,
        credentials.hash,
        credentials.salt,
        now,
        now
      ).run();
    } catch (error) {
      return errorJson(
        "Не удалось создать аккаунт",
        500,
        String(error?.message || error)
      );
    }

    const token = await createSession(db, userId);

    return json(
      {
        ok: true,
        user: { id: userId, email }
      },
      201,
      { "Set-Cookie": makeCookie(token) }
    );
  }

  const user = await db.prepare(`
    SELECT id, email, password_hash, password_salt
    FROM bb_users
    WHERE email = ?
  `).bind(email).first();

  if (!user) {
    return errorJson("Неверный email или пароль", 401);
  }

  const calculated = await hashPassword(
    password,
    user.password_salt
  );

  if (!safeEqual(calculated.hash, user.password_hash)) {
    return errorJson("Неверный email или пароль", 401);
  }

  const token = await createSession(db, user.id);

  return json(
    {
      ok: true,
      user: { id: user.id, email: user.email }
    },
    200,
    { "Set-Cookie": makeCookie(token) }
  );
}

// ------------------------------------------------------------
// Финансовые данные аккаунта
// GET  /api/data
// PUT  /api/data
// ------------------------------------------------------------

async function dataHandler(request, user, db) {
  if (request.method === "GET") {
    const row = await db.prepare(`
      SELECT data_json, updated_at
      FROM bb_user_data
      WHERE user_id = ?
    `).bind(user.id).first();

    if (!row) {
      return json({
        exists: false,
        data: null,
        updated_at: null
      });
    }

    let data;

    try {
      data = JSON.parse(row.data_json);
    } catch {
      return errorJson(
        "Не удалось прочитать сохранённые данные аккаунта",
        500
      );
    }

    return json({
      exists: true,
      data,
      updated_at: row.updated_at
    });
  }

  if (request.method === "PUT") {
    const body = await readJson(request);

    if (
      !body ||
      !body.data ||
      typeof body.data !== "object" ||
      Array.isArray(body.data)
    ) {
      return errorJson(
        "В запросе отсутствуют корректные данные поля data",
        400
      );
    }

    const serialized = JSON.stringify(body.data);

    if (serialized.length > MAX_DATA_SIZE) {
      return errorJson(
        "Размер финансовых данных превышает допустимый лимит",
        413
      );
    }

    const updatedAt = new Date().toISOString();

    await db.prepare(`
      INSERT INTO bb_user_data
        (user_id, data_json, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        data_json = excluded.data_json,
        updated_at = excluded.updated_at
    `).bind(
      user.id,
      serialized,
      updatedAt
    ).run();

    return json({
      ok: true,
      updated_at: updatedAt
    });
  }

  return errorJson("Метод не поддерживается", 405);
}

// ------------------------------------------------------------
// Персональная память ИИ
// GET    /api/ai/memory
// PUT    /api/ai/memory
// DELETE /api/ai/memory
// ------------------------------------------------------------

async function memoryHandler(request, user, db) {
  if (request.method === "GET") {
    const row = await db.prepare(`
      SELECT content, updated_at
      FROM bb_ai_memory
      WHERE user_id = ?
    `).bind(user.id).first();

    return json({
      memory: row?.content || "",
      updated_at: row?.updated_at || null
    });
  }

  if (request.method === "PUT") {
    const body = await readJson(request);

    if (!body || typeof body.content !== "string") {
      return errorJson(
        "Передай текст памяти в поле content",
        400
      );
    }

    const content = body.content.trim();

    if (content.length > MAX_MEMORY_SIZE) {
      return errorJson(
        "Превышен допустимый размер памяти",
        413
      );
    }

    const updatedAt = new Date().toISOString();

    await db.prepare(`
      INSERT INTO bb_ai_memory
        (user_id, content, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        content = excluded.content,
        updated_at = excluded.updated_at
    `).bind(
      user.id,
      content,
      updatedAt
    ).run();

    return json({
      ok: true,
      memory: content,
      updated_at: updatedAt
    });
  }

  if (request.method === "DELETE") {
    await db.prepare(
      "DELETE FROM bb_ai_memory WHERE user_id = ?"
    ).bind(user.id).run();

    return json({ ok: true });
  }

  return errorJson("Метод не поддерживается", 405);
}

// ------------------------------------------------------------
// История ИИ
// GET /api/ai/history?limit=50
// ------------------------------------------------------------

async function historyHandler(request, user, db) {
  if (request.method !== "GET") {
    return errorJson("Метод не поддерживается", 405);
  }

  const url = new URL(request.url);
  const requested = Number(url.searchParams.get("limit") || 50);

  const limit = Math.max(
    1,
    Math.min(
      MAX_HISTORY,
      Number.isFinite(requested) ? requested : 50
    )
  );

  const result = await db.prepare(`
    SELECT id, role, content, created_at
    FROM bb_ai_messages
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT ?
  `).bind(user.id, limit).all();

  return json({
    messages: (result.results || []).reverse()
  });
}

// ------------------------------------------------------------
// Контекст и сохранение истории ИИ
// ------------------------------------------------------------

async function getAiPersonalContext(db, userId) {
  const memory = await db.prepare(`
    SELECT content
    FROM bb_ai_memory
    WHERE user_id = ?
  `).bind(userId).first();

  const history = await db.prepare(`
    SELECT role, content
    FROM bb_ai_messages
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 12
  `).bind(userId).all();

  return {
    memory: memory?.content || "",
    history: (history.results || []).reverse()
  };
}

async function saveAiMessages(db, userId, question, answer) {
  const now = new Date().toISOString();

  await db.batch([
    db.prepare(`
      INSERT INTO bb_ai_messages
        (user_id, role, content, created_at)
      VALUES (?, 'user', ?, ?)
    `).bind(userId, question, now),

    db.prepare(`
      INSERT INTO bb_ai_messages
        (user_id, role, content, created_at)
      VALUES (?, 'assistant', ?, ?)
    `).bind(userId, answer, now)
  ]);
}

// ------------------------------------------------------------
// Gemini API
// ------------------------------------------------------------

async function callGemini(env, prompt) {
  if (!env.GEMINI_API_KEY) {
    throw new Error("Не настроен секрет GEMINI_API_KEY");
  }

  const models = [
    "gemini-2.5-flash"
  ];

  let lastError = "";

  for (const model of models) {
    const endpoint =
      `https://generativelanguage.googleapis.com/v1beta/models/` +
      `${model}:generateContent`;

    let response;

    try {
      response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": env.GEMINI_API_KEY
        },
        body: JSON.stringify({
          systemInstruction: {
            parts: [{ text: SYSTEM_PROMPT }]
          },
          contents: [
            {
              role: "user",
              parts: [{ text: prompt }]
            }
          ],
          generationConfig: {
            temperature: 0.25,
            maxOutputTokens: 8192
          }
        }),
        signal: AbortSignal.timeout(45000)
      });
    } catch (error) {
      lastError = String(error?.message || error);
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
        `Gemini HTTP ${response.status}: ` +
        String(result?.error?.message || raw).slice(0, 700);

      if (
        [429, 500, 502, 503, 504].includes(response.status)
      ) {
        continue;
      }

      throw new Error(lastError);
    }

    const answer = (
      result?.candidates?.[0]?.content?.parts || []
    )
      .map(part => part.text || "")
      .join("")
      .trim();

    if (answer) {
      return { answer, model };
    }

    lastError = "Gemini не вернул текстовый ответ";
  }

  throw new Error(lastError || "Не удалось получить ответ Gemini");
}

// ------------------------------------------------------------
// POST /api/ai
// ------------------------------------------------------------

async function aiHandler(request, env, user) {
  if (request.method !== "POST") {
    return errorJson("Метод не поддерживается", 405);
  }

  if (!user) {
    return errorJson("Для работы с ИИ необходимо войти в аккаунт", 401);
  }

  const body = await readJson(request);

  if (!body || typeof body !== "object") {
    return errorJson("Некорректный JSON", 400);
  }

  const question = String(
    body.question || body.message || ""
  ).trim();

  const appContext =
    body.context && typeof body.context === "object"
      ? body.context
      : {};

  if (!question) {
    return errorJson("Пустой вопрос", 400);
  }

  if (question.length > MAX_QUESTION_SIZE) {
    return errorJson("Слишком длинный вопрос", 413);
  }

  const contextText = JSON.stringify(appContext);

  if (contextText.length > MAX_CONTEXT_SIZE) {
    return errorJson("Слишком большой контекст запроса", 413);
  }

  const personal = await getAiPersonalContext(
    env.DB,
    user.id
  );

  const prompt = [
    "ДАННЫЕ ПОЛЬЗОВАТЕЛЯ ИЗ BITBALANCE:",
    contextText,

    "ПЕРСОНАЛЬНАЯ ПАМЯТЬ ЭТОГО АККАУНТА:",
    personal.memory || "Пока нет сохранённой памяти.",

    "НЕДАВНЯЯ ИСТОРИЯ ЭТОГО АККАУНТА:",
    JSON.stringify(personal.history),

    "ВОПРОС ПОЛЬЗОВАТЕЛЯ:",
    question
  ].join("\n\n");

  const generated = await callGemini(env, prompt);

  try {
    await saveAiMessages(
      env.DB,
      user.id,
      question,
      generated.answer
    );
  } catch (error) {
    // Ошибка сохранения истории не должна скрывать ответ ИИ.
    console.error(
      "AI history save error:",
      String(error?.message || error)
    );
  }

  return json({
    answer: generated.answer,
    model: generated.model,
    history_saved: true
  });
}

// ------------------------------------------------------------
// Главный обработчик Worker
// ------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Все не-API запросы обслуживаются через Cloudflare Assets.
      if (!path.startsWith("/api/")) {
        if (env.ASSETS && env.ASSETS.fetch) {
          return await env.ASSETS.fetch(request);
        }

        return new Response(
          "BitBalance: не настроен Assets binding ASSETS",
          { status: 503 }
        );
      }

      if (!env.DB) {
        return errorJson(
          "Не настроена D1 binding DB",
          500
        );
      }

      // Создание таблиц безопасно: только CREATE IF NOT EXISTS.
      await ensureSchema(env.DB);

      if (path === "/api/health" && request.method === "GET") {
        return json({
          ok: true,
          database: true,
          account_storage: true,
          gemini_configured: Boolean(env.GEMINI_API_KEY)
        });
      }

      if (!originAllowed(request, url)) {
        return errorJson(
          "Недопустимый источник запроса",
          403
        );
      }

      if (path.startsWith("/api/auth/")) {
        return await authHandler(
          request,
          env,
          url,
          path
        );
      }

      // Для всех остальных персональных API нужен аккаунт.
      const user = await getUser(request, env.DB);

      if (!user) {
        return errorJson(
          "Требуется вход в аккаунт",
          401
        );
      }

      if (path === "/api/data") {
        return await dataHandler(
          request,
          user,
          env.DB
        );
      }

      if (path === "/api/ai") {
        return await aiHandler(
          request,
          env,
          user
        );
      }

      if (path === "/api/ai/history") {
        return await historyHandler(
          request,
          user,
          env.DB
        );
      }

      if (path === "/api/ai/memory") {
        return await memoryHandler(
          request,
          user,
          env.DB
        );
      }

      return errorJson(
        "API endpoint не найден",
        404
      );

    } catch (error) {
      console.error(
        "BitBalance Worker error:",
        String(error?.stack || error?.message || error)
      );

      return errorJson(
        "Ошибка Worker",
        500,
        String(error?.message || error)
      );
    }
  }
};