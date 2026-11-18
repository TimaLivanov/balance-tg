export async function onRequestPost(context) {
  const { request, env } = context;
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
  if (request.method === "OPTIONS") {
    return new Response(null, { headers: cors });
  }
  
  const key = String(env.GEMINI_API_KEY || "").trim();
  if (!key) {
    return new Response(JSON.stringify({ error: "GEMINI_API_KEY не задан" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...cors },
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Неверный JSON" }), {
      status: 400,
      headers: { "Content-Type": "application/json", ...cors },
    });
  }

  const question = String(body.question || "").trim().slice(0, 2000);
  if (!question) {
    return new Response(JSON.stringify({ error: "Пустой вопрос" }), {
      status: 400,
      headers: { "Content-Type": "application/json", ...cors },
    });
  }

  const ctx = body.context || {};
  const system =
    "Ты финансовый помощник приложения Balance. Отвечай по-русски, кратко. Опирайся только на JSON пользователя. Не выдумывай цифры.";
  
  const model = String(env.GEMINI_MODEL || "gemini-2.5-flash").trim();
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(key)}`;

  const payload = {
    contents: [
      {
        role: "user",
        parts: [
          {
            text:
              system +
              "\n\nКонтекст:\n" +
              JSON.stringify(ctx).slice(0, 12000) +
              "\n\nВопрос:\n" +
              question,
          },
        ],
      },
    ],
    generationConfig: { temperature: 0.4, maxOutputTokens: 1024 },
  };

  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (!r.ok) {
      const msg = (data && data.error && data.error.message) || "Ошибка Gemini";
      return new Response(JSON.stringify({ error: msg }), {
        status: 502,
        headers: { "Content-Type": "application/json", ...cors },
      });
    }
    const text =
      (data.candidates &&
        data.candidates[0] &&
        data.candidates[0].content &&
        data.candidates[0].content.parts &&
        data.candidates[0].content.parts.map((p) => p.text).join("")) ||
      "Пустой ответ";
    return new Response(JSON.stringify({ answer: text }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...cors },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: "Ошибка запроса: " + err.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...cors },
    });
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
