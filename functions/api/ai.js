
export async function onRequestPost({ request, env }) {
  try {
    if (!env.GEMINI_API_KEY) {
      return Response.json(
        { error: "Не задан GEMINI_API_KEY" },
        { status: 500 }
      );
    }

    const { question, context } = await request.json();

    if (!question || typeof question !== "string") {
      return Response.json(
        { error: "Не задан вопрос" },
        { status: 400 }
      );
    }

    const prompt = `
Ты финансовый AI-советник приложения BitBalance.
Отвечай по-русски, понятно и конкретно.
Учитывай финансовые данные пользователя.
Не придумывай отсутствующие цифры.

Данные пользователя:
${JSON.stringify(context || {})}

Вопрос:
${question}
`;

    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": env.GEMINI_API_KEY
        },
        body: JSON.stringify({
          contents: [{
            parts: [{ text: prompt }]
          }]
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return Response.json(
        { error: data.error?.message || "Ошибка Gemini API" },
        { status: response.status }
      );
    }

    const answer =
      data.candidates?.[0]?.content?.parts
        ?.map(part => part.text || "")
        .join("") || "Gemini не вернул ответ";

    return Response.json({ answer });

  } catch (error) {
    return Response.json(
      { error: error.message || "Внутренняя ошибка сервера" },
      { status: 500 }
    );
  }
}
