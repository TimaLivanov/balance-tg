
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // AI API
    if (url.pathname === "/api/ai") {
      if (request.method !== "POST") {
        return Response.json(
          { error: "Method not allowed" },
          { status: 405 }
        );
      }

      if (!env.GEMINI_API_KEY) {
        return Response.json(
          { error: "Не настроен GEMINI_API_KEY" },
          { status: 500 }
        );
      }

      try {
        const body = await request.json();

        const question = String(body.question || "").trim();
        const context = JSON.stringify(body.context || {});

        if (!question) {
          return Response.json(
            { error: "Пустой вопрос" },
            { status: 400 }
          );
        }

        if (question.length > 5000 || context.length > 30000) {
          return Response.json(
            { error: "Слишком большой запрос" },
            { status: 413 }
          );
        }

        const response = await fetch(
          "https://generativelanguage.googleapis.com/v1beta/interactions",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-goog-api-key": env.GEMINI_API_KEY
            },
            body: JSON.stringify({
              model: "gemini-3.8-flash",
              store: false,
              system_instruction:
                "Ты финансовый AI-советник BitBalance. " +
                "Отвечай на русском языке. " +
                "Проверяй финансовые расчёты. " +
                "Не выдумывай доходы, расходы и долги. " +
                "Используй переданный контекст пользователя. " +
                "Если информации недостаточно, прямо скажи об этом.",
              input:
                "ДАННЫЕ ПОЛЬЗОВАТЕЛЯ:\n" +
                context +
                "\n\nВОПРОС:\n" +
                question
            })
          }
        );

        const result = await response.json();

        if (!response.ok) {
          return Response.json(
            {
              error:
                result.error?.message || "Ошибка Gemini API"
            },
            { status: 502 }
          );
        }

        const answer = (result.steps || [])
          .filter(step => step.type === "model_output")
          .flatMap(step => step.content || [])
          .filter(item => item.type === "text")
          .map(item => item.text)
          .join("\n")
          .trim();

        if (!answer) {
          return Response.json(
            { error: "Gemini не вернул текстовый ответ" },
            { status: 502 }
          );
        }

        return Response.json(
          { answer },
          {
            headers: {
              "Cache-Control": "no-store"
            }
          }
        );

      } catch (error) {
        return Response.json(
          { error: "Ошибка сервера: " + error.message },
          { status: 500 }
        );
      }
    }

    // Static application
    return env.ASSETS.fetch(request);
  }
};
